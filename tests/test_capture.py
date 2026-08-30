"""Tests for the passive packet-capture source.

The trust boundary is the raw frame the driver hands to the read loop, so
everything on this side of it is exercised with no hardware, no Npcap and - for
the logic tests - no scapy at all. The sniffer itself is replaced by a fake that
reproduces the failure signalling that matters: a start that is never confirmed,
and a thread that dies mid-run with ``exception`` left unset.

The handful of tests that do want scapy build real frames with it and feed
their bytes to the raw parsers, skipping cleanly when scapy is absent, so that
a future release whose byte layout differs from what the parsers assume fails
here rather than in the field.
"""

import importlib.util
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from netmon import capture
from netmon.capture import (
    CAPTURE_STATE_CAPTURE_DIED,
    CAPTURE_STATE_DROPPING_PACKETS,
    CAPTURE_STATE_ERROR,
    CAPTURE_STATE_INTERFACE_MISSING,
    CAPTURE_STATE_NEEDS_ELEVATION,
    CAPTURE_STATE_NOT_RUNNING,
    CAPTURE_STATE_NPCAP_MISSING,
    CAPTURE_STATE_OK,
    CAPTURE_STATE_UNSUPPORTED_PLATFORM,
    NPCAP_MISSING_DETAIL,
    CaptureSource,
    CaptureStatus,
    NpcapMissingError,
    derive_state,
    filter_for,
    is_losing_packets,
    packets_lost,
    parse_ipv4_src_en10mb,
    parse_ipv4_src_null,
    parser_for,
    select_interface,
)
from netmon.rate_window import RateWindow

from .conftest import FakeClock

HOST_IP = "192.168.2.1"
DEVICE_IP = "192.168.2.2"
OTHER_DEVICE_IP = "192.168.2.3"
IFACE = "\\Device\\NPF_{11111111-1111-1111-1111-111111111111}"
OTHER_IFACE = "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}"

BUCKET_MS = 250
WINDOW_BUCKETS = 40

PERMISSION_MESSAGE = (
    "\\Device\\NPF_{1}: You don't have permission to perform this capture on "
    "that device"
)
FAILURE_MESSAGE = "libpcap said no"
REFUSED_RECORDING_MESSAGE = "ip must be a non-empty string"
SHORT_START_TIMEOUT_S = 0.1
TRUNCATED_FRAME = b"\x00" * 20

# Large enough that a handful of lost packets sits below the tolerance and a
# tenth of them sits well above it, so both sides of the ratio are reachable.
RECEIVED_SAMPLE = 10_000
BELOW_TOLERANCE_COUNTED = 9_995
AT_TOLERANCE_COUNTED = 9_990
ABOVE_TOLERANCE_COUNTED = 9_000
# Deliberately unequal to the packets actually lost, so the two numbers in the
# sentence cannot be confused for one another.
DRIVER_DROPPED = 400

REPO_ROOT = Path(__file__).resolve().parents[1]

requires_scapy = pytest.mark.skipif(
    importlib.util.find_spec("scapy") is None, reason="scapy is not installed"
)


class FakeThread:
    """Reports liveness from the sniffer that owns it."""

    def __init__(self, sniffer: "FakeSniffer") -> None:
        self._sniffer = sniffer

    def is_alive(self) -> bool:
        return self._sniffer.alive


class FakeSniffer:
    """Stands in for the pcap sniffer, misleading signals included."""

    def __init__(self, iface, bpf_filter, on_packet, on_started) -> None:
        self.iface = iface
        self.filter = bpf_filter
        self.on_packet = on_packet
        self.on_started = on_started
        # Nothing in the module is allowed to trust a running flag, so the
        # fake keeps one and lets it say the wrong thing.
        self.running = False
        self.exception: BaseException | None = None
        self.thread: FakeThread | None = None
        self.alive = True
        self.confirm_start = True
        self.start_error: BaseException | None = None
        self.start_raises: BaseException | None = None
        self.stop_error: BaseException | None = None
        self.stopped_with: float | None = None

    def start(self) -> None:
        if self.start_raises is not None:
            raise self.start_raises
        # A flag set before the socket opens would be left True on a thread
        # that is already gone after a setup failure.
        self.running = True
        self.thread = FakeThread(self)
        if self.start_error is not None:
            self.exception = self.start_error
            self.alive = False
            return
        if self.confirm_start:
            self.on_started()

    def stop(self, timeout: float) -> None:
        self.stopped_with = timeout
        if self.stop_error is not None:
            raise self.stop_error
        self.alive = False
        self.running = False

    def die_mid_run(self) -> None:
        """Reproduce the read loop dying without storing an exception.

        ``running`` goes False, the thread exits, and ``exception`` is left
        unset - the failure appears nowhere unless the thread itself is
        watched.
        """
        self.running = False
        self.alive = False


class ReportingSniffer(FakeSniffer):
    """A fake that can also report driver drop counters."""

    drop_report: object = None

    def drop_counts(self):
        if isinstance(self.drop_report, BaseException):
            raise self.drop_report
        return self.drop_report


class FakeSnifferFactory:
    """Builds one fake sniffer and keeps it so a test can drive it."""

    def __init__(self, sniffer_class=FakeSniffer, **preset) -> None:
        self._sniffer_class = sniffer_class
        self._preset = preset
        self.sniffer: FakeSniffer | None = None
        self.calls = 0

    def __call__(self, iface, bpf_filter, on_packet, on_started) -> FakeSniffer:
        self.calls += 1
        sniffer = self._sniffer_class(iface, bpf_filter, on_packet, on_started)
        for name, value in self._preset.items():
            setattr(sniffer, name, value)
        self.sniffer = sniffer
        return sniffer


class RaisingFactory:
    """A factory that fails the way a refused or broken socket open would."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def __call__(self, iface, bpf_filter, on_packet, on_started):
        raise self._error


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
AF_INET_HOST_ORDER = 2
AF_INET6_HOST_ORDER = 23  # Windows AF_INET6, for the DLT_NULL family field


def ipv4_header(src: str = DEVICE_IP, ihl_words: int = 5) -> bytes:
    """A minimal IPv4 header; only the fields the parsers read are real."""
    header = bytearray(ihl_words * 4)
    header[0] = (4 << 4) | ihl_words
    header[12:16] = socket.inet_aton(src)
    return bytes(header)


def ethernet_frame(
    src: str = DEVICE_IP, ethertype: int = ETHERTYPE_IPV4, ihl_words: int = 5
) -> bytes:
    """An Ethernet frame carrying an IPv4 packet, or another ethertype's."""
    body = ipv4_header(src, ihl_words) if ethertype == ETHERTYPE_IPV4 else b""
    return b"\x00" * 12 + struct.pack("!H", ethertype) + body


def null_frame(src: str = DEVICE_IP, family: int = AF_INET_HOST_ORDER) -> bytes:
    """A DLT_NULL loopback frame: a host-byte-order family, then the packet."""
    body = ipv4_header(src) if family == AF_INET_HOST_ORDER else b""
    return struct.pack("<I", family) + body


class RefusingWindow:
    """An aggregator that rejects whatever it is handed.

    ``RateWindow.record`` raises ``ValueError`` for an empty address or a
    non-positive packet count, so refusing is faithful to its contract.
    """

    def __init__(self, error: BaseException) -> None:
        self._error = error
        self.calls = 0

    def record(self, ip: str, packets: int = 1) -> None:
        self.calls += 1
        raise self._error


@pytest.fixture
def on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the lifecycle tests as though this were the target platform."""
    monkeypatch.setattr(capture.sys, "platform", capture.WINDOWS_PLATFORM)


@pytest.fixture
def window(clock: FakeClock) -> RateWindow:
    return RateWindow(bucket_ms=BUCKET_MS, buckets=WINDOW_BUCKETS, clock=clock)


def build_source(
    window: RateWindow, factory, iface: str | None = IFACE
) -> CaptureSource:
    return CaptureSource(window, HOST_IP, iface=iface, sniffer_factory=factory)


def recorded_addresses(window: RateWindow) -> list[str]:
    return [device["ip"] for device in window.snapshot()["devices"]]


def feed_packets(
    sniffer: FakeSniffer, count: int, source_ip: str | None = DEVICE_IP
) -> None:
    """Push ``count`` packets through the capture callback."""
    for _ in range(count):
        sniffer.on_packet(source_ip)


class FakeInterface:
    def __init__(self, network_name: str, *addresses: str) -> None:
        self.network_name = network_name
        self.ips = {4: list(addresses), 6: []}


class FakeIfaceTable:
    """scapy's ``conf.ifaces``, which holds its adapters in ``data``."""

    def __init__(self, interfaces: Iterable[FakeInterface]) -> None:
        self.data = {
            interface.network_name: interface for interface in interfaces
        }


class FakePcapFd:
    """The slice of scapy's pcap wrapper the read loop reaches for."""

    def __init__(self, datalink: int = capture.DLT_EN10MB) -> None:
        self._datalink = datalink
        self.pcap = object()  # the handle the ctypes calls would be aimed at

    def datalink(self) -> int:
        return self._datalink


class FakePcapListenSocket:
    """Stands in for scapy's libpcap listen socket."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.closed = False
        self.pcap_fd = FakePcapFd()

    def close(self) -> None:
        self.closed = True


class FakeNativeListenSocket:
    """scapy's own Windows socket - the substitution that must be refused.

    It cannot see incoming TCP at all, so a capture that silently ended up on
    it would look healthy while seeing almost nothing.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeConf:
    """The slice of scapy's ``conf`` the pcap layer reads.

    ``L2listen`` is a class rather than a factory because the module checks
    what it *is*, not just what it returns.
    """

    def __init__(
        self,
        listen_socket: object = FakePcapListenSocket,
        use_pcap: bool = True,
        interfaces: Iterable[FakeInterface] = (),
    ) -> None:
        self.L2listen = listen_socket
        self.use_pcap = use_pcap
        self.ifaces = FakeIfaceTable(interfaces)
        # scapy's idea of the primary adapter, which on a laptop is the Wi-Fi
        # card. Nothing here is allowed to fall back to it.
        self.iface = OTHER_IFACE


def install_pcap_layer(
    monkeypatch: pytest.MonkeyPatch, conf: FakeConf | None = None
) -> FakeConf:
    """Put scapy-free stand-ins behind the module's lazy scapy accessors.

    Faking the accessors rather than scapy itself is what keeps these tests off
    ``import scapy.all``, which costs seconds and which the pure-logic suite
    has to run without.
    """
    conf = FakeConf() if conf is None else conf
    monkeypatch.setattr(capture, "_scapy_conf", lambda: conf)
    monkeypatch.setattr(
        capture, "_pcap_listen_socket_class", lambda: FakePcapListenSocket
    )
    return conf


def ignore_packet(packet: Any) -> None:
    """Callback for the tests that only care how the sniffer was built."""


def ignore_start() -> None:
    """Start confirmation for those same tests."""


def build_pcap_sniffer() -> capture._PcapSniffer:
    """The real ``_PcapSniffer``, over whatever pcap layer is installed."""
    return capture._PcapSniffer(
        IFACE, filter_for(HOST_IP), ignore_packet, ignore_start
    )


# --------------------------------------------------------------------------
# Filter construction
# --------------------------------------------------------------------------


def test_the_filter_narrows_by_destination_only() -> None:
    assert filter_for(HOST_IP) == f"ip dst {HOST_IP}"


def test_the_filter_carries_no_subnet_term() -> None:
    """Regression guard against a well-meaning 'src net ...' tightening.

    The watched subnet is a parameter of each read, so a capture-time subnet
    filter would silently break the page's subnet control and discard history
    that a later read could never recover.
    """
    bpf_filter = filter_for(HOST_IP)

    assert "/" not in bpf_filter
    assert "net" not in bpf_filter
    assert "src" not in bpf_filter
    assert bpf_filter.count("dst") == 1


def test_a_host_address_that_is_not_an_address_is_rejected() -> None:
    with pytest.raises(ValueError):
        filter_for("192.168.2.999")


# --------------------------------------------------------------------------
# Interface selection
# --------------------------------------------------------------------------


def test_the_adapter_carrying_the_host_address_is_chosen() -> None:
    interfaces = [
        FakeInterface(OTHER_IFACE, "192.168.1.219"),
        FakeInterface(IFACE, HOST_IP),
        FakeInterface("\\Device\\NPF_Loopback", "127.0.0.1"),
    ]

    assert select_interface(HOST_IP, interfaces) == IFACE


def test_no_adapter_with_the_address_selects_nothing() -> None:
    """The interface_missing condition: tether unplugged or static IP gone."""
    interfaces = [
        FakeInterface(OTHER_IFACE, "192.168.1.219"),
        FakeInterface(IFACE, "169.254.241.51"),
    ]

    assert select_interface(HOST_IP, interfaces) is None


def test_an_adapter_with_no_addresses_is_skipped() -> None:
    interfaces = [FakeInterface(OTHER_IFACE), FakeInterface(IFACE, HOST_IP)]

    assert select_interface(HOST_IP, interfaces) == IFACE


def test_two_adapters_sharing_an_address_resolve_deterministically() -> None:
    interfaces = [FakeInterface(IFACE, HOST_IP), FakeInterface(OTHER_IFACE, HOST_IP)]

    chosen = select_interface(HOST_IP, interfaces)

    assert chosen == OTHER_IFACE
    assert select_interface(HOST_IP, list(reversed(interfaces))) == chosen


def test_the_adapter_table_is_read_from_scapy_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The production path, which every other test here bypasses."""
    conf = FakeConf(
        interfaces=[
            FakeInterface(OTHER_IFACE, "192.168.1.219"),
            FakeInterface(IFACE, HOST_IP),
        ]
    )
    monkeypatch.setattr(capture, "_scapy_conf", lambda: conf)

    chosen = select_interface(HOST_IP)

    assert chosen == IFACE
    assert chosen != conf.iface


def test_scapys_own_primary_adapter_is_never_a_fallback(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """``conf.iface`` is the Wi-Fi card here, so falling back to it would draw
    the house LAN as plausible vehicle rows."""
    conf = FakeConf(interfaces=[FakeInterface(OTHER_IFACE, "192.168.1.219")])
    monkeypatch.setattr(capture, "_scapy_conf", lambda: conf)

    assert select_interface(HOST_IP) is None


# --------------------------------------------------------------------------
# Raw-frame parsing
# --------------------------------------------------------------------------


def test_the_source_address_of_an_ethernet_ipv4_frame_is_parsed() -> None:
    assert parse_ipv4_src_en10mb(ethernet_frame()) == DEVICE_IP


def test_the_source_address_of_a_loopback_frame_is_parsed() -> None:
    assert parse_ipv4_src_null(null_frame()) == DEVICE_IP


def test_an_ipv4_header_with_options_is_parsed() -> None:
    """A longer header is legal; the source address sits at a fixed offset."""
    frame = ethernet_frame(ihl_words=6)

    assert parse_ipv4_src_en10mb(frame) == DEVICE_IP


@pytest.mark.parametrize(
    "frame",
    [
        ethernet_frame(ethertype=ETHERTYPE_ARP),
        ethernet_frame(ethertype=ETHERTYPE_IPV6),
        ethernet_frame()[:20],  # truncated inside the IPv4 header
        ethernet_frame()[:33],  # one byte short of the full IPv4 header
        b"\x00" * 13,  # shorter than an Ethernet header
        b"",
        # Version nibble says 6 despite the IPv4 ethertype.
        ethernet_frame()[:14] + bytes([0x65]) + ethernet_frame()[15:],
        # IHL below the minimum contradicts the version.
        ethernet_frame()[:14] + bytes([0x43]) + ethernet_frame()[15:],
    ],
)
def test_an_ethernet_frame_without_a_usable_ipv4_packet_parses_to_nothing(
    frame: bytes,
) -> None:
    assert parse_ipv4_src_en10mb(frame) is None


@pytest.mark.parametrize(
    "frame",
    [
        null_frame(family=AF_INET6_HOST_ORDER),
        null_frame()[:10],  # truncated inside the IPv4 header
        b"\x02\x00\x00",  # shorter than the family header
        b"",
    ],
)
def test_a_loopback_frame_without_a_usable_ipv4_packet_parses_to_nothing(
    frame: bytes,
) -> None:
    assert parse_ipv4_src_null(frame) is None


def test_the_parser_matches_the_adapters_datalink_type() -> None:
    assert parser_for(capture.DLT_EN10MB) is parse_ipv4_src_en10mb
    assert parser_for(capture.DLT_NULL) is parse_ipv4_src_null


def test_an_unknown_datalink_is_an_error_not_a_misparse() -> None:
    """Every frame would be misread or discarded; the capture states report it."""
    with pytest.raises(ValueError, match="datalink"):
        parser_for(99)


# --------------------------------------------------------------------------
# State derivation
# --------------------------------------------------------------------------

BOOM = RuntimeError(FAILURE_MESSAGE)
DENIED = OSError(PERMISSION_MESSAGE)


@pytest.mark.parametrize(
    "started,exception,thread_alive,expected",
    [
        # The three rows of the truth table, in order.
        (True, None, True, CAPTURE_STATE_OK),
        (True, BOOM, False, CAPTURE_STATE_ERROR),
        (True, None, False, CAPTURE_STATE_CAPTURE_DIED),
        # A start that was never confirmed is a failure even with nothing
        # raised, however alive the thread looks.
        (False, None, False, CAPTURE_STATE_ERROR),
        (False, None, True, CAPTURE_STATE_ERROR),
        # A stored exception always wins.
        (False, BOOM, False, CAPTURE_STATE_ERROR),
        (False, BOOM, True, CAPTURE_STATE_ERROR),
        (True, BOOM, True, CAPTURE_STATE_ERROR),
        # A refused permission is the one failure worth naming separately.
        (False, DENIED, False, CAPTURE_STATE_NEEDS_ELEVATION),
        (True, DENIED, True, CAPTURE_STATE_NEEDS_ELEVATION),
        (False, PermissionError(), False, CAPTURE_STATE_NEEDS_ELEVATION),
    ],
)
def test_state_is_derived_from_the_combination(
    started: bool, exception: BaseException | None, thread_alive: bool, expected: str
) -> None:
    assert derive_state(started, exception, thread_alive) == expected


# --------------------------------------------------------------------------
# Platform dispatch
# --------------------------------------------------------------------------


def test_capture_off_windows_reports_an_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    monkeypatch.setattr(capture.sys, "platform", "linux")
    factory = FakeSnifferFactory()
    source = build_source(window, factory)

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_UNSUPPORTED_PLATFORM
    assert "linux" in status.detail
    assert factory.calls == 0
    assert source.running is False


def test_the_pure_logic_still_works_off_windows(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing at module scope may depend on the platform or on scapy."""
    monkeypatch.setattr(capture.sys, "platform", "darwin")

    assert filter_for(HOST_IP) == f"ip dst {HOST_IP}"
    assert derive_state(True, None, True) == CAPTURE_STATE_OK
    assert parse_ipv4_src_en10mb(ethernet_frame()) == DEVICE_IP


def test_importing_the_module_does_not_import_scapy() -> None:
    """``--mock`` must keep working on a machine with no scapy installed."""
    probe = "import netmon.capture, sys; print(any(m == 'scapy' or m.startswith('scapy.') for m in sys.modules))"
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=True,
    )

    assert result.stdout.strip() == "False"


# --------------------------------------------------------------------------
# Lifecycle and live status
# --------------------------------------------------------------------------


def test_a_healthy_capture_reports_ok_and_names_the_address(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_OK
    assert HOST_IP in status.detail
    assert source.running is True


def test_the_sniffer_is_built_with_the_resolved_interface_and_filter(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)

    source.start()

    assert factory.sniffer.iface == IFACE
    assert factory.sniffer.filter == filter_for(HOST_IP)


def test_an_explicit_interface_skips_adapter_discovery(
    on_windows: None, monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("adapter discovery should not have been consulted")

    monkeypatch.setattr(capture, "select_interface", fail)
    source = build_source(window, FakeSnifferFactory())

    source.start()

    assert source.status().state == CAPTURE_STATE_OK


def test_no_adapter_for_the_host_address_reports_interface_missing(
    on_windows: None, monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    monkeypatch.setattr(capture, "select_interface", lambda host_ip: None)
    factory = FakeSnifferFactory()
    source = build_source(window, factory, iface=None)

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_INTERFACE_MISSING
    assert HOST_IP in status.detail
    assert factory.calls == 0


def test_a_capture_that_dies_mid_run_stops_reporting_ok(
    on_windows: None, window: RateWindow
) -> None:
    """The failure the whole module exists to surface.

    A raising callback leaves ``exception`` unset, so this is invisible unless
    the thread itself is watched.
    """
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()
    assert source.status().state == CAPTURE_STATE_OK

    factory.sniffer.die_mid_run()
    status = source.status()

    assert status.state == CAPTURE_STATE_CAPTURE_DIED
    assert factory.sniffer.exception is None
    assert source.running is False


def test_a_setup_failure_is_not_hidden_by_a_running_flag(
    on_windows: None, window: RateWindow
) -> None:
    """scapy leaves ``running`` True on a thread that never opened a socket."""
    factory = FakeSnifferFactory(start_error=RuntimeError(FAILURE_MESSAGE))
    source = build_source(window, factory)

    source.start()
    status = source.status()

    assert factory.sniffer.running is True
    assert status.state == CAPTURE_STATE_ERROR
    assert FAILURE_MESSAGE in status.detail


def test_a_start_that_is_never_confirmed_is_reported_rather_than_assumed(
    on_windows: None, monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    monkeypatch.setattr(capture, "START_TIMEOUT_S", SHORT_START_TIMEOUT_S)
    factory = FakeSnifferFactory(confirm_start=False)
    source = build_source(window, factory)

    source.start()
    status = source.status()

    assert source.running is True
    assert status.state == CAPTURE_STATE_ERROR
    assert "did not confirm" in status.detail


def test_a_socket_that_cannot_be_opened_reports_the_reason(
    on_windows: None, window: RateWindow
) -> None:
    source = build_source(window, RaisingFactory(RuntimeError(FAILURE_MESSAGE)))

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_ERROR
    assert FAILURE_MESSAGE in status.detail


def test_missing_npcap_points_at_where_to_get_it(
    on_windows: None, window: RateWindow
) -> None:
    source = build_source(
        window, RaisingFactory(NpcapMissingError(NPCAP_MISSING_DETAIL))
    )

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_NPCAP_MISSING
    assert "npcap.com" in status.detail


def test_a_refused_permission_asks_for_elevation_when_unelevated(
    on_windows: None, monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    monkeypatch.setattr(capture, "is_elevated", lambda: False)
    source = build_source(window, RaisingFactory(OSError(PERMISSION_MESSAGE)))

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_NEEDS_ELEVATION
    assert "administrator" in status.detail.lower()


def test_a_refused_permission_says_something_else_when_already_elevated(
    on_windows: None, monkeypatch: pytest.MonkeyPatch, window: RateWindow
) -> None:
    """Elevation explains a failure; it never predicts one."""
    monkeypatch.setattr(capture, "is_elevated", lambda: True)
    source = build_source(window, RaisingFactory(OSError(PERMISSION_MESSAGE)))

    source.start()
    status = source.status()

    assert status.state == CAPTURE_STATE_NEEDS_ELEVATION
    assert "Npcap" in status.detail


def test_starting_twice_does_not_open_a_second_capture(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)

    source.start()
    source.start()

    assert factory.calls == 1


def test_a_failed_start_is_not_retried_silently(
    on_windows: None, window: RateWindow
) -> None:
    source = build_source(window, RaisingFactory(RuntimeError(FAILURE_MESSAGE)))

    source.start()
    source.start()

    assert source.status().state == CAPTURE_STATE_ERROR


def test_status_before_starting_says_so(window: RateWindow) -> None:
    source = build_source(window, FakeSnifferFactory())

    assert source.status() == CaptureStatus(
        CAPTURE_STATE_NOT_RUNNING, capture.NOT_RUNNING_DETAIL
    )
    assert source.running is False


# --------------------------------------------------------------------------
# Stopping
# --------------------------------------------------------------------------


def test_stopping_a_capture_that_never_started_is_harmless(
    window: RateWindow
) -> None:
    source = build_source(window, FakeSnifferFactory())

    source.stop()

    assert source.running is False


def test_stopping_releases_the_sniffer_and_passes_the_timeout(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    source.stop(timeout=0.25)

    assert factory.sniffer.stopped_with == 0.25
    assert source.running is False
    assert source.status().state == CAPTURE_STATE_NOT_RUNNING


def test_a_sniffer_that_raises_on_starting_can_still_be_stopped(
    on_windows: None, window: RateWindow
) -> None:
    """Its libpcap handle exists from the moment it was built.

    ``AsyncSniffer.start()`` is not known to raise, but if it ever did, a
    sniffer the source had not kept hold of would leave that handle
    unreachable - ``stop()`` is the only thing that can release it.
    """
    factory = FakeSnifferFactory(start_raises=RuntimeError(FAILURE_MESSAGE))
    source = build_source(window, factory)

    source.start()
    status = source.status()
    source.stop()

    assert status.state == CAPTURE_STATE_ERROR
    assert FAILURE_MESSAGE in status.detail
    assert factory.sniffer.stopped_with == capture.STOP_TIMEOUT_S


def test_stopping_a_sniffer_that_is_already_dead_never_raises(
    on_windows: None, window: RateWindow
) -> None:
    """scapy raises "Not running !" here, and the server stops from a finally."""
    factory = FakeSnifferFactory(stop_error=RuntimeError("Not running !"))
    source = build_source(window, factory)
    source.start()
    factory.sniffer.die_mid_run()

    source.stop()

    assert source.status().state == CAPTURE_STATE_NOT_RUNNING


# --------------------------------------------------------------------------
# Recording, and the callback's refusal to raise
# --------------------------------------------------------------------------


def test_captured_packets_reach_the_aggregator(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(DEVICE_IP)
    factory.sniffer.on_packet(OTHER_DEVICE_IP)
    factory.sniffer.on_packet(DEVICE_IP)

    assert recorded_addresses(window) == [DEVICE_IP, OTHER_DEVICE_IP]
    assert window.snapshot()["devices"][0]["total_packets"] == 2


def test_the_callback_never_raises_on_a_frame_without_an_address(
    on_windows: None, window: RateWindow
) -> None:
    """One escaped exception would end the capture permanently."""
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(None)

    assert recorded_addresses(window) == []
    assert source.status().state == CAPTURE_STATE_OK


def test_an_unreadable_frame_does_not_stop_later_ones_being_counted(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(None)
    factory.sniffer.on_packet(DEVICE_IP)

    assert recorded_addresses(window) == [DEVICE_IP]


@pytest.mark.parametrize(
    "error", [ValueError(REFUSED_RECORDING_MESSAGE), RuntimeError(FAILURE_MESSAGE)]
)
def test_an_aggregator_that_refuses_a_recording_does_not_end_the_capture(
    on_windows: None, error: BaseException
) -> None:
    """The other half of the callback's guard, and the harder half to reach.

    Every frame that cannot be read fails earlier, at extraction, so the only
    way ``record`` itself raises is a value it rejects - and one exception
    escaping here would end the capture permanently, leaving every device
    scrolling along the baseline as though it had simply gone quiet.
    """
    window = RefusingWindow(error)
    factory = FakeSnifferFactory()
    source = CaptureSource(
        window, HOST_IP, iface=IFACE, sniffer_factory=factory
    )
    source.start()

    factory.sniffer.on_packet(DEVICE_IP)
    status = source.status()

    assert window.calls == 1
    assert status.state == CAPTURE_STATE_OK
    assert source.running is True


def test_a_refused_recording_is_described_as_what_it_was(
    on_windows: None
) -> None:
    """An address was read; recording it is what failed.

    The sentence reaches an ROV operator verbatim, so it has to be true of
    both the frame with no readable address and the address that was rejected.
    """
    factory = FakeSnifferFactory()
    source = CaptureSource(
        RefusingWindow(ValueError(REFUSED_RECORDING_MESSAGE)),
        HOST_IP,
        iface=IFACE,
        sniffer_factory=factory,
    )
    source.start()

    factory.sniffer.on_packet(DEVICE_IP)

    assert "1 packets could not be attributed" in source.status().detail


def test_unattributable_packets_are_counted_and_surfaced(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(None)
    factory.sniffer.on_packet(None)

    assert "2 packets" in source.status().detail


# --------------------------------------------------------------------------
# Packet loss
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "received,counted,expected",
    [
        # Nothing received yet is not a loss, and must not divide by zero.
        (0, 0, False),
        (0, RECEIVED_SAMPLE, False),
        (RECEIVED_SAMPLE, RECEIVED_SAMPLE, False),
        (RECEIVED_SAMPLE, BELOW_TOLERANCE_COUNTED, False),
        (RECEIVED_SAMPLE, AT_TOLERANCE_COUNTED, False),
        (RECEIVED_SAMPLE, AT_TOLERANCE_COUNTED - 1, True),
        (RECEIVED_SAMPLE, ABOVE_TOLERANCE_COUNTED, True),
        (RECEIVED_SAMPLE, 0, True),
        # The two counters are read a moment apart, so ours can lead.
        (RECEIVED_SAMPLE, RECEIVED_SAMPLE + 3, False),
    ],
)
def test_loss_is_judged_as_a_ratio_of_what_arrived(
    received: int, counted: int, expected: bool
) -> None:
    """A blip must not nag forever; a sustained loss must show."""
    assert is_losing_packets(received, counted) is expected


@pytest.mark.parametrize(
    "received,counted,expected",
    [
        (RECEIVED_SAMPLE, ABOVE_TOLERANCE_COUNTED, 1_000),
        (RECEIVED_SAMPLE, RECEIVED_SAMPLE, 0),
        (RECEIVED_SAMPLE, RECEIVED_SAMPLE + 3, 0),
    ],
)
def test_the_packets_lost_are_the_gap_between_the_two_counters(
    received: int, counted: int, expected: int
) -> None:
    assert packets_lost(received, counted) == expected


def test_sustained_loss_is_reported_as_its_own_state(
    on_windows: None, window: RateWindow
) -> None:
    """Silent kernel drops are how a failing capture would otherwise hide.

    Reported inside ``ok`` the loss reaches the JSON and is shown to nobody,
    because the page raises its banner only for a state it does not recognise.
    """
    factory = FakeSnifferFactory(
        ReportingSniffer, drop_report=(RECEIVED_SAMPLE, DRIVER_DROPPED)
    )
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, ABOVE_TOLERANCE_COUNTED)

    status = source.status()

    assert status.state == CAPTURE_STATE_DROPPING_PACKETS
    assert "1,000 of the 10,000" in status.detail
    assert "400" in status.detail
    assert "undercounted" in status.detail


def test_loss_hidden_by_the_kernel_buffer_is_reported_though_ps_drop_is_zero(
    on_windows: None, window: RateWindow
) -> None:
    """The regression guard for the measured finding.

    A saturated capture was observed reporting ``ps_drop`` of zero while only
    half the received packets had reached the callback - the rest were queued
    in Npcap's kernel buffer, which stays quiet until it fills. Judged on
    ``ps_drop`` alone this capture reports a clean ``ok`` while undercounting
    every device by half.
    """
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=(RECEIVED_SAMPLE, 0))
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, RECEIVED_SAMPLE // 2)

    status = source.status()

    assert status.state == CAPTURE_STATE_DROPPING_PACKETS
    assert "5,000 of the 10,000" in status.detail


def test_a_capture_losing_less_than_the_tolerance_still_reports_ok(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=(RECEIVED_SAMPLE, 5))
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, BELOW_TOLERANCE_COUNTED)

    status = source.status()

    assert status.state == CAPTURE_STATE_OK
    assert "undercounted" not in status.detail


def test_a_capture_losing_nothing_reports_ok(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=(RECEIVED_SAMPLE, 0))
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, RECEIVED_SAMPLE)

    assert source.status().state == CAPTURE_STATE_OK


def test_a_capture_that_has_received_nothing_reports_ok(
    on_windows: None, window: RateWindow
) -> None:
    """An idle tether is not a lossy one, and zero received divides by zero."""
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=(0, 0))
    source = build_source(window, factory)

    source.start()

    assert source.status().state == CAPTURE_STATE_OK


def test_frames_that_could_not_be_read_still_count_as_having_arrived(
    on_windows: None, window: RateWindow
) -> None:
    """They reached the callback, so they were not lost by the driver.

    Counting only the packets that were successfully attributed would report a
    capture seeing nothing but ARP as losing every packet it sees.
    """
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=(RECEIVED_SAMPLE, 0))
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, RECEIVED_SAMPLE, None)

    status = source.status()

    assert status.state == CAPTURE_STATE_OK
    assert f"{RECEIVED_SAMPLE} packets" in status.detail


@pytest.mark.parametrize(
    "preset,expected",
    [
        ({}, CAPTURE_STATE_CAPTURE_DIED),
        (
            {"start_error": RuntimeError(FAILURE_MESSAGE)},
            CAPTURE_STATE_ERROR,
        ),
    ],
)
def test_a_capture_that_is_not_running_outranks_the_loss_it_was_showing(
    on_windows: None, window: RateWindow, preset: dict[str, Any], expected: str
) -> None:
    """Rates that are not live at all are worse news than undercounted ones."""
    factory = FakeSnifferFactory(
        ReportingSniffer, drop_report=(RECEIVED_SAMPLE, DRIVER_DROPPED), **preset
    )
    source = build_source(window, factory)
    source.start()
    factory.sniffer.alive = False

    assert source.status().state == expected


def test_a_stopped_capture_reports_that_rather_than_the_loss(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory(
        ReportingSniffer, drop_report=(RECEIVED_SAMPLE, DRIVER_DROPPED)
    )
    source = build_source(window, factory)
    source.start()
    feed_packets(factory.sniffer, ABOVE_TOLERANCE_COUNTED)
    assert source.status().state == CAPTURE_STATE_DROPPING_PACKETS

    source.stop()

    assert source.status().state == CAPTURE_STATE_NOT_RUNNING


@pytest.mark.parametrize(
    "drop_report", [None, AttributeError("pcap_fd is gone"), ("nonsense",)]
)
def test_unavailable_drop_counters_degrade_to_silence(
    on_windows: None, window: RateWindow, drop_report
) -> None:
    """The private scapy chain may break on upgrade; capture must not."""
    factory = FakeSnifferFactory(ReportingSniffer, drop_report=drop_report)
    source = build_source(window, factory)

    source.start()

    assert source.status().state == CAPTURE_STATE_OK


def test_a_sniffer_with_no_drop_counters_still_reports_ok(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)

    source.start()

    assert source.status().state == CAPTURE_STATE_OK


# --------------------------------------------------------------------------
# The pcap layer, faked rather than imported
# --------------------------------------------------------------------------


def test_a_scapy_that_will_capture_through_libpcap_is_accepted(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    conf = install_pcap_layer(monkeypatch)

    assert capture._require_pcap() is conf


def test_a_scapy_without_the_libpcap_binding_reports_npcap_missing(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failing to load pcap at all is exactly the npcap_missing condition."""

    def missing() -> type:
        raise ImportError("No module named 'scapy.arch.libpcap'")

    install_pcap_layer(monkeypatch)
    monkeypatch.setattr(capture, "_pcap_listen_socket_class", missing)

    with pytest.raises(NpcapMissingError, match="npcap.com"):
        capture._require_pcap()


def test_a_scapy_that_would_not_use_pcap_reports_npcap_missing(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    install_pcap_layer(monkeypatch, FakeConf(use_pcap=False))

    with pytest.raises(NpcapMissingError):
        capture._require_pcap()


@pytest.mark.parametrize(
    "listen_socket", [FakeNativeListenSocket, FakeNativeListenSocket()]
)
def test_a_substituted_listen_socket_reports_npcap_missing(
    monkeypatch: pytest.MonkeyPatch, listen_socket: object
) -> None:
    """``conf.use_pcap`` alone does not prove the socket class came from pcap.

    scapy's own Windows socket cannot see incoming TCP, so a silent
    substitution would present itself as a working capture that sees almost
    nothing.
    """
    install_pcap_layer(monkeypatch, FakeConf(listen_socket=listen_socket))

    with pytest.raises(NpcapMissingError):
        capture._require_pcap()


def test_the_capture_socket_is_opened_without_promiscuous_mode(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """``conf.sniff_promisc`` defaults to True and the socket falls back to it.

    Left implicit, this would put the adapter into promiscuous mode and
    contradict the program's own claim to be a pure listener on one address.
    """
    install_pcap_layer(monkeypatch)

    sniffer = build_pcap_sniffer()

    assert sniffer._socket.kwargs == {
        "iface": IFACE,
        "filter": filter_for(HOST_IP),
        "promisc": False,
    }


def wait_for(predicate: Callable[[], bool], timeout_s: float = 2.0) -> bool:
    """Poll a condition the capture thread drives, giving up rather than hanging."""
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
    return True


def fake_packet_source(
    sniffer: capture._PcapSniffer, frames: list[bytes]
) -> Callable[[], Iterator[bytes]]:
    """A ``_packets`` stand-in: yields the frames, then waits for stop().

    The real reader blocks in ``pcap_next_ex`` between packets, which is where
    a stop lands; the fake waits on the same event.
    """

    def packets() -> Iterator[bytes]:
        yield from frames
        while not sniffer._stopping.is_set():
            time.sleep(0.001)

    return packets


def test_frames_from_the_driver_are_parsed_and_handed_over(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    install_pcap_layer(monkeypatch)
    received: list[str | None] = []
    started = threading.Event()
    sniffer = capture._PcapSniffer(
        IFACE, filter_for(HOST_IP), received.append, started.set
    )
    sniffer._packets = fake_packet_source(
        sniffer, [ethernet_frame(), ethernet_frame(OTHER_DEVICE_IP)]
    )

    sniffer.start()
    assert wait_for(lambda: len(received) == 2)
    sniffer.stop()

    assert received == [DEVICE_IP, OTHER_DEVICE_IP]
    assert started.is_set()
    assert sniffer.exception is None
    assert sniffer._socket.closed is True


def test_a_read_error_is_stored_and_ends_the_thread(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """An errored handle must not spin: the failure is stored and reported."""
    install_pcap_layer(monkeypatch)
    sniffer = capture._PcapSniffer(IFACE, filter_for(HOST_IP), ignore_packet, ignore_start)

    def failing() -> Iterator[bytes]:
        raise RuntimeError(FAILURE_MESSAGE)
        yield  # unreachable; makes this a generator

    sniffer._packets = failing

    sniffer.start()
    assert wait_for(lambda: sniffer.exception is not None)
    sniffer.stop()

    assert isinstance(sniffer.exception, RuntimeError)
    assert FAILURE_MESSAGE in str(sniffer.exception)
    assert sniffer.thread is not None and not sniffer.thread.is_alive()


def test_a_callback_exception_is_stored_and_ends_the_thread(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The callback's contract is never to raise; a breach is fatal and visible.

    A capture that cannot record is a capture that is lying, so the loop stops
    and the stored exception is what ``status()`` reports - the failure is
    never absorbed into a silently undercounting capture.
    """
    install_pcap_layer(monkeypatch)

    def raising(source_ip: str | None) -> None:
        raise RuntimeError(FAILURE_MESSAGE)

    sniffer = capture._PcapSniffer(IFACE, filter_for(HOST_IP), raising, ignore_start)
    sniffer._packets = fake_packet_source(sniffer, [ethernet_frame()])

    sniffer.start()
    assert wait_for(lambda: sniffer.exception is not None)
    sniffer.stop()

    assert isinstance(sniffer.exception, RuntimeError)


def test_an_unknown_datalink_is_reported_before_any_packet_is_read(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    install_pcap_layer(monkeypatch)
    started = threading.Event()
    sniffer = capture._PcapSniffer(
        IFACE, filter_for(HOST_IP), ignore_packet, started.set
    )
    sniffer._socket.pcap_fd = FakePcapFd(datalink=99)

    sniffer.start()
    assert wait_for(lambda: sniffer.exception is not None)
    sniffer.stop()

    assert isinstance(sniffer.exception, ValueError)
    assert "datalink" in str(sniffer.exception)
    assert not started.is_set()


def test_the_kernel_buffer_is_enlarged_on_open(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    enlarged: list[capture._PcapSniffer] = []
    monkeypatch.setattr(
        capture._PcapSniffer,
        "_enlarge_kernel_buffer",
        lambda self: enlarged.append(self),
    )
    install_pcap_layer(monkeypatch)

    sniffer = build_pcap_sniffer()

    assert enlarged == [sniffer]


def test_a_refused_kernel_buffer_enlargement_is_not_fatal(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default buffer remains, and the loss detection is the backstop.

    The fake handle is not a real ``pcap_t``, so the ctypes call always fails
    here - construction succeeding anyway is the point.
    """
    install_pcap_layer(monkeypatch)

    sniffer = build_pcap_sniffer()

    assert sniffer._socket.closed is False


def test_stopping_the_pcap_sniffer_releases_the_socket(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    install_pcap_layer(monkeypatch)
    sniffer = build_pcap_sniffer()
    sniffer._packets = fake_packet_source(sniffer, [])
    sniffer.start()

    sniffer.stop()

    assert sniffer._socket.closed is True


def test_stopping_a_sniffer_that_never_started_releases_the_socket(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    install_pcap_layer(monkeypatch)
    sniffer = build_pcap_sniffer()

    sniffer.stop()

    assert sniffer._socket.closed is True


# --------------------------------------------------------------------------
# Against scapy's real frame encoding
# --------------------------------------------------------------------------


@requires_scapy
def test_scapys_ethernet_encoding_matches_the_parser() -> None:
    """The parser's byte assumptions are checked against scapy's own encoding.

    A scapy release that changed what ``bytes(Ether()/IP()/UDP())`` produces
    would break the parser's assumptions here rather than in the field.
    """
    from scapy.all import ARP, IP, IPv6, UDP, Ether, Raw

    assert (
        parse_ipv4_src_en10mb(bytes(Ether() / IP(src=DEVICE_IP) / UDP()))
        == DEVICE_IP
    )
    assert (
        parse_ipv4_src_en10mb(
            bytes(Ether() / IP(src=DEVICE_IP) / UDP() / Raw(load=b"x" * 64))
        )
        == DEVICE_IP
    )
    assert parse_ipv4_src_en10mb(bytes(Ether() / ARP())) is None
    assert parse_ipv4_src_en10mb(bytes(Ether() / IPv6(src="fe80::1"))) is None
    assert parse_ipv4_src_en10mb(bytes(Ether() / Raw(load=TRUNCATED_FRAME))) is None


@requires_scapy
def test_scapys_ipv4_encoding_matches_the_loopback_parser() -> None:
    """DLT_NULL is the family header followed by the same IPv4 packet."""
    from scapy.all import IP, UDP

    frame = struct.pack("<I", AF_INET_HOST_ORDER) + bytes(
        IP(src=DEVICE_IP) / UDP()
    )

    assert parse_ipv4_src_null(frame) == DEVICE_IP
