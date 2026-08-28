"""Tests for the passive packet-capture source.

The trust boundary is the packet object scapy hands to the callback, so
everything on this side of it is exercised with no hardware, no Npcap and - for
the logic tests - no scapy at all. The sniffer itself is replaced by a fake that
reproduces scapy's unhelpful failure signalling: ``running`` left ``True`` on a
dead thread after a setup failure, and ``exception`` left ``None`` when the
sniff loop kills itself over a raising callback.

The handful of tests that do want the real dispatch loop run offline packets
through ``scapy.sniff`` and skip cleanly when scapy is absent, so that a future
release which changes whether a raising callback is fatal fails here rather than
in the field.
"""

import importlib.util
import subprocess
import sys
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
    extract_source_ip,
    filter_for,
    is_losing_packets,
    packets_lost,
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
    """Stands in for scapy's ``AsyncSniffer``, misleading signals included."""

    def __init__(self, iface, bpf_filter, on_packet, on_started) -> None:
        self.iface = iface
        self.filter = bpf_filter
        self.on_packet = on_packet
        self.on_started = on_started
        # Nothing in the module is allowed to trust this, so it is left saying
        # the wrong thing whenever scapy would.
        self.running = False
        self.exception: BaseException | None = None
        self.thread: FakeThread | None = None
        self.alive = True
        self.confirm_start = True
        self.start_error: BaseException | None = None
        self.stop_error: BaseException | None = None
        self.stopped_with: float | None = None

    def start(self) -> None:
        # scapy sets running before opening the socket, so a setup failure
        # leaves it True on a thread that is already gone.
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
        """Reproduce a callback exception killing the sniff loop.

        ``running`` goes False, the thread exits, and ``exception`` is left
        unset - the failure appears nowhere but a log warning.
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


class FakeLayer:
    def __init__(self, src: str) -> None:
        self.src = src


class FakePacket:
    """Minimal stand-in for a scapy packet's layer lookup."""

    def __init__(self, **layers: FakeLayer) -> None:
        self._layers = layers

    def __getitem__(self, name: str) -> FakeLayer:
        try:
            return self._layers[name]
        except KeyError:
            raise IndexError(f"Layer [{name!r}] not found") from None


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
    sniffer: FakeSniffer, count: int, packet: FakePacket | None = None
) -> None:
    """Push ``count`` packets through the capture callback."""
    if packet is None:
        packet = FakePacket(IP=FakeLayer(DEVICE_IP))
    for _ in range(count):
        sniffer.on_packet(packet)


class FakeInterface:
    def __init__(self, network_name: str, *addresses: str) -> None:
        self.network_name = network_name
        self.ips = {4: list(addresses), 6: []}


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


# --------------------------------------------------------------------------
# Packet-to-IP extraction
# --------------------------------------------------------------------------


def test_the_source_address_of_an_ipv4_packet_is_extracted() -> None:
    packet = FakePacket(IP=FakeLayer(DEVICE_IP))

    assert extract_source_ip(packet) == DEVICE_IP


@pytest.mark.parametrize(
    "packet",
    [
        FakePacket(ARP=FakeLayer(DEVICE_IP)),
        FakePacket(IPv6=FakeLayer("fe80::1")),
        FakePacket(),
        FakePacket(IP=FakeLayer("")),
        None,
        object(),
        "not a packet",
        42,
    ],
)
def test_anything_without_a_usable_ipv4_layer_extracts_to_nothing(packet) -> None:
    assert extract_source_ip(packet) is None


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
    assert extract_source_ip(FakePacket(IP=FakeLayer(DEVICE_IP))) == DEVICE_IP


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

    factory.sniffer.on_packet(FakePacket(IP=FakeLayer(DEVICE_IP)))
    factory.sniffer.on_packet(FakePacket(IP=FakeLayer(OTHER_DEVICE_IP)))
    factory.sniffer.on_packet(FakePacket(IP=FakeLayer(DEVICE_IP)))

    assert recorded_addresses(window) == [DEVICE_IP, OTHER_DEVICE_IP]
    assert window.snapshot()["devices"][0]["total_packets"] == 2


@pytest.mark.parametrize(
    "packet",
    [
        FakePacket(ARP=FakeLayer(DEVICE_IP)),
        FakePacket(IPv6=FakeLayer("fe80::1")),
        FakePacket(IP=FakeLayer("")),
        FakePacket(),
        None,
        object(),
        b"",
    ],
)
def test_the_callback_never_raises_on_a_frame_it_cannot_read(
    on_windows: None, window: RateWindow, packet
) -> None:
    """One escaped exception would end the capture permanently."""
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(packet)

    assert recorded_addresses(window) == []
    assert source.status().state == CAPTURE_STATE_OK


def test_an_unreadable_frame_does_not_stop_later_ones_being_counted(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(FakePacket(ARP=FakeLayer(DEVICE_IP)))
    factory.sniffer.on_packet(FakePacket(IP=FakeLayer(DEVICE_IP)))

    assert recorded_addresses(window) == [DEVICE_IP]


def test_unattributable_packets_are_counted_and_surfaced(
    on_windows: None, window: RateWindow
) -> None:
    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    factory.sniffer.on_packet(FakePacket(ARP=FakeLayer(DEVICE_IP)))
    factory.sniffer.on_packet(FakePacket())

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
    feed_packets(
        factory.sniffer, RECEIVED_SAMPLE, FakePacket(ARP=FakeLayer(DEVICE_IP))
    )

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
# Against scapy's real dispatch loop
# --------------------------------------------------------------------------


def offline_frames() -> list:
    """One frame of every kind the capture has to survive."""
    from scapy.all import ARP, IP, IPv6, UDP, Ether, Raw

    return [
        Ether() / IP(src=DEVICE_IP) / UDP(),
        Ether() / ARP(),
        Ether() / IPv6(src="fe80::1"),
        Ether() / Raw(load=TRUNCATED_FRAME),
        Ether() / IP(src=OTHER_DEVICE_IP) / UDP(),
    ]


@requires_scapy
def test_a_raising_callback_really_does_end_a_real_capture() -> None:
    """The premise of the whole design, asserted against scapy itself.

    If a future release stops treating a raising callback as fatal, this fails
    loudly here instead of quietly changing what the module has to defend
    against.
    """
    from scapy.all import sniff

    seen = []

    def raising(packet) -> None:
        seen.append(packet)
        raise RuntimeError(FAILURE_MESSAGE)

    sniff(offline=offline_frames(), prn=raising, store=False)

    assert len(seen) == 1


@requires_scapy
def test_the_real_callback_survives_every_frame_and_keeps_counting(
    on_windows: None, window: RateWindow
) -> None:
    from scapy.all import sniff

    factory = FakeSnifferFactory()
    source = build_source(window, factory)
    source.start()

    sniff(offline=offline_frames(), prn=factory.sniffer.on_packet, store=False)

    assert recorded_addresses(window) == [DEVICE_IP, OTHER_DEVICE_IP]
    assert source.status().state == CAPTURE_STATE_OK
