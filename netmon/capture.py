"""Passive packet capture that feeds :meth:`RateWindow.record`.

The monitor is a pure listener. It opens one libpcap handle on the adapter
holding the topside address, reads the source address of every packet arriving
*at* that address, and hands it to the aggregator. Nothing is transmitted, the
capture is not in the packet path, and promiscuous mode is switched off
explicitly.

The read loop is ours rather than scapy's sniffer, on measurement: scapy
builds a full structured object per packet, which costs about 400 us of CPU -
roughly 88% of the whole userspace path - and caps the capture near 1,700
packets/second, inside the range a BlueROV2 is expected to produce. The only
field this program has ever read is the source address, so the loop reads raw
frames with ``pcap_next_ex`` and parses those four bytes with ``struct``,
at about 37 us per packet all in. scapy still opens and configures the
socket - filter compilation, promiscuous mode, immediate delivery - which is
the tested territory worth keeping.

Three invariants shape the module, and none of them are obvious:

* **The packet callback is incapable of raising.** The read loop treats an
  escaped exception as fatal: it is stored and the thread exits. Because the
  aggregator scrolls every device's window whether or not it is sending, a
  dead capture renders as every device going quiet, which is the one failure
  this program exists to make visible - so a death is reported, never hidden.
* **Liveness is derived, never assumed.** A start confirmation, the stored
  exception and the thread together map onto the capture states - see
  :func:`derive_state`.
* **A failure is reported, never predicted.** Whether capture needs elevated
  rights depends on how Npcap was installed on Windows and on ``access_bpf``
  membership on macOS, so elevation is only ever used to *explain* a
  permission error that actually occurred.

scapy is imported lazily, inside the functions that need it: ``--mock`` must
keep working on a machine without scapy, the pure-logic tests must run without
it, and ``import scapy.all`` costs seconds of architecture initialisation.
"""

import ctypes
import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol

from .rate_window import RateWindow

WINDOWS_PLATFORM = "win32"
DARWIN_PLATFORM = "darwin"
# Live capture is built for these platforms. Every other value of
# ``sys.platform`` becomes ``unsupported_platform`` before a socket opens.
CAPTURE_PLATFORMS = frozenset({WINDOWS_PLATFORM, DARWIN_PLATFORM})
IPV4_FAMILY = 4
CAPTURE_FILTER_TEMPLATE = "ip dst {host_ip}"
PERMISSION_MARKER = "permission"

START_TIMEOUT_S = 5.0
START_POLL_S = 0.05
STOP_TIMEOUT_S = 2.0

# libpcap datalink types the capture can parse. The tether adapter is
# Ethernet; Npcap's loopback device, which the benchmark captures on, prepends
# a 4-byte host-byte-order address-family header instead.
DLT_NULL = 0
DLT_EN10MB = 1
NULL_HEADER_BYTES = 4
ETHERNET_HEADER_BYTES = 14
ETHERTYPE_IPV4 = 0x0800
AF_INET_HOST_ORDER = 2  # the DLT_NULL family value for IPv4 on Windows and macOS
IPV4_MIN_HEADER_BYTES = 20
IPV4_SRC_OFFSET = 12  # within the IPv4 header
IPV4_VERSION = 4

# The kernel buffer Npcap fills while userspace is busy. The driver's default
# is about 1 MB, which the benchmark showed absorbing only a few seconds of
# backlog once the capture falls behind; the larger request turns poll stalls
# and bursts into latency rather than loss. A refusal leaves the default in
# place and costs nothing.
KERNEL_BUFFER_BYTES = 8 * 2**20

# Fraction of the received packets that may go uncounted before the loss is
# worth an operator's attention. A capture that mislays a handful of packets
# while its socket is warming up would otherwise nag for the rest of the
# session, while a sustained loss crosses this within seconds.
LOSS_RATIO_TOLERANCE = 0.001

CAPTURE_STATE_OK = "ok"
CAPTURE_STATE_DROPPING_PACKETS = "dropping_packets"
CAPTURE_STATE_ERROR = "error"
CAPTURE_STATE_NOT_RUNNING = "not_running"
CAPTURE_STATE_CAPTURE_DIED = "capture_died"
CAPTURE_STATE_NEEDS_ELEVATION = "needs_elevation"
CAPTURE_STATE_NPCAP_MISSING = "npcap_missing"
CAPTURE_STATE_INTERFACE_MISSING = "interface_missing"
CAPTURE_STATE_UNSUPPORTED_PLATFORM = "unsupported_platform"

# Shown to an ROV operator verbatim in a banner, so each one names what has
# happened and what to do about it.
OK_DETAIL = "Capturing live traffic addressed to {host_ip}."
DROPPING_PACKETS_DETAIL = (
    "{lost:,} of the {received:,} packets that reached the capture driver were "
    "lost before they could be counted, so every rate shown here is "
    "undercounted. The driver reports {driver_dropped:,} of them discarded."
)
UNATTRIBUTED_DETAIL = "{count} packets could not be attributed to a device."
NOT_RUNNING_DETAIL = (
    "Packet capture is not running. Restart this program to see live traffic."
)
CAPTURE_DIED_DETAIL = (
    "Packet capture stopped unexpectedly after starting, so these rates are no "
    "longer live. Restart this program."
)
START_TIMEOUT_DETAIL = (
    "Packet capture did not confirm that it had started within {seconds:g} "
    "seconds, so these rates may not be live."
)
# The permission sentences are platform-specific because the remedy is: on
# Windows an operator restarts an elevated shell against Npcap, and on macOS
# they rerun with ``sudo`` or join the ``access_bpf`` group Wireshark installs.
# One sentence would be wrong on both machines, so ``_needs_elevation_detail``
# picks the right one from ``sys.platform`` at status time rather than baking
# either into the module.
NEEDS_ELEVATION_DETAIL_WINDOWS = (
    "Windows refused permission to capture packets. Restart this program as an "
    "administrator."
)
NEEDS_ELEVATION_DETAIL_DARWIN = (
    "macOS refused permission to capture packets. Rerun this program with "
    "sudo, or install Wireshark so its ChmodBPF helper puts you in the "
    "access_bpf group that can open /dev/bpf*."
)
ELEVATED_PERMISSION_DETAIL_WINDOWS = (
    "Windows refused permission to capture packets even though this program is "
    "already running as an administrator. Check that Npcap is installed and "
    "that its driver is running."
)
ELEVATED_PERMISSION_DETAIL_DARWIN = (
    "macOS refused permission to capture packets even though this program is "
    "already running as root. Check that /dev/bpf* is readable and that the "
    "tether adapter is up."
)
NPCAP_MISSING_DETAIL = (
    "Npcap is not installed, so live packet capture is unavailable. Install it "
    "from npcap.com and restart this program."
)
LIBPCAP_MISSING_DETAIL = (
    "libpcap is not available, so live packet capture is unavailable. macOS "
    "ships libpcap in /usr/lib/libpcap.dylib; if it is missing, install it "
    "(e.g. `brew install libpcap`) and restart this program."
)
INTERFACE_MISSING_DETAIL = (
    "No network adapter is using {host_ip}. Check that the tether is plugged in "
    "and that the adapter still holds that static address."
)
UNSUPPORTED_PLATFORM_DETAIL = (
    "Live packet capture is only available on Windows and macOS; this machine "
    "reports {platform}."
)
ERROR_DETAIL = "Packet capture failed: {message}"

INVALID_HOST_IP = "{host_ip!r} is not a valid IP address."


@dataclass(frozen=True)
class CaptureStatus:
    """What the UI is told about the health of the packet source."""

    state: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"state": self.state, "detail": self.detail}


class NpcapMissingError(RuntimeError):
    """scapy is importable but cannot capture through Npcap on Windows.

    The Windows-only sibling of :class:`LibpcapMissingError`: kept distinct so
    the state derivation can point Windows operators at npcap.com without
    conflating the two OSes' failure modes.
    """


class LibpcapMissingError(RuntimeError):
    """scapy is importable but cannot capture through libpcap on macOS.

    macOS ships libpcap by default, so this is genuinely unusual and reads
    through :func:`_status_from_exception` as ``error`` rather than a state
    of its own - unlike Windows, there is no single install to point at.
    """


class Sniffer(Protocol):
    """The slice of a capture thread this module depends on.

    ``running`` is deliberately absent: a flag set before the socket opens is
    unreliable as a health signal, so nothing here is allowed to consult one.
    """

    exception: BaseException | None
    thread: threading.Thread | None

    def start(self) -> None: ...

    def stop(self, timeout: float) -> None: ...


# The packet callback receives the parsed source address, or ``None`` for a
# frame that had none readable.
SnifferFactory = Callable[
    [str, str, Callable[[str | None], None], Callable[[], None]], Sniffer
]


def filter_for(host_ip: str) -> str:
    """BPF filter accepting only packets addressed to ``host_ip``.

    It deliberately carries **no** source-subnet term. The watched subnet is a
    parameter of each read, resolved per request, and two pages may watch
    different subnets against one process - so the capture layer cannot know
    which subnet will be asked for. Anything excluded here could never be
    recovered by a later read, which is exactly what the aggregator's retained
    history exists to allow.
    """
    try:
        ipaddress.ip_address(host_ip)
    except ValueError as error:
        raise ValueError(INVALID_HOST_IP.format(host_ip=host_ip)) from error
    return CAPTURE_FILTER_TEMPLATE.format(host_ip=host_ip)


def select_interface(
    host_ip: str, interfaces: Iterable[Any] | None = None
) -> str | None:
    """NPF device name of the adapter carrying ``host_ip``, or ``None``.

    ``conf.iface`` is not consulted: it resolves to whichever adapter scapy
    considers primary, which on a laptop is the Wi-Fi card, and capturing there
    would present the house LAN as plausible vehicle rows. No match is the
    ``interface_missing`` condition - the tether is unplugged or the static
    address is gone - rather than a reason to fall back to another adapter.

    ``interfaces`` substitutes the interface table in tests; production callers
    leave it out and scapy's own table is read.
    """
    if interfaces is None:
        interfaces = _scapy_conf().ifaces.data.values()
    names = sorted(
        interface.network_name
        for interface in interfaces
        if host_ip in (interface.ips.get(IPV4_FAMILY) or [])
    )
    # Two adapters sharing one address is a misconfiguration rather than a
    # choice, so pick by name and keep picking the same one across restarts.
    return names[0] if names else None


def _ipv4_src_at(frame: bytes, header_at: int) -> str | None:
    """Source address of the IPv4 packet at ``header_at``, or ``None``.

    The kernel filter has already accepted the frame as IPv4 addressed to the
    host, so what remains is bounds-checking and four bytes. Anything that
    fails those checks is malformed or truncated and counts as unattributable
    rather than raising: one escaped exception ends the capture permanently.
    """
    if len(frame) < header_at + IPV4_MIN_HEADER_BYTES:
        return None
    version_ihl = frame[header_at]
    ihl = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != IPV4_VERSION or ihl < IPV4_MIN_HEADER_BYTES:
        return None
    if len(frame) < header_at + ihl:
        return None
    return socket.inet_ntoa(frame[header_at + IPV4_SRC_OFFSET :][:4])


def parse_ipv4_src_en10mb(frame: bytes) -> str | None:
    """Source address of an Ethernet/IPv4 frame, or ``None``.

    802.1Q-tagged frames read as non-IPv4 here, which matches the kernel
    filter: libpcap's ``ip dst`` does not match VLAN-tagged packets without
    the ``vlan`` keyword, so they never reach this parser.
    """
    if len(frame) < ETHERNET_HEADER_BYTES + IPV4_MIN_HEADER_BYTES:
        return None
    if struct.unpack_from("!H", frame, 12)[0] != ETHERTYPE_IPV4:
        return None
    return _ipv4_src_at(frame, ETHERNET_HEADER_BYTES)


def parse_ipv4_src_null(frame: bytes) -> str | None:
    """Source address of a DLT_NULL loopback frame, or ``None``."""
    if len(frame) < NULL_HEADER_BYTES + IPV4_MIN_HEADER_BYTES:
        return None
    if struct.unpack_from("<I", frame, 0)[0] != AF_INET_HOST_ORDER:
        return None
    return _ipv4_src_at(frame, NULL_HEADER_BYTES)


def parser_for(datalink: int) -> Callable[[bytes], str | None]:
    """The raw-frame parser matching an adapter's libpcap datalink type.

    Anything else is a real error rather than a parse failure: a datalink this
    module has no parser for means every frame would be misread or discarded,
    which the capture states exist to report.
    """
    if datalink == DLT_EN10MB:
        return parse_ipv4_src_en10mb
    if datalink == DLT_NULL:
        return parse_ipv4_src_null
    raise ValueError(f"no parser for datalink {datalink}")


def derive_state(
    started: bool, exception: BaseException | None, thread_alive: bool
) -> str:
    """Map a sniffer's observable condition onto a capture state.

    The mapping is counterintuitive because scapy reports failure in two
    unrelated ways:

    ==========================  =========  ===========  ==============
    Condition                   started    exception    thread alive
    ==========================  =========  ===========  ==============
    Healthy                     True       None         True
    Setup failed                False      set          False
    Died mid-run                True       None         False
    ==========================  =========  ===========  ==============

    A stored exception therefore always wins, and a start that was never
    confirmed is a failure even when nothing was raised.
    """
    if exception is not None:
        if _is_permission_error(exception):
            return CAPTURE_STATE_NEEDS_ELEVATION
        return CAPTURE_STATE_ERROR
    if not started:
        return CAPTURE_STATE_ERROR
    return CAPTURE_STATE_OK if thread_alive else CAPTURE_STATE_CAPTURE_DIED


def packets_lost(received: int, counted: int) -> int:
    """How many packets the driver took in that never reached the callback.

    This gap, rather than libpcap's ``ps_drop``, is the honest measure of what
    the monitor is failing to count. A saturated capture was measured reporting
    ``ps_drop`` of zero while only half the received packets had arrived at the
    callback: the rest were sitting in Npcap's kernel buffer, which absorbs
    seconds of backlog and reports nothing wrong until it finally fills. The
    counters are also read a moment apart, so the difference is clamped rather
    than allowed to go negative.
    """
    return max(received - counted, 0)


def is_losing_packets(received: int, counted: int) -> bool:
    """Whether uncounted packets exceed :data:`LOSS_RATIO_TOLERANCE`.

    A ratio rather than any non-zero count, so a brief blip does not nag an
    operator for the rest of the session. A capture that has received nothing
    yet has lost nothing.
    """
    if received <= 0:
        return False
    return packets_lost(received, counted) / received > LOSS_RATIO_TOLERANCE


def is_elevated() -> bool:
    """Whether this process holds Administrator (Windows) or root (macOS) rights.

    Used only to *explain* a permission failure that has already happened. On
    Windows, Npcap can be installed without its admin-only restriction; on
    macOS the ``access_bpf`` group (installed by Wireshark's ChmodBPF helper)
    can grant capture without root - so in both cases an up-front check would
    report ``needs_elevation`` on a machine that captures fine.
    """
    if sys.platform == DARWIN_PLATFORM:
        # ``os.geteuid`` is absent on Windows, so guard even though this branch
        # will only ever run there.
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        return geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _needs_elevation_detail() -> str:
    """Platform-specific sentence for a refused permission this process cannot fix."""
    if sys.platform == DARWIN_PLATFORM:
        return NEEDS_ELEVATION_DETAIL_DARWIN
    return NEEDS_ELEVATION_DETAIL_WINDOWS


def _elevated_permission_detail() -> str:
    """Platform-specific sentence for a refused permission after elevation."""
    if sys.platform == DARWIN_PLATFORM:
        return ELEVATED_PERMISSION_DETAIL_DARWIN
    return ELEVATED_PERMISSION_DETAIL_WINDOWS


class CaptureSource:
    """Passive libpcap listener feeding :meth:`RateWindow.record`.

    Uses scapy over Npcap on Windows and scapy over Apple's system libpcap on
    macOS: the sniffer, read loop and drop-counter reads are the same on both.

    :meth:`start`, :meth:`stop` and :attr:`running` mirror ``MockSource`` so the
    server can treat the two sources interchangeably, and neither start nor stop
    raises: every failure becomes a state reported by :meth:`status`.

    ``sniffer_factory`` is the seam the tests drive. It is called with the
    resolved interface, the BPF filter, the source-address callback and the
    start-confirmation callback, and returns a :class:`Sniffer`.
    """

    def __init__(
        self,
        window: RateWindow,
        host_ip: str,
        iface: str | None = None,
        sniffer_factory: SnifferFactory | None = None,
    ) -> None:
        self._window = window
        self._host_ip = host_ip
        self._iface = iface
        self._sniffer_factory: SnifferFactory = sniffer_factory or _PcapSniffer
        self._sniffer: Sniffer | None = None
        self._failure: CaptureStatus | None = None
        self._started = threading.Event()
        # Written only by the capture thread, read by the HTTP threads. Plain
        # integers rather than anything guarded: the callback is the hottest
        # path in the program and a lock there would cost more packets than the
        # counters exist to notice.
        self._counted = 0
        self._unattributed = 0

    @property
    def running(self) -> bool:
        """Whether the capture thread is currently alive.

        This is thread liveness, not health: a capture whose socket never
        opened can still be alive for a moment. :meth:`status` is what the UI
        is told.
        """
        return self._sniffer is not None and _thread_alive(self._sniffer)

    def start(self) -> None:
        """Open the capture and begin recording. Never raises.

        The server starts its source inside its own startup path, where a
        monitor that refuses to run is far less useful than one that runs and
        says why it cannot see anything - so a wrong platform, a missing pcap
        backend, a missing adapter or a refused permission all become states
        instead of exceptions. Calling this twice is a no-op.
        """
        if self._sniffer is not None or self._failure is not None:
            return
        if sys.platform not in CAPTURE_PLATFORMS:
            self._failure = CaptureStatus(
                CAPTURE_STATE_UNSUPPORTED_PLATFORM,
                UNSUPPORTED_PLATFORM_DETAIL.format(platform=sys.platform),
            )
            return

        try:
            bpf_filter = filter_for(self._host_ip)
            iface = self._iface or select_interface(self._host_ip)
            if iface is None:
                self._failure = CaptureStatus(
                    CAPTURE_STATE_INTERFACE_MISSING,
                    INTERFACE_MISSING_DETAIL.format(host_ip=self._host_ip),
                )
                return
            sniffer = self._sniffer_factory(
                iface, bpf_filter, self._on_packet, self._started.set
            )
            # Held before it is started: the sniffer owns an open libpcap
            # handle from the moment it is built, and stop() is the only thing
            # that can release it.
            self._sniffer = sniffer
            sniffer.start()
        except NpcapMissingError as error:
            self._failure = CaptureStatus(CAPTURE_STATE_NPCAP_MISSING, str(error))
            return
        except LibpcapMissingError as error:
            # macOS ships libpcap, so its absence is not a state of its own
            # the way Npcap's is on Windows - there is no single installer to
            # point at. It reads as ``error`` and the UI banner shows the
            # sentence verbatim.
            self._failure = CaptureStatus(CAPTURE_STATE_ERROR, str(error))
            return
        except Exception as error:
            self._failure = _status_from_exception(error)
            return

        self._await_start(sniffer)

    def stop(self, timeout: float = STOP_TIMEOUT_S) -> None:
        """Stop the capture and release its socket. Never raises.

        Safe when the capture never started or has already died on its own,
        because the server calls this from an unconditional ``finally`` where a
        traceback would turn a clean Ctrl+C into a crash.
        """
        sniffer = self._sniffer
        if sniffer is None:
            return
        self._sniffer = None
        self._started.clear()
        try:
            sniffer.stop(timeout)
        except Exception:
            # A sniffer that is already dead has nothing left to stop, and
            # scapy signals that by raising. There is nothing to report.
            pass

    def status(self) -> CaptureStatus:
        """Current capture health, re-derived on every call.

        Deriving it per call rather than freezing it at startup is what lets a
        capture that dies at minute nine be reported at minute nine.
        """
        if self._failure is not None:
            return self._failure
        sniffer = self._sniffer
        if sniffer is None:
            return CaptureStatus(CAPTURE_STATE_NOT_RUNNING, NOT_RUNNING_DETAIL)

        exception = sniffer.exception
        state = derive_state(
            self._started.is_set(), exception, _thread_alive(sniffer)
        )
        if state == CAPTURE_STATE_OK:
            return self._healthy_status(sniffer)
        if state == CAPTURE_STATE_CAPTURE_DIED:
            return CaptureStatus(state, CAPTURE_DIED_DETAIL)
        if exception is None:
            return CaptureStatus(
                CAPTURE_STATE_ERROR,
                START_TIMEOUT_DETAIL.format(seconds=START_TIMEOUT_S),
            )
        return _status_from_exception(exception)

    def _await_start(self, sniffer: Sniffer) -> None:
        """Wait for the sniffer to confirm every socket opened.

        ``started_callback`` fires only once the sockets are up, which makes it
        the one reliable "startup succeeded" signal. A setup failure never
        fires it, so the wait also watches for the thread dying rather than
        burning the whole timeout on a failure that is already decided.
        """
        deadline = time.monotonic() + START_TIMEOUT_S
        while not self._started.wait(START_POLL_S):
            if sniffer.exception is not None or not _thread_alive(sniffer):
                return
            if time.monotonic() >= deadline:
                return

    def _on_packet(self, source_ip: str | None) -> None:
        """Attribute one captured packet to its source address. Never raises.

        See the module docstring: an exception escaping here would end the
        capture and leave every device's trace scrolling along the baseline,
        which is the picture that is supposed to mean "this device went quiet".
        The sniffer hands over the parsed source address, so what remains is a
        counter increment and one recording.
        """
        self._counted += 1
        if source_ip is None:
            self._unattributed += 1
            return
        try:
            self._window.record(source_ip)
        except Exception:
            self._unattributed += 1

    def _healthy_status(self, sniffer: Sniffer) -> CaptureStatus:
        """Status for a capture whose thread is alive and unbroken.

        Packet loss sits at the bottom of the precedence order, reachable only
        from here: every state above it means the rates are not live at all,
        which is worse news than rates that are live but undercounted. The
        driver's counter is read before ours so that a packet arriving between
        the two reads cannot manufacture a loss that never happened.

        All of the arithmetic lives here rather than in the callback, because
        this runs twice a second against a callback that runs thousands of
        times a second.
        """
        counts = _drop_counts(sniffer)
        received, driver_dropped = counts if counts is not None else (0, 0)
        counted = self._counted
        if is_losing_packets(received, counted):
            return CaptureStatus(
                CAPTURE_STATE_DROPPING_PACKETS,
                DROPPING_PACKETS_DETAIL.format(
                    lost=packets_lost(received, counted),
                    received=received,
                    driver_dropped=driver_dropped,
                ),
            )
        return CaptureStatus(CAPTURE_STATE_OK, self._ok_detail())

    def _ok_detail(self) -> str:
        """Sentence for a capture that is seeing everything it should."""
        parts = [OK_DETAIL.format(host_ip=self._host_ip)]
        if self._unattributed:
            parts.append(UNATTRIBUTED_DETAIL.format(count=self._unattributed))
        return " ".join(parts)


class _PcapSniffer:
    """Owns the libpcap socket and the capture thread as one unit.

    The socket is scapy's: opening it is filter compilation, promiscuous mode
    and immediate-delivery territory that scapy has already tested, and the
    drop counters are only reachable through the socket object. The read loop
    is ours, on measurement - scapy's sniffer pays for a full packet
    dissection per frame, the bulk of the per-packet cost, when the only field
    this program reads is four bytes of IPv4 header.
    """

    def __init__(
        self,
        iface: str,
        bpf_filter: str,
        on_packet: Callable[[str | None], None],
        on_started: Callable[[], None],
    ) -> None:
        conf = _require_pcap()

        # promisc=False explicitly: conf.sniff_promisc defaults to True and the
        # socket falls back to it, which would put the adapter into promiscuous
        # mode and contradict this program's own design.
        self._socket = conf.L2listen(
            iface=iface, filter=bpf_filter, promisc=False
        )
        self._on_packet = on_packet
        self._on_started = on_started
        self._exception: BaseException | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._enlarge_kernel_buffer()

    @property
    def exception(self) -> BaseException | None:
        return self._exception

    @property
    def thread(self) -> threading.Thread | None:
        return self._thread

    def start(self) -> None:
        thread = threading.Thread(
            target=self._run, name="netmon-capture", daemon=True
        )
        self._thread = thread
        thread.start()

    def stop(self, timeout: float = STOP_TIMEOUT_S) -> None:
        """Stop the read loop, then release the socket. Never raises.

        The join is bounded rather than open-ended, and the socket is left
        alone if the thread outlives it: closing a handle a blocked reader is
        still holding trades a clean shutdown for a crash in the capture
        thread. The thread is a daemon and its read times out within 100 ms,
        so an unresponsive one cannot hold the process open.
        """
        self._stopping.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        if thread is None or not thread.is_alive():
            self._socket.close()

    def _run(self) -> None:
        """Read frames, parse source addresses, feed the callback.

        Any escape - a failed read, an unknown datalink, a callback that
        breaks its contract - is stored and ends the thread: a capture that
        cannot read is a capture that is lying, so the failure surfaces
        through :meth:`CaptureSource.status` rather than being absorbed.
        """
        try:
            parse = parser_for(self._socket.pcap_fd.datalink())
            self._on_started()
            for frame in self._packets():
                self._on_packet(parse(frame))
        except Exception as error:
            self._exception = error

    def _packets(self) -> Iterator[bytes]:
        """Raw frames from the driver, until stopped or the read fails.

        The return code is kept, which scapy's own wrapper does not do: it
        collapses timeout and error into the same empty answer, and an errored
        handle answers immediately, so treating an error as a timeout would
        spin the loop at a full core while reporting nothing. The 100 ms read
        timeout scapy configures on the handle is what lets a stop land
        between packets.

        ponytail: calls libpcap's ``pcap_next_ex`` through scapy's private
        socket internals, because scapy exposes no read loop without its
        dissection. Ceiling - the ``pcap_fd.pcap`` attribute chain and the
        vendored ctypes binding are private API and, with the identical reach
        in :meth:`drop_counts`, are the reason scapy is pinned below 2.8.
        Upgrade path - none within scapy; a public raw-read API would replace
        this whole method.
        """
        from scapy.libs.winpcapy import pcap_geterr, pcap_next_ex, pcap_pkthdr

        header = ctypes.POINTER(pcap_pkthdr)()
        pkt_data = ctypes.POINTER(ctypes.c_ubyte)()
        handle = self._socket.pcap_fd.pcap
        while not self._stopping.is_set():
            result = pcap_next_ex(
                handle, ctypes.byref(header), ctypes.byref(pkt_data)
            )
            if result > 0:
                yield bytes(bytearray(pkt_data[: header.contents.caplen]))
            elif result == 0:
                continue  # the read timeout ticked over with no packet
            else:
                raise OSError(
                    f"pcap read failed: "
                    f"{pcap_geterr(handle).decode(errors='replace')}"
                )

    def _enlarge_kernel_buffer(self) -> None:
        """Ask the driver for a bigger kernel buffer than its ~1 MB default.

        A refusal or a missing binding leaves the default in place and costs
        nothing, so both are quiet: the loss detection in ``status()`` is the
        backstop either way.
        """
        try:
            from scapy.libs.winpcapy import pcap_setbuff

            pcap_setbuff(self._socket.pcap_fd.pcap, KERNEL_BUFFER_BYTES)
        except Exception:
            pass

    def drop_counts(self) -> tuple[int, int] | None:
        """``(received, dropped)`` from the capture driver, or ``None``.

        Known constraint: this is called from the HTTP threads twice a second
        against the same ``pcap_t`` the capture thread is reading from, and
        libpcap handles are not documented as thread-safe. It is empirically
        fine here, and the guard below turns a Python-level failure into
        "unknown", but it could not catch a fault inside the C call. Locking is
        deliberately not added: the callback's hot path is budgeted at a
        counter increment, so a lock there would cost more packets than these
        counters exist to notice.

        ponytail: reaches libpcap's ``pcap_stats`` through scapy's private
        socket internals, because scapy 2.7 exposes no statistics wrapper.
        Ceiling - both the ``pcap_fd.pcap`` attribute chain and the vendored
        ctypes binding are private API and are the likeliest thing to break on
        a scapy upgrade, so this degrades to "unknown" instead of failing.
        Upgrade path - drop this wrapper for a public ``stats()`` if scapy ever
        grows one.
        """
        try:
            from scapy.libs.winpcapy import pcap_stat, pcap_stats

            stats = pcap_stat()
            if pcap_stats(self._socket.pcap_fd.pcap, ctypes.byref(stats)) != 0:
                return None
            return int(stats.ps_recv), int(stats.ps_drop)
        except Exception:
            return None


def _scapy_conf() -> Any:
    """scapy's configuration object, imported lazily.

    On macOS scapy defaults to its native BPF socket rather than libpcap, and
    the flag has to be set on ``scapy.config`` *before* ``scapy.all`` runs its
    architecture init - once the arch layer has resolved ``conf.L2listen`` and
    ``scapy.arch.libpcap`` has been loaded, flipping ``use_pcap`` no longer
    substitutes the socket class. Doing it here keeps that seam in one place,
    and this module already ships all its scapy imports lazily so the extra
    pre-import costs nothing on a machine that never opens a capture.
    """
    if sys.platform == DARWIN_PLATFORM:
        from scapy.config import conf as pre_arch_conf

        pre_arch_conf.use_pcap = True
    from scapy.all import conf

    return conf


def _pcap_listen_socket_class() -> type:
    """scapy's libpcap listen-socket class, imported lazily.

    Its absence means scapy has no libpcap binding at all, which is how
    :func:`_require_pcap` recognises a missing Npcap on Windows and a missing
    system libpcap on macOS.
    """
    from scapy.arch.libpcap import L2pcapListenSocket

    return L2pcapListenSocket


def _pcap_missing_error() -> RuntimeError:
    """The right ``pcap is missing`` exception for this platform.

    Distinct types because the two failures have different remedies and
    different states: Windows has one installer at npcap.com and gets its own
    ``npcap_missing`` state; macOS ships libpcap in the base system, so a
    missing one is unusual and reads as ``error`` with a libpcap sentence.
    """
    if sys.platform == DARWIN_PLATFORM:
        return LibpcapMissingError(LIBPCAP_MISSING_DETAIL)
    return NpcapMissingError(NPCAP_MISSING_DETAIL)


def _require_pcap() -> Any:
    """Return scapy's config, having confirmed it will capture via libpcap.

    ``conf.use_pcap`` must be read *after* importing ``scapy.all``: read from
    ``scapy.config`` alone it is ``False`` on Windows simply because the
    architecture layer has not initialised yet. The listen-socket class is
    checked too, because the flag alone does not prove the class was
    substituted - and scapy's own Windows socket cannot see incoming TCP at
    all, so a silent substitution would look like a working capture that sees
    almost nothing. On macOS the same check catches the mirror-image failure:
    if libpcap could not be loaded, scapy leaves ``L2listen`` as its native
    BPF socket rather than the libpcap one.
    """
    conf = _scapy_conf()
    try:
        pcap_listen_socket = _pcap_listen_socket_class()
    except ImportError as error:
        raise _pcap_missing_error() from error
    listen_socket = conf.L2listen
    if not conf.use_pcap or not (
        isinstance(listen_socket, type)
        and issubclass(listen_socket, pcap_listen_socket)
    ):
        raise _pcap_missing_error()
    return conf


def _thread_alive(sniffer: Sniffer) -> bool:
    """Whether the sniffer's thread exists and is still running."""
    thread = sniffer.thread
    return thread is not None and thread.is_alive()


def _drop_counts(sniffer: Sniffer) -> tuple[int, int] | None:
    """Drop counters from a sniffer that can report them, else ``None``.

    The reading is unpacked here rather than trusted, because it comes from a
    private scapy attribute chain and ``status()`` answers every poll: a shape
    that changed under us must cost the drop counters, not the whole page.
    """
    reader = getattr(sniffer, "drop_counts", None)
    if reader is None:
        return None
    try:
        received, dropped = reader()
        return int(received), int(dropped)
    except Exception:
        return None


def _is_permission_error(error: BaseException) -> bool:
    """Whether an exception represents a refused capture permission.

    libpcap reports this as "You don't have permission to perform this capture
    on that device", wrapped by scapy in a plain ``OSError``, so the message is
    the only reliable marker.
    """
    return isinstance(error, PermissionError) or PERMISSION_MARKER in str(
        error
    ).lower()


def _status_from_exception(error: BaseException) -> CaptureStatus:
    """Pair a capture failure with the sentence an operator can act on."""
    state = derive_state(started=False, exception=error, thread_alive=False)
    if state == CAPTURE_STATE_NEEDS_ELEVATION:
        detail = (
            _elevated_permission_detail()
            if is_elevated()
            else _needs_elevation_detail()
        )
        return CaptureStatus(state, detail)
    return CaptureStatus(state, ERROR_DETAIL.format(message=error))
