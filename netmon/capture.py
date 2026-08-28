"""Passive packet capture that feeds :meth:`RateWindow.record`.

The monitor is a pure listener. It opens one libpcap handle on the adapter
holding the topside address, reads the source address of every packet arriving
*at* that address, and hands it to the aggregator. Nothing is transmitted, the
capture is not in the packet path, and promiscuous mode is switched off
explicitly.

Three properties of scapy's sniffer shape this module, and none of them are
obvious from its documentation:

* **An exception raised inside the packet callback ends the capture.** The
  sniff loop catches it, warns, drops the socket and exits the thread - leaving
  ``exception`` unset. Because the aggregator scrolls every device's window
  whether or not it is sending, a dead capture renders as every device going
  quiet, which is the one failure this program exists to make visible. The
  callback here is therefore incapable of raising.
* **``running`` is not a liveness signal.** It is set before the socket is
  opened, so a setup failure leaves it ``True`` on a thread that is already
  dead. State is derived from the combination of a start confirmation, the
  stored exception and the thread - see :func:`derive_state`.
* **A failure is reported, never predicted.** Whether capture needs
  Administrator rights depends on how Npcap was installed, so elevation is only
  ever used to *explain* a permission error that actually occurred.

scapy is imported lazily, inside the functions that need it: ``--mock`` must
keep working on a machine without scapy, the pure-logic tests must run without
it, and ``import scapy.all`` costs seconds of architecture initialisation.
"""

import ctypes
import ipaddress
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from .rate_window import RateWindow

WINDOWS_PLATFORM = "win32"
IPV4_FAMILY = 4
IPV4_LAYER = "IP"
CAPTURE_FILTER_TEMPLATE = "ip dst {host_ip}"
PERMISSION_MARKER = "permission"

START_TIMEOUT_S = 5.0
START_POLL_S = 0.05
STOP_TIMEOUT_S = 2.0

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
UNATTRIBUTED_DETAIL = (
    "{count} packets arrived with no address that could be counted."
)
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
NEEDS_ELEVATION_DETAIL = (
    "Windows refused permission to capture packets. Restart this program as an "
    "administrator."
)
ELEVATED_PERMISSION_DETAIL = (
    "Windows refused permission to capture packets even though this program is "
    "already running as an administrator. Check that Npcap is installed and "
    "that its driver is running."
)
NPCAP_MISSING_DETAIL = (
    "Npcap is not installed, so live packet capture is unavailable. Install it "
    "from npcap.com and restart this program."
)
INTERFACE_MISSING_DETAIL = (
    "No network adapter is using {host_ip}. Check that the tether is plugged in "
    "and that the adapter still holds that static address."
)
UNSUPPORTED_PLATFORM_DETAIL = (
    "Live packet capture is only available on Windows; this machine reports "
    "{platform}."
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
    """scapy is importable but cannot capture through libpcap/Npcap."""


class Sniffer(Protocol):
    """The slice of scapy's ``AsyncSniffer`` this module depends on.

    ``running`` is deliberately absent: it is unreliable as a health signal, so
    nothing here is allowed to consult it.
    """

    exception: BaseException | None
    thread: threading.Thread | None

    def start(self) -> None: ...

    def stop(self, timeout: float) -> None: ...


SnifferFactory = Callable[
    [str, str, Callable[[Any], None], Callable[[], None]], Sniffer
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


def extract_source_ip(packet: Any) -> str | None:
    """Source address of a captured IPv4 packet, or ``None`` if it has none.

    Indexing the layer by name keeps this free of scapy imports, and the broad
    guard is the point rather than laziness: ARP, IPv6 and truncated frames all
    raise here, and one escaped exception ends the capture permanently.
    """
    try:
        source_ip = str(packet[IPV4_LAYER].src)
    except Exception:
        return None
    return source_ip or None


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
    """Whether this process holds Administrator rights.

    Used only to *explain* a permission failure that has already happened.
    Npcap can be installed without its admin-only restriction, in which case an
    unelevated capture works perfectly and an up-front check would report
    ``needs_elevation`` on a machine that captures fine.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class CaptureSource:
    """Passive scapy/Npcap listener feeding :meth:`RateWindow.record`.

    :meth:`start`, :meth:`stop` and :attr:`running` mirror ``MockSource`` so the
    server can treat the two sources interchangeably, and neither start nor stop
    raises: every failure becomes a state reported by :meth:`status`.

    ``sniffer_factory`` is the seam the tests drive. It is called with the
    resolved interface, the BPF filter, the packet callback and the
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
        says why it cannot see anything - so a wrong platform, a missing Npcap,
        a missing adapter or a refused permission all become states instead of
        exceptions. Calling this twice is a no-op.
        """
        if self._sniffer is not None or self._failure is not None:
            return
        if sys.platform != WINDOWS_PLATFORM:
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
            sniffer.start()
        except NpcapMissingError as error:
            self._failure = CaptureStatus(CAPTURE_STATE_NPCAP_MISSING, str(error))
            return
        except Exception as error:
            self._failure = _status_from_exception(error)
            return

        self._sniffer = sniffer
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

    def _on_packet(self, packet: Any) -> None:
        """Attribute one captured packet to its source address. Never raises.

        See the module docstring: an exception escaping here would silently end
        the capture and leave every device's trace scrolling along the
        baseline, which is the picture that is supposed to mean "this device
        went quiet".
        """
        self._counted += 1
        source_ip = extract_source_ip(packet)
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
    """Owns the libpcap socket and scapy's sniffing thread as one unit.

    The socket is opened here rather than left to ``AsyncSniffer(iface=...)``
    because drop counts are only reachable through the socket object - and
    ``AsyncSniffer`` closes only sockets it opened itself, so closing this one
    is our job.
    """

    def __init__(
        self,
        iface: str,
        bpf_filter: str,
        on_packet: Callable[[Any], None],
        on_started: Callable[[], None],
    ) -> None:
        conf = _require_pcap()
        from scapy.sendrecv import AsyncSniffer

        # promisc=False explicitly: conf.sniff_promisc defaults to True and the
        # socket falls back to it, which would put the adapter into promiscuous
        # mode and contradict this program's own design.
        self._socket = conf.L2listen(
            iface=iface, filter=bpf_filter, promisc=False
        )
        try:
            self._sniffer = AsyncSniffer(
                opened_socket=self._socket,
                prn=on_packet,
                store=False,
                started_callback=on_started,
            )
        except Exception:
            self._socket.close()
            raise

    @property
    def exception(self) -> BaseException | None:
        return self._sniffer.exception

    @property
    def thread(self) -> threading.Thread | None:
        return self._sniffer.thread

    def start(self) -> None:
        self._sniffer.start()

    def stop(self, timeout: float = STOP_TIMEOUT_S) -> None:
        """Ask the sniffer to finish, then release the socket.

        The join is bounded rather than open-ended, and the socket is left
        alone if the thread outlives it: closing a handle a blocked reader is
        still holding trades a clean shutdown for a crash in the capture
        thread. The thread is a daemon, so an unresponsive one cannot hold the
        process open.
        """
        try:
            self._sniffer.stop(join=False)
        except Exception:
            # scapy raises when the sniffer is not running, which is exactly
            # the case where there is nothing left to stop.
            pass
        thread = self._sniffer.thread
        if thread is not None:
            thread.join(timeout)
        if thread is None or not thread.is_alive():
            self._socket.close()

    def drop_counts(self) -> tuple[int, int] | None:
        """``(received, dropped)`` from the capture driver, or ``None``.

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
    """scapy's configuration object, imported lazily."""
    from scapy.all import conf

    return conf


def _require_pcap() -> Any:
    """Return scapy's config, having confirmed it will capture via libpcap.

    ``conf.use_pcap`` must be read *after* importing ``scapy.all``: read from
    ``scapy.config`` alone it is ``False`` simply because the architecture
    layer has not initialised yet. The listen-socket class is checked too,
    because the flag alone does not prove the class was substituted - and
    scapy's own Windows socket cannot see incoming TCP at all, so a silent
    substitution would look like a working capture that sees almost nothing.
    """
    conf = _scapy_conf()
    try:
        from scapy.arch.libpcap import L2pcapListenSocket
    except ImportError as error:
        raise NpcapMissingError(NPCAP_MISSING_DETAIL) from error
    listen_socket = conf.L2listen
    if not conf.use_pcap or not (
        isinstance(listen_socket, type)
        and issubclass(listen_socket, L2pcapListenSocket)
    ):
        raise NpcapMissingError(NPCAP_MISSING_DETAIL)
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
            ELEVATED_PERMISSION_DETAIL if is_elevated() else NEEDS_ELEVATION_DETAIL
        )
        return CaptureStatus(state, detail)
    return CaptureStatus(state, ERROR_DETAIL.format(message=error))
