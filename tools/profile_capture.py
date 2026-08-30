"""Time the per-packet stages of the capture path, in isolation.

The capture loop reads raw frames with ``pcap_next_ex`` and parses four bytes
of IPv4 header with ``struct``, because measuring showed scapy's full-packet
dissection dominating the userspace path - about 400 us of a ~450-640 us
per-packet cost, capping the capture near 1,700 packets/second. This tool is
the reproducible form of that measurement: what the dissection path costs
versus what the shipped raw-parse path costs, so a future scapy release or a
different traffic mix can be re-measured rather than re-debated.

Run: ``python tools/profile_capture.py``
"""

import ctypes
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# Run as a script, not a package module, so the repo root is put on the path
# explicitly rather than relying on the working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netmon import capture  # noqa: E402
from netmon.rate_window import RateWindow  # noqa: E402

FRAME_SRC_IP = "192.168.2.2"
FRAME_DST_IP = "192.168.2.1"
FRAME_PAYLOAD_BYTES = 64

MICRO_TARGET_S = 0.4
MICRO_REPS = 5


def build_frames() -> tuple[bytes, bytes]:
    """The representative frame on both datalinks the capture parses."""
    import struct

    from scapy.all import Ether, IP, UDP, Raw

    payload = Raw(load=b"x" * FRAME_PAYLOAD_BYTES)
    ip = IP(src=FRAME_SRC_IP, dst=FRAME_DST_IP) / UDP(sport=5000, dport=9999) / payload
    ethernet = bytes(
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip
    )
    null = struct.pack("<I", capture.AF_INET_HOST_ORDER) + bytes(ip)
    return ethernet, null


def scapy_extract(packet: Any) -> str | None:
    """What the callback paid per packet when scapy dissected: layer lookup
    plus a string conversion, on top of the dissection itself."""
    return str(packet["IP"].src)


def _time_per_op(operation: Callable[[], Any], label: str) -> float:
    """Microseconds per call, best of several calibrated runs.

    The minimum is the honest estimator here: every disturbance inflates a
    run, so the fastest run is the cleanest measure of the work itself.
    """
    probe_started = time.perf_counter()
    operation()
    probe_s = time.perf_counter() - probe_started
    iterations = max(100, int(MICRO_TARGET_S / max(probe_s, 1e-9) * 0.9))
    best = float("inf")
    for _ in range(MICRO_REPS):
        started = time.perf_counter()
        for _ in range(iterations):
            operation()
        elapsed = time.perf_counter() - started
        best = min(best, elapsed / iterations)
    per_op_us = best * 1e6
    print(f"  {label:<44} {per_op_us:8.2f} us")
    return per_op_us


def run_micro() -> int:
    """Time each per-packet stage, old path and new."""
    from scapy.all import Ether, Loopback

    ethernet, null = build_frames()
    print(f"frame: {len(ethernet)} bytes (Ethernet), {len(null)} bytes (DLT_NULL)\n")

    packet = Loopback(null)
    window = RateWindow()
    window.record(FRAME_SRC_IP)

    # scapy's pcap wrapper turns the driver's buffer into ``bytes`` via
    # ``bytes(bytearray(ptr[:len]))`` on a POINTER(c_ubyte) - a list of ints
    # in between. Reproduced here on an equivalent ctypes buffer; the shipped
    # path pays the same copy inside ``_PcapSniffer._packets``.
    c_ubyte = ctypes.c_ubyte
    buffer = ctypes.create_string_buffer(ethernet, len(ethernet))
    pointer = ctypes.cast(buffer, ctypes.POINTER(c_ubyte))
    length = len(ethernet)

    print("the old path: scapy dissection + layer extraction")
    dissect_us = _time_per_op(lambda: Ether(ethernet), "Ether() dissection")
    _time_per_op(lambda: Loopback(null), "Loopback() dissection (loopback)")
    extract_us = _time_per_op(lambda: scapy_extract(packet), "str(packet[IP].src)")

    print("\nthe shipped path: raw frame, struct parse, record")
    _time_per_op(
        lambda: bytes(bytearray(pointer[:length])), "ctypes pointer -> bytes copy"
    )
    parse_us = _time_per_op(
        lambda: capture.parse_ipv4_src_en10mb(ethernet), "parse_ipv4_src_en10mb"
    )
    _time_per_op(lambda: capture.parse_ipv4_src_null(null), "parse_ipv4_src_null")
    record_us = _time_per_op(
        lambda: window.record(FRAME_SRC_IP), "RateWindow.record (warm address)"
    )

    print(
        f"\nold per-packet userspace (dissect + extract + record): "
        f"~{dissect_us + extract_us + record_us:.0f} us"
        f"\nnew per-packet userspace (parse + record): "
        f"~{parse_us + record_us:.1f} us"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run_micro()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
