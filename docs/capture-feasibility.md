# Packet Capture Feasibility

> Reference material for the capture layer: why the stack is our own read loop
> over scapy over Npcap, what the kernel filter is and deliberately is not, and
> the handful of scapy and driver behaviours the design has to work around.

This document records the research and the measurements behind the capture
design, so decisions about it start from evidence rather than a leap of faith.

## Verdict: feasible, and it adds zero network traffic

The monitor is a **pure listener**. It asks the OS for copies of packets that
were already arriving and transmits nothing, so it adds no load to the tether
and the ROV cannot tell it is running.

It is explicitly **not** in the packet path. Windows technologies that
intercept traffic and can therefore drop or alter it — WinDivert, the Windows
Filtering Platform — are deliberately not used. Promiscuous mode is not needed
either: we only want packets addressed to us, which the NIC already accepts.

That last one has to be asserted rather than assumed. `conf.sniff_promisc`
defaults to `True` and the listen socket falls back to it, so `promisc=False`
is passed explicitly at every socket we open. Left implicit, the capture would
put the adapter into promiscuous mode and contradict this claim.

The real costs are a one-time driver install and a pip dependency on scapy.
Elevation is a third cost only sometimes — see
[Elevation is conditional](#elevation-is-conditional).

## Where this runs

Blue Robotics' own setup instructions have the operator assign `192.168.2.1` as
a **static IP on the topside computer's Ethernet adapter**, with the ROV at
`192.168.2.2`. So this runs on the operator's laptop, not on the vehicle, which
is why the host OS matters at all. **Windows** is the only platform capture is
built for.

## The capture stack: scapy over Npcap

Three layers, each owned by someone other than us wherever possible:

```
netmon/capture.py    reads raw frames via pcap_next_ex, parses the source IP with struct
       |
scapy                opens and configures the socket: filter, promisc=False, immediate delivery
       |
Npcap                kernel driver, does the actual capturing, one-time installer
       |
network adapter      packets arriving from the 192.168.2.x subnet
```

The `filter` is a BPF expression compiled and applied **in the kernel**, so
Python never sees packets that are not addressed to us. Socket setup — filter
compilation, promiscuous mode, immediate delivery — and TCP-versus-UDP
visibility are scapy and Npcap's tested territory rather than something this
project has to validate. What the read loop adds on top is deliberately small:
four bytes at a fixed offset.

The integration is a socket scapy opens, plus a read loop of ours:

```python
socket = conf.L2listen(iface=iface, filter=f"ip dst {host_ip}", promisc=False)
pcap_setbuff(socket.pcap_fd.pcap, KERNEL_BUFFER_BYTES)  # 8 MB of burst headroom
parse = parser_for(socket.pcap_fd.datalink())           # Ethernet or DLT_NULL
on_started()                                            # socket up: start confirmed

while not stopping.is_set():
    result = pcap_next_ex(handle, byref(header), byref(pkt_data))
    if result > 0:
        on_packet(parse(frame))  # must be incapable of raising - see below
    elif result == 0:
        continue                 # read timeout ticked over; stop lands here
    else:
        raise OSError(...)       # stored on the sniffer, ends the thread


def on_packet(source_ip):
    """Must be incapable of raising - see below."""
    if source_ip is None:
        return
    try:
        window.record(source_ip)
    except Exception:
        return
```

### The callback guard is mandatory, not defensive habit

**An exception escaping the read loop terminates the entire capture.** The
loop's top level catches anything that escapes — a failed read, an unknown
datalink, a callback that breaks its contract — stores it on the sniffer, and
lets the thread exit. Nothing restarts it. That is deliberate rather than
fragile: a capture that cannot read is a capture that is lying, so the failure
is stored where `status()` will find it instead of being absorbed.

That matters far more than it looks, because of how it lands on the page. The
aggregator deliberately scrolls every device's window whether or not it is
sending, so silence renders as a line marching left along the baseline, chosen
to mean "this device went quiet". A dead capture makes **every** device render
exactly that way: a stalled monitor that looks like working software, which is
the one failure this program exists to make visible.

The parse cannot raise: a frame with no readable source address — malformed,
truncated, not IPv4 — parses to `None` and is counted as unattributable. What
remains guarded is the recording itself, wrapped so that a failure there costs
one packet's attribution rather than the capture.

Liveness is derived, never assumed. The sniffer exposes **no `running` flag at
all** — a boolean set before the socket opens is unreliable as a health signal,
so nothing in the module is allowed to consult one. What it exposes instead is
a start confirmation, fired only once the socket is open and the parser chosen;
the stored `exception`; and the thread. The three map onto the capture states
counterintuitively:

| Condition    | started | exception | thread alive |
|--------------|---------|-----------|--------------|
| Healthy      | True    | None      | True         |
| Setup failed | False   | set       | False        |
| Died mid-run | True    | None      | False        |

A stored exception always wins, and a start that was never confirmed is a
failure even when nothing was raised. The mapping is re-derived on every poll
rather than resolved once at startup, so a capture that dies at minute nine is
reported at minute nine.

## The BPF filter, and why the subnet stays out of it

The filter is:

```
ip dst <host_ip>
```

and it deliberately carries **no subnet term**. This needs stating explicitly,
because tightening it to something like `src net 192.168.2.0/24 and ip dst
192.168.2.1` looks like an obvious improvement and would silently break the
subnet control.

The watched subnet is a **parameter of the read**, resolved per request in the
handler, and two browsers may watch different subnets against one process. The
capture layer therefore cannot know which subnet will be asked for; a
capture-time source filter would have to be the union of every subnet any
client might ever type, which collapses to no filter at all. Worse, anything
the filter excludes can never be recovered by a later read — the aggregator
retains history precisely so that switching subnets is non-destructive, and a
capture-time subnet filter would defeat that.

**What `ip dst <host_ip>` excludes, deliberately:** broadcast, multicast and
ARP, since `dst` must equal the host address exactly. A device that only ever
broadcasts, or only ARPs, will never appear as a row. That suits a page about
per-device rates rather than discovery, but it is an assumption about real ROV
traffic that only the vehicle can confirm.

## Interface selection is ours, not scapy's

`conf.iface` resolves to whichever adapter scapy considers primary, which on a
laptop is the Wi-Fi card. Sniffing it would capture the house LAN and present
it as plausible vehicle rows, so the interface is derived instead by scanning
scapy's interface table for the adapter carrying the host address — the same
static `192.168.2.1` Blue Robotics has the operator set on the Ethernet port.
No adapter carrying that address is a real detection rather than a guess: the
tether is unplugged or the static address is gone.

## Why not the standard library (evaluated and rejected)

Worth recording, because "why not just use a raw socket?" is the obvious first
question and the answer is non-obvious.

Windows exposes `socket.SIO_RCVALL`, which is present in the stdlib (verified on
the development machine — `AF_PACKET: False`, `SIO_RCVALL: True`), and it
appears to work. Scapy implements exactly this technique in
`scapy/arch/windows/native.py` as its no-Npcap fallback, and documents what it
found:

> Unofficial limitations:
> - Turns out we actually don't see any incoming TCP data, only the outgoing. We
>   do properly see UDP, ICMP, etc. both ways though.
>
> **To overcome those limitations, install Npcap.**

That is disqualifying rather than inconvenient. A device speaking only TCP would
never appear as a row, and TCP-heavy devices would be silently undercounted.
Because most ROV traffic is UDP — video, MAVLink, sonar — it would have looked
like it was working.

Two further strikes:

- `SIO_RCVALL` does no kernel-side filtering, so every packet on the interface
  crosses into userspace only to be discarded in Python.
- It is reportedly broken by TCP Offload Engines and can be suppressed by the
  Windows firewall.

## Npcap: prerequisite, licensing, and detection

Npcap is the packet-capture driver Wireshark installs on Windows; it is the
standard answer because Windows has no built-in equivalent. It is already
present on the development machine (`wpcap.dll` and the `Npcap` system directory
both found).

### Licensing

Fine for our usage model, but it does constrain packaging. The free version is
capped at five systems and forbids redistribution, so **we must not bundle the
installer**. Npcap's license explicitly permits the arrangement we want:

> Software providers (open source or otherwise) which want to use Npcap
> functionality are welcome to point their users to npcap.com for those users to
> download and install.

Bundling would require an OEM redistribution licence.

### Detection

Detection is **required**. A missing Npcap is reported through `capture.state`
as `npcap_missing`, with a `detail` naming npcap.com, rather than crashing or
silently falling back to the broken stdlib path. Scapy must also be prevented
from quietly substituting its native socket, so `conf.use_pcap` is **asserted,
not assumed**.

Two details make that assertion easy to get wrong:

- It must be read **after importing `scapy.all`**. Read from `scapy.config`
  alone it reports `False` simply because the architecture layer has not
  initialised, so an assertion in the wrong place fails spuriously on a machine
  where Npcap works.
- The flag alone does not prove the substitution happened, so `conf.L2listen`
  is checked to be the pcap listen socket class as well. Scapy's own Windows
  socket cannot see incoming TCP at all, and a silent substitution would
  present as a working capture that sees almost nothing.

## Elevation is conditional

Whether capture needs Administrator rights is a property of **how Npcap was
installed**, not of Windows. On the development machine Npcap has
`AdminOnly=0`, and an unelevated passive capture on the tether adapter opens,
filters, runs and stops cleanly.

So a permission failure is **detected, never predicted**. Gating on
`IsUserAnAdmin()` up front would report `needs_elevation` on a machine that
captures perfectly; elevation state is consulted only to *explain* a permission
error that has actually occurred, which is what makes the difference between
"restart as an administrator" and "you already are, so check the Npcap driver".

## Dropped packets are a production signal

Silent kernel drops are how a capture that is losing traffic would otherwise
hide behind plausible-looking rates, so the driver's counters are read in normal
operation rather than only under benchmark.

Scapy 2.7.0 exposes no `stats()` wrapper, so this needs a small ctypes call
against libpcap's `pcap_stats`, reached through the socket. The socket is ours
outright — scapy opens it, our loop reads it — so its cleanup is ours too, and
the handle chain (`socket.pcap_fd.pcap`) it is reached through is private scapy
API. That same chain also carries the read loop's `pcap_next_ex`, making it the
likeliest thing to break on upgrade and the reason scapy is pinned to
`>=2.7.0,<2.8`. The reader is one small function that degrades to "drops
unknown" rather than crashing if that chain ever changes.

What is done with the counters matters as much as reading them. The loss signal
is the gap between `ps_recv` and the packets actually counted, not `ps_drop` —
see [`ps_drop` under-reports](#ps_drop-under-reports-trust-the-gap-instead)
below — and the `dropping_packets` capture state is derived from that gap as a
ratio of received packets, with `ps_drop` carried into the detail sentence as
corroboration.

## Performance: measure, do not guess

The capture path's ceiling was estimated, then measured, then profiled — and
each step overturned the one before. The estimate put scapy's per-packet
dissection at 100–300 microseconds and the ceiling around 3,000–10,000
packets/second, against the 1,000–5,000 a BlueROV2 pushing video plus telemetry
is expected to produce: plausibly fine, but genuinely close enough to warrant
checking. The measurement found the ceiling at about 1,700 packets/second — the
*bottom* of the expected range. The profile then attributed the 550–640
microseconds of CPU per packet: roughly **88% of it was scapy's per-packet
dissection (~400 microseconds)**, the driver read 40–65, the packet callback
about 15.

The only field this program has ever read is the source address, so the fix
needed no parsing library: the loop reads raw frames with `pcap_next_ex` and
unpacks those four bytes with the standard-library `struct` module, at about 40
microseconds per packet all in, of which the parse itself is about 2. Scapy
keeps the parts worth keeping — opening the socket, compiling the filter,
configuring delivery — and the kernel buffer is enlarged to 8 MB with
`pcap_setbuff`, so bursts and poll stalls become latency rather than loss.

## Measured throughput

**Zero drops at 20,000 packets/second offered, at 0.88 of a core.** The ceiling
is above what the generator can offer, so this harness cannot find it; the
1,000–5,000 packets/second a BlueROV2 is expected to produce sits well
underneath it.

The figures come from `tools/benchmark_capture.py`, a loopback sweep that drives
the shipped capture path — Npcap, the kernel filter, the frame read and parse,
the packet callback, `RateWindow.record` — against a paced UDP generator running
in a separate process, thirty seconds per step. A 2 Hz poller runs against a real
`/api/rates` endpoint throughout, and the sweep repeats at three retained-address
counts, because `RateWindow.snapshot` holds the lock the callback needs. Each
step records four numbers together, since any one alone misleads: packets that
reached the callback, the driver's `ps_recv` and `ps_drop`, the capture thread's
CPU time, and the generator's own send count as ground truth for offered load.

`unproc` below is `ps_recv − ps_drop − counted`: packets the driver accepted and
did not report as dropped, which nonetheless never reached the callback.

**The table below measured the scapy-based path** — per-packet dissection in
the callback, the architecture the profile above replaced. Its ceilings and
per-packet costs describe that path, not the shipped one. It stands because its
driver-level findings — `ps_drop` under-reporting, the kernel-buffer backlog —
and its lock-contention findings are properties of Npcap and the aggregator
rather than of the parser.

| preload | offered | sent | counted | sustained pps | ps_recv | ps_drop | drop/recv | unproc | cores | poll mean ms | poll max ms |
|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 0 | 0 | 0 | 1660 | 55.3 | 1660 | 0 | 0.0000 | 0 | 0.039 | 14.1 | 125.1 |
| 0 | 500 | 14999 | 16626 | 554.2 | 16626 | 0 | 0.0000 | 0 | 0.405 | 15.1 | 51.2 |
| 0 | 1000 | 29999 | 31639 | 1054.6 | 31639 | 0 | 0.0000 | 0 | 0.680 | 20.3 | 42.4 |
| 0 | 2500 | 74999 | 50828 | **1694.1** | 76563 | 16790 | 0.2193 | 8945 | 0.937 | 43.5 | 250.0 |
| 0 | 5000 | 149999 | 50811 | 1693.2 | 151571 | 97134 | 0.6408 | 3626 | 0.933 | 39.1 | 73.8 |
| 0 | 10000 | 299999 | 50366 | 1678.7 | 301481 | 246193 | 0.8166 | 4922 | 0.929 | 41.1 | 74.8 |
| 0 | 20000 | 598211 | 48078 | 1602.4 | 599768 | 546558 | 0.9113 | 5132 | 0.895 | 42.3 | 192.6 |
| 1000 | 0 | 0 | 1485 | 49.5 | 1485 | 0 | 0.0000 | 0 | 0.030 | 75.7 | 400.3 |
| 1000 | 500 | 14999 | 16488 | 549.6 | 16484 | 0 | 0.0000 | −4 | 0.344 | 70.9 | 192.8 |
| 1000 | 1000 | 29999 | 31459 | 1048.5 | 31459 | 0 | 0.0000 | 0 | 0.634 | 86.6 | 343.1 |
| 1000 | 2500 | 74999 | 43049 | **1433.9** | 76439 | 23969 | 0.3136 | 9421 | 0.770 | 97.0 | 197.4 |
| 1000 | 5000 | 149999 | 42200 | 1405.9 | 151451 | 104757 | 0.6917 | 4494 | 0.779 | 99.5 | 182.7 |
| 1000 | 10000 | 299999 | 42382 | 1412.5 | 301347 | 254800 | 0.8455 | 4165 | 0.758 | 119.8 | 350.9 |
| 1000 | 20000 | 599999 | 41842 | 1394.6 | 601413 | 557025 | 0.9262 | 2546 | 0.763 | 103.0 | 202.9 |
| 10000 | 0 | 0 | 872 | 29.0 | 861 | 0 | 0.0000 | −11 | 0.024 | 567.3 | 735.8 |
| 10000 | 500 | 14999 | 7935 | 264.4 | 15838 | **0** | 0.0000 | **7903** | 0.137 | 615.5 | 801.4 |
| 10000 | 1000 | 29999 | 6013 | 199.8 | 30793 | 21931 | 0.7122 | 2849 | 0.115 | 710.1 | 1438.6 |
| 10000 | 2500 | 74999 | 6043 | **201.3** | 75786 | 69120 | 0.9120 | 623 | 0.112 | 657.3 | 1059.2 |
| 10000 | 5000 | 149999 | 4698 | 156.5 | 150765 | 146313 | 0.9705 | −246 | 0.090 | 658.5 | 836.6 |
| 10000 | 10000 | 299999 | 5577 | 185.7 | 300774 | 294097 | 0.9778 | 1100 | 0.110 | 649.1 | 760.6 |
| 10000 | 20000 | 599999 | 5029 | 167.5 | 600576 | 596126 | 0.9926 | −579 | 0.099 | 670.6 | 800.8 |

`counted` slightly exceeds `sent` at low rates because the capture also sees the
poller's own HTTP packets and ambient loopback traffic; the 0 pps rows measure
that background at roughly 55 packets/second. The small negative `unproc` values
are counter-read skew, all under 0.1% of `ps_recv`.

On that path the ceiling was a CPU wall, not a wait: at saturation the capture
thread held 0.93–0.94 of a core, which at 1,694 packets/second is 553
microseconds each. The marginal cost derived from the unsaturated steps, with
the idle baseline subtracted, is about 640 microseconds. One core divided by
that cost is approximately the observed ceiling, which is what identified the
callback thread as the constraint — and what the profile above then attributed
to dissection.

### `ps_drop` under-reports; trust the gap instead

**A saturated capture reported `ps_drop` of zero while barely half the received
packets reached the callback.** At 10,000 retained addresses and only 500
packets/second offered, `ps_recv` was 15,838, `ps_drop` was 0, and 7,935 packets
were counted — the missing 7,903 were sitting in Npcap's kernel buffer, draining
at 264 packets/second. The buffer absorbs several seconds of backlog and reports
nothing wrong until it fills; the consistent 3,000–9,000 `unproc` figure across
the saturated rows matches a roughly 1 MB buffer at about 116 bytes per packet.
The capture requests an 8 MB buffer rather than accepting that default, which
turns bursts into latency rather than loss — and lengthens the backlog that can
accumulate silently before `ps_drop` admits anything, making the gap signal
below more load-bearing, not less.

Anything built on top of these counters must therefore treat **the gap between
`ps_recv` and packets actually counted as the trustworthy loss signal**, not
`ps_drop`. A monitor watching `ps_drop` alone reports perfect health through the
entire period in which the buffer is filling, and only admits a problem once the
capture is already many seconds behind. This compounds the failure described in
[The callback guard is mandatory](#the-callback-guard-is-mandatory-not-defensive-habit):
a capture running seconds behind real time draws every device as though it had
gone quiet, and the drop counter agrees that nothing is wrong.

### Parsing cost versus lock contention

Which of the two binds depends entirely on how many addresses the aggregator has
retained. On the scapy-based path the sweep measured:

- **At a handful of addresses, parsing cost bound outright.** The 1,694
  packets/second ceiling was set by CPU in the callback, and polling cost 14–43
  milliseconds without taking anything off the top.
- **At 1,000 retained addresses, contention was already a 15% tax.** The ceiling
  fell to 1,434 packets/second and poll latency roughly tripled.
- **At 10,000, contention won completely** — an 88% collapse to about 200
  packets/second. The tell is that the capture thread's CPU *fell*, from 0.94
  of a core to 0.10: it was blocked on the lock rather than working. Poll
  latency averaged 660 milliseconds with a 1.44 second peak, so a 2 Hz poll
  demanded about 1.3 seconds of lock time per second and the aggregator was
  effectively locked permanently.

Two things about that are worth stating precisely. **Measuring `snapshot` in
isolation understates the stall by four to five times** — around 100
milliseconds at 1,000 addresses against 19 standalone, and 660 against 178 —
because the GIL and the lock interact once a capture thread is competing for
both, so an isolated snapshot benchmark is not a safe guide to what a poll costs
in production. And the retained-address count at which this matters is low:
degradation is measurable at 1,000 addresses and severe at 10,000.

The lock those rows exercise — `snapshot` against `record` — is untouched by
the parser swap, so the contention cliff stands even though its figures were
measured with the slower callback. What the swap removes is the other
constraint: with the parse at about 40 microseconds per packet, parsing cost no
longer binds at any plausible vehicle rate. Contention is the remaining cliff,
and it opens only if address retention runs away, which is what interface
derivation from the host address exists to prevent.

### The `dpkt` trigger, retired unevaluated

The trigger was fixed before the sweep ran: swapping parsing to `dpkt` was
warranted if, at **twice the observed real-vehicle packet rate**, either
`ps_drop / ps_recv` exceeded 0.001 or the capture thread exceeded about half a
core. It is retired unevaluated. Profiling before swapping the parser — the
sweep measured the whole userspace path without attributing cost within it —
found ~88% of the per-packet cost in scapy's dissection, and the replacement
turned out to be the standard library rather than dpkt: a `struct` unpack reads
the source address in about 2 microseconds, the same figure dpkt manages for
the same field, with no new dependency. There is nothing left for dpkt to
recover.

### How far these numbers transfer

They bound the **userspace ceiling** — driver, kernel filter, frame read,
parse, callback, aggregator — which is the question the measurement exists to
answer. They do not transfer as absolute figures for the tether:

- **Loopback is not Ethernet.** Npcap's loopback device reports **DLT_NULL**: a
  4-byte host-byte-order address-family header in place of an Ethernet header.
  The parser handles both datalinks — DLT_NULL on loopback, DLT_EN10MB on a
  physical adapter — so the framing difference is absorbed at the parse, but a
  physical NIC's driver path, buffer sizing and drop accounting all differ.
- **Packet size differed.** The generator sends 64-byte payloads; ROV video is
  likely closer to 1,400-byte UDP. The parse reads only fixed-offset header
  bytes, so per-packet cost is independent of payload length — and a given
  bitrate at 1,400 bytes is far fewer packets.
- **The buffer figure is this device's.** The backlog figures above were
  measured at Npcap's ~1 MB default on the loopback adapter; the capture
  requests 8 MB, and a physical adapter's accounting may differ regardless.

## Breadcrumbs for macOS and Linux

Recorded so that porting, if it is ever wanted, starts from research rather
than scratch. These are
notes, not stubs — the only code artifact is a platform dispatch that reports
`unsupported_platform`. Both are easier than Windows, because scapy uses native
kernel facilities there and **no driver install is needed**.

- **Linux:** scapy uses `AF_PACKET` natively; needs root or `CAP_NET_RAW`.
- **macOS:** scapy uses BPF via `/dev/bpf*`; needs root, or membership of the
  `access_bpf` group that Wireshark's ChmodBPF helper creates.

## Why the API carries a capture status

Capture can fail for several understandable reasons — Npcap absent, tether
unplugged, permission refused, unsupported OS, or a sniffer that died after
starting — and every one of them is more useful reported than raised. So the
rates API carries a capture status the UI renders as a banner, with the device
rows left readable, and the status is re-read on each poll so a capture that
dies mid-session is reported when it dies rather than at the next restart.
