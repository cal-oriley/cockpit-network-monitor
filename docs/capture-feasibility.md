# Packet Capture Feasibility

> Reference material for the capture layer: why the stack is scapy over Npcap,
> what the kernel filter is and deliberately is not, and the handful of scapy
> behaviours the design has to work around.

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
netmon/capture.py    reads pkt[IP].src, calls RateWindow.record
       |
scapy                Python library, userspace, pip dependency
       |
Npcap                kernel driver, does the actual capturing, one-time installer
       |
network adapter      packets arriving from the 192.168.2.x subnet
```

The `filter` is a BPF expression compiled and applied **in the kernel**, so
Python never sees packets that are not addressed to us. Header offsets and
TCP-versus-UDP visibility are scapy and Npcap's tested territory rather than
something this project has to validate.

The integration is small, but not as small as a lambda:

```python
socket = conf.L2listen(iface=iface, filter=f"ip dst {host_ip}", promisc=False)
sniffer = AsyncSniffer(opened_socket=socket, prn=on_packet, store=False,
                       started_callback=on_started)
sniffer.start()


def on_packet(packet):
    """Must be incapable of raising - see below."""
    try:
        source_ip = str(packet["IP"].src)
    except Exception:
        return
    try:
        window.record(source_ip)
    except Exception:
        return
```

### The callback guard is mandatory, not defensive habit

**An exception raised inside `prn` terminates the entire capture.** Scapy's
sniff loop catches it, closes the socket, drops it from the poll set and exits
the thread — leaving `running` as `False` and, critically, `exception` as
`None`. The failure appears nowhere but a log warning.

That matters far more than it looks, because of how it lands on the page. The
aggregator deliberately scrolls every device's window whether or not it is
sending, so silence renders as a line marching left along the baseline, chosen
to mean "this device went quiet". A dead capture makes **every** device render
exactly that way: a stalled monitor that looks like working software, which is
the one failure this program exists to make visible.

An unguarded `packet[IP].src` is enough to reach it. `packet[IP]` raises on any
non-IPv4 frame, so a single ARP or IPv6 packet slipping past the filter would
end capture permanently.

The same asymmetry rules out trusting `running` as a health signal: it is set
`True` before the socket is opened, so a setup failure leaves it `True` on a
thread that is already dead. Liveness is derived instead from the combination
of `started_callback` having fired, the stored `exception`, and
`thread.is_alive()`, and it is re-derived on every poll rather than resolved
once at startup.

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
against libpcap's `pcap_stats`, reached through the socket. That is why the
socket is constructed by us and handed over as `opened_socket=` rather than
letting `AsyncSniffer` build one from `iface=`. Two consequences follow:
`AsyncSniffer` only auto-closes sockets it created, so this one's cleanup is
ours; and the handle chain (`sock.pcap_fd.pcap`) is private scapy API and the
likeliest thing to break on upgrade, which is the reason scapy is pinned to
`>=2.7.0,<2.8`. The reader is one small function that degrades to "drops
unknown" rather than crashing if that chain ever changes.

## Performance: measure, do not guess

Scapy builds a full structured object per packet, roughly 100–300 microseconds
against dpkt's 2, implying a ceiling somewhere around 3,000–10,000
packets/second. A BlueROV2 pushing video plus telemetry is on the order of
1,000–5,000 packets/second, so this is plausibly fine but genuinely close enough
to warrant checking.

**Ship plain scapy and measure the observed packets-per-second ceiling** rather
than pre-optimizing. The kernel BPF filter already removes the largest chunk of
avoidable work. Dropped-packet counts are read alongside the rate, since a
healthy-looking packet rate beside a rising drop count is precisely the silent
failure to catch.

If the measurement falls short, the contained fix is to keep scapy for capture
and hand parsing to `dpkt`, which touches only `netmon/capture.py`.

## Measured throughput

The numbers observed from the benchmark harness (`tools/`) are recorded here.

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
