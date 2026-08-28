# Packet Capture Feasibility (Phase 2 Research)

> **Reference material for the Phase 2 plan. This is not an instruction to
> implement anything in Phase 1.** Phase 1 is the UI plus the rolling-window
> aggregator on mock data, standard library only. Nothing described here is
> built yet, and an agent that finds itself importing scapy while working on
> Phase 1 has misread its scope.

This document records the research behind the Phase 2 capture design so that
phase starts from evidence rather than a leap of faith.

## Verdict: feasible, and it adds zero network traffic

The monitor is a **pure listener**. It asks the OS for copies of packets that
were already arriving and transmits nothing, so it adds no load to the tether
and the ROV cannot tell it is running.

It is explicitly **not** in the packet path. Windows technologies that
intercept traffic and can therefore drop or alter it — WinDivert, the Windows
Filtering Platform — are deliberately not used. Promiscuous mode is not needed
either: we only want packets addressed to us, which the NIC already accepts.

The real costs are elevation and a one-time driver install.

## Where this runs

Blue Robotics' own setup instructions have the operator assign `192.168.2.1` as
a **static IP on the topside computer's Ethernet adapter**, with the ROV at
`192.168.2.2`. So this runs on the operator's laptop, not on the vehicle, which
is why the host OS matters at all. Phase 2 targets **Windows only**.

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

The whole integration is about five lines:

```python
AsyncSniffer(filter="ip dst 192.168.2.1", prn=lambda p: window.record(p[IP].src),
             store=False).start()
```

The `filter` is a BPF expression compiled and applied **in the kernel**, so
Python never sees packets that are not addressed to us. Header offsets,
TCP-versus-UDP visibility, and interface selection are scapy and Npcap's tested
territory rather than something this project has to validate.

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

Bundling later would require an OEM redistribution licence.

### Detection

Detection is **required**. A missing Npcap is reported through `capture.state`
as `npcap_missing`, with a `detail` naming npcap.com, rather than crashing or
silently falling back to the broken stdlib path. Phase 2 must also ensure scapy
does not quietly substitute its native socket: `conf.use_pcap` is **asserted,
not assumed**.

## Performance: measure, do not guess

Scapy builds a full structured object per packet, roughly 100–300 microseconds
against dpkt's 2, implying a ceiling somewhere around 3,000–10,000
packets/second. A BlueROV2 pushing video plus telemetry is on the order of
1,000–5,000 packets/second, so this is plausibly fine but genuinely close enough
to warrant checking.

**Ship plain scapy, then benchmark it in Phase 2 and record the observed
packets-per-second ceiling** rather than pre-optimizing. The kernel BPF filter
already removes the largest chunk of avoidable work. Dropped-packet counts must
be read from the capture handle during the benchmark, since silent kernel drops
are how this failure mode would otherwise hide.

If the measurement falls short, the contained fix is to keep scapy for capture
and hand parsing to `dpkt`, which touches only `netmon/capture.py`.

## Breadcrumbs for macOS and Linux

Recorded so a later phase starts from research rather than scratch. These are
notes, not stubs — the only code artifact is a platform dispatch that raises a
clear unsupported-platform error. Both are easier than Windows, because scapy
uses native kernel facilities there and **no driver install is needed**.

- **Linux:** scapy uses `AF_PACKET` natively; needs root or `CAP_NET_RAW`.
- **macOS:** scapy uses BPF via `/dev/bpf*`; needs root, or membership of the
  `access_bpf` group that Wireshark's ChmodBPF helper creates.

## Consequence for Phase 1

Capture can fail for several understandable reasons — not elevated, Npcap
absent, tether unplugged, unsupported OS — so the API carries a capture status
from the start and the UI renders it as a banner. Building that into the
prototype means Phase 2 adds a data source and nothing else, with no contract
renegotiation. Phase 1 itself stays **zero-dependency**; scapy arrives with
Phase 2.
