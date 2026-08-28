---
name: network monitor UI prototype
overview: "A phased plan for cockpit-network-monitor: a Python web app that graphs per-IP packet rates on a subnet you choose from the page itself, defaulting to 192.168.2.0/24, by passively listening to arriving traffic. Phase 1 builds the complete UI on mock data with no dependencies beyond the standard library; packet capture via scapy over Npcap follows in Phase 2."
todos:
  - id: preflight
    content: "Preflight: create feat/ui-prototype off main, write canonical plan to .cursor/plans/network-monitor-agents.plan.md, fill AGENTS.md, add requirements.txt"
    status: pending
  - id: feasibility-doc
    content: "Preflight: write docs/capture-feasibility.md recording the scapy-over-Npcap decision, why the stdlib raw-socket path was rejected (misses incoming TCP), Npcap licensing, the benchmark to run, and macOS/Linux breadcrumbs for the Phase 2 plan"
    status: pending
  - id: agent-a
    content: "Agent A (doer): RateWindow aggregator, mock traffic source, stdlib HTTP server with /api/rates and capture status, unit tests"
    status: pending
  - id: agent-b
    content: "Agent B (doer): web/ dark-themed UI - stacked per-IP cards, canvas graphs, shared time axis, polling client, capture-status banner"
    status: pending
  - id: subnet-switching
    content: "Subnet switching: server-side filtering behind ?subnet= with validation, in-page subnet control in the header, mock devices on a second subnet so the filter is observable"
    status: pending
  - id: merge-verify
    content: Merge, run pytest, verify /api/rates against the contract, browser-check the UI and capture screenshots
    status: pending
  - id: audit
    content: Launch fresh auditor to review both agents against the plan; surface verdict inline
    status: pending
  - id: wrap
    content: Commit, push feat/ui-prototype, open PR with test plan, hand design iteration back to developer
    status: pending
isProject: false
---

# Cockpit Network Monitor: Project Plan and UI Prototype

## Summary

`cockpit-network-monitor` is a small Python program that runs on the topside computer at `192.168.2.1` and serves a single web page showing, for every device on the watched subnet that sends it a packet, a live 10-second graph of that device's packet rate. The watched subnet defaults to `192.168.2.0/24` and is **changed from the page itself** — the header carries a subnet field, and traffic from source IPs outside the current subnet is filtered out rather than shown. Devices are never discovered or scanned for; a row appears the first time an IP is seen and then stays for the life of the process, so a device going quiet reads as a visible flatline rather than a disappearing row. The page is styled dark and sized to fill an iframe, because it will be embedded into Blue Robotics Cockpit.

The work is split into three phases so the look and feel is settled before any packet-capture code exists. **This plan builds Phase 1 only:** the complete UI plus the rolling-window aggregator behind it, fed by a synthetic traffic generator. Phases 2 and 3 are scoped here for context and will each get their own plan.

## Phases

- **Phase 1 (this plan) - UI prototype on mock data.** The real page, the real HTTP API, and the real aggregator, fed by a fake traffic source. Runs on the dev laptop, verifiable in a browser, no hardware and no elevation needed. We iterate on the design here.
- **Phase 2 (later plan) - real packet capture on Windows.** Replace the mock feeder with a passive scapy listener over Npcap that reads the source IP of each arriving packet and calls `RateWindow.record`. Windows only, needs Administrator plus a one-time Npcap install, and requires in-real-life testing against a real vehicle. The aggregator and the entire UI are untouched by this phase, which is the point of building the seam now. macOS and Linux are researched and documented but deliberately not built.
- **Phase 3 (later plan) - Cockpit integration.** Embedding the page as an iframe panel in Cockpit, and whatever packaging that turns out to need.

## Feasibility of the real capture (researched, not built in this plan)

Investigated up front so Phase 2 is not a leap of faith. The findings below get written to `docs/capture-feasibility.md` during preflight as reference material; **no Phase 1 agent implements any of it.**

### Verdict: feasible, and it adds zero network traffic

The monitor is a **pure listener**. It asks the OS for copies of packets that were already arriving and transmits nothing, so it adds no load to the tether and the ROV cannot tell it is running. It is explicitly **not** in the packet path: Windows technologies that intercept and can drop or alter traffic (WinDivert, the Windows Filtering Platform) are deliberately not used. Promiscuous mode is not needed either, since we only want packets addressed to us, which the NIC already accepts. The real costs are elevation and a one-time driver install.

### Where this actually runs

Blue Robotics' own setup instructions have you assign `192.168.2.1` as a **static IP on the topside computer's Ethernet adapter**, with the ROV at `192.168.2.2`. So this runs on the operator's laptop, not on the vehicle, which is why the host OS matters at all. Per your decision, Phase 2 targets **Windows only**.

### The capture stack: scapy over Npcap

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

The `filter` is a BPF expression compiled and applied **in the kernel**, so Python never sees packets that are not addressed to us. Header offsets, TCP-versus-UDP visibility, and interface selection are scapy and Npcap's tested territory rather than something this project has to validate.

### Why not the standard library (evaluated and rejected)

Worth recording, because "why not just use a raw socket?" is the obvious first question and the answer is non-obvious. Windows exposes `socket.SIO_RCVALL`, which is present in the stdlib (verified here - `AF_PACKET: False`, `SIO_RCVALL: True`), and it appears to work. Scapy implements exactly this technique in `scapy/arch/windows/native.py` as its no-Npcap fallback, and documents what it found:

> Unofficial limitations:
> - Turns out we actually don't see any incoming TCP data, only the outgoing. We do properly see UDP, ICMP, etc. both ways though.
>
> **To overcome those limitations, install Npcap.**

That is disqualifying rather than inconvenient. A device speaking only TCP would never appear as a row, and TCP-heavy devices would be silently undercounted. Because most ROV traffic is UDP (video, MAVLink, sonar), it would have looked like it was working. Two further strikes: `SIO_RCVALL` does no kernel-side filtering, so every packet on the interface crosses into userspace to be discarded in Python, and it is reportedly broken by TCP Offload Engines and can be suppressed by the Windows firewall.

### Npcap: prerequisite, licensing, and detection

Npcap is the packet-capture driver Wireshark installs on Windows; it is the standard answer because Windows has no built-in equivalent. Already present on the development machine (`wpcap.dll` and the `Npcap` system directory both found).

- **Licensing is fine for our usage model** but does constrain packaging. The free version is capped at five systems and forbids redistribution, so we must not bundle the installer. Npcap's license explicitly permits the arrangement we want: *"Software providers (open source or otherwise) which want to use Npcap functionality are welcome to point their users to npcap.com for those users to download and install."* Bundling later would need an OEM redistribution license.
- **Detection is required.** Per your decision, a missing Npcap is reported through `capture.state` as `npcap_missing` with a `detail` pointing at npcap.com, rather than crashing or silently falling back to the broken stdlib path. Phase 2 must also ensure scapy does not quietly substitute its native socket - `conf.use_pcap` should be asserted rather than assumed.

### Performance: measure, do not guess

Scapy builds a full structured object per packet, roughly 100-300 microseconds against dpkt's 2, implying a ceiling somewhere around 3,000-10,000 packets/second. A BlueROV2 pushing video plus telemetry is on the order of 1,000-5,000 packets/second, so this is plausibly fine but genuinely close enough to warrant checking.

Per your decision: **ship plain scapy, then benchmark it in Phase 2 and record the observed packets-per-second ceiling** rather than pre-optimizing. The kernel BPF filter already removes the largest chunk of avoidable work. If the measurement falls short, the contained fix is to keep scapy for capture and hand parsing to `dpkt`, which touches only `netmon/capture.py`. Dropped-packet counts should be read from the capture handle during the benchmark, since silent kernel drops are how this failure mode would otherwise hide.

### Breadcrumbs for macOS and Linux

Recorded so a later phase starts from research rather than scratch. These are notes, not stubs - the only code artifact is a platform dispatch that raises a clear unsupported-platform error. Both are easier than Windows, because scapy uses native kernel facilities there and **no driver install is needed**.

- **Linux:** scapy uses `AF_PACKET` natively; needs root or `CAP_NET_RAW`.
- **macOS:** scapy uses BPF via `/dev/bpf*`; needs root, or membership of the `access_bpf` group that Wireshark's ChmodBPF helper creates.

### Consequence for Phase 1

Capture can fail for several understandable reasons - not elevated, Npcap absent, tether unplugged, unsupported OS - so the API carries a capture status from the start and the UI renders it as a banner. Building that into the prototype means Phase 2 adds a data source and nothing else, with no contract renegotiation. Phase 1 itself stays **zero-dependency**; scapy arrives with Phase 2.

## Technology decisions

- **Web server: Python standard library `http.server.ThreadingHTTPServer`.** Per `external-rules/ponytail.mdc`, stop at the first rung that holds: serving three static files and one JSON endpoint at 2 Hz is squarely covered by the stdlib, so Phase 1 has **zero pip dependencies**. A `ponytail:` comment will name the ceiling (no SSE/WebSocket, no async) and the upgrade path (drop in FastAPI + uvicorn if push updates are ever needed).
- **Packet capture: scapy over Npcap, not hand-rolled.** The same ponytail ladder lands on rung 4 here - use a dependency that already solves it - because the stdlib alternative is not merely more code but silently wrong about incoming TCP. Reasoning and evidence in the Feasibility section above. Phase 2 only.
- **Charting: hand-rolled `<canvas>` drawing, no library.** You asked me to make the ponytail call here. Every row already receives a fixed-length, bucket-aligned array from the server, so plotting is `moveTo`/`lineTo` over ~40 points - roughly 50 lines. A vendored library would be more bytes than the code it replaces and would have to be fought to align independent charts to one shared axis.
- **Transport: browser polls `GET /api/rates` every 500 ms.** The server owns the 10-second window, so the page holds no history of its own. A refresh or a dropped poll therefore loses nothing, and all the logic that can break sits server-side where it is unit-testable.
- **Subnet filtering lives server-side, driven by a query parameter.** The page owns the *choice* of subnet but not the *matching*: it passes the CIDR up as `?subnet=`, and the server validates it with `ipaddress.ip_network` and filters `devices` before serializing. This follows the transport decision above — CIDR containment is exactly the kind of logic that should be unit-testable rather than reimplemented in JavaScript, and `ipaddress` is stdlib, so it costs no dependency and accepts any prefix length rather than only swapping a `/24`'s third octet. The request stays stateless: the subnet is a parameter of the read, never server state, so two browsers can watch different subnets against one process.
- **Y axis: packets per second**, autoscaled per row with the row's peak labeled. Shape matters more than magnitude for spotting dropouts.

## Layout

Per your answer: one subtle card per IP stacked vertically, graph beside the label, with a single time axis shared across all rows. A CSS grid with a fixed-width label column and a flexible graph column keeps every canvas horizontally aligned, and the axis is drawn once at the bottom of the graph column.

The subnet in the header is an editable field rather than static text — it is the control that changes what the page watches.

```
Subnet Traffic  [ 192.168.2.0/24 ]                 4 devices
+----------------------------------------------------------+
| 192.168.2.2        _/\__/\_____/\__                      |
| 42 pps  peak 88   /        \  /    \___                  |
+----------------------------------------------------------+
| 192.168.2.4       ____                                   |
| 0 pps  NO TRAFFIC     \_______________                   |
+----------------------------------------------------------+
                  -10s        -5s              now
```

## Interface contracts

These are the boundaries between the two agents, agreed before either starts.

### Contract 1 - `GET /api/rates` (Agent A serves, Agent B consumes)

Requested as `GET /api/rates?subnet=<cidr>`. The `subnet` parameter is **optional**; omitted, the server uses its default of `192.168.2.0/24`.

```json
{
  "host_ip": "192.168.2.1",
  "subnet": "192.168.2.0/24",
  "capture": { "state": "mock", "detail": "Showing simulated traffic" },
  "bucket_ms": 250,
  "buckets": 40,
  "now_ms": 1787000000000,
  "devices": [
    {
      "ip": "192.168.2.2",
      "pps": [0.0, 4.0, 8.0],
      "current_pps": 8.0,
      "peak_pps": 31.0,
      "total_packets": 4127,
      "idle_ms": 0
    }
  ]
}
```

- `pps` is **always** exactly `buckets` long, oldest first, newest last. Index `i` covers the interval ending `(buckets - 1 - i) * bucket_ms` before `now_ms`. Fixed length and fixed alignment are what make the shared time axis work.
- **Every** device's window advances with wall-clock time, whether or not it is sending. A silent device keeps producing a full-length `pps` that scrolls, filling with zeros from the right, so its trace visibly marches leftward along the baseline and drains its old activity off the left edge. An idle device must never return a frozen array - a stalled graph would read as "the monitor died", which is precisely the opposite of what a dropout should look like.
- `current_pps` is the newest completed bucket; `peak_pps` is the max across the window.
- `idle_ms` is milliseconds since the last packet from that IP. The UI marks a device stale at `idle_ms >= 2000`.
- `devices` is sorted ascending by numeric IP and is stable across polls, so rows never reorder under the cursor.
- `devices` contains **only** IPs inside `subnet`; sources outside it are filtered out server-side and never reach the page.
- `subnet` echoes the effective subnet the payload was filtered to, in normalized CIDR form, so the page renders its header from the response rather than from what the user typed.
- Once seen, a device stays in the list for the process lifetime, reporting zeros — subject to the `subnet` filter, so a device hidden by a subnet change reappears with its history intact when that subnet is selected again. The aggregator keeps every IP it has ever seen; `subnet` only narrows the view.
- Served with `Cache-Control: no-store`.

**Invalid `subnet`** — anything `ipaddress.ip_network` rejects (malformed CIDR, host bits set, empty string) gets **HTTP 400** with `{"error": "<human-readable sentence>"}` and no `devices` key. The page surfaces that sentence next to the subnet field and keeps displaying the last good payload, so a typo mid-edit never blanks the graphs.

**`capture.state`** is one of `ok`, `mock`, `needs_elevation`, `npcap_missing`, `interface_missing`, `unsupported_platform`, or `error`, and `capture.detail` is a human-readable sentence (for `npcap_missing`, one naming npcap.com). The **UI must treat the state list as open**: render `ok` plainly, tag `mock` discreetly, and show any other value as a warning banner using `detail` verbatim rather than switch-casing on known strings. That way Phase 2 can introduce new failure states without touching frontend code - the whole reason this field exists in Phase 1.

### Contract 2 - `RateWindow` (Agent A owns; Phase 2's capture thread will feed it)

```python
class RateWindow:
    def __init__(self, bucket_ms: int = 250, buckets: int = 40,
                 clock: Callable[[], float] = time.monotonic) -> None: ...
    def record(self, ip: str, packets: int = 1) -> None: ...
    def snapshot(self) -> dict: ...  # bucket_ms, buckets, now_ms, devices
```

`snapshot` returns only what the aggregator actually knows: `bucket_ms`, `buckets`, `now_ms`, and `devices`. The server layers `host_ip`, `subnet`, and `capture` on top. That split is deliberate rather than incidental - an aggregator that had to report `capture` would need opinions about Npcap and elevation, and one that had to report `subnet` would need to do the filtering. It reports **every** IP it has ever seen and knows nothing about subnets, which is what lets a device hidden by a subnet change come back with its history intact, and keeps the Phase 2 seam a single `record` call.

Thread-safe behind one `threading.Lock`: `record` is called from the producer thread, `snapshot` from HTTP handler threads. The injectable `clock` is what makes the tests deterministic. This signature is the Phase 1/Phase 2 seam - Phase 2 only replaces who calls `record`. Keeping `record` this narrow is what makes the seam credible: a scapy sniffer callback has nothing to say to the aggregator beyond "this IP sent a packet", which is exactly one line inside `prn`.

### Contract 3 - static files

`netmon/server.py` serves the `web/` directory at `/` with `index.html` as the index. Agent A refers to that path but creates nothing inside it; Agent B owns every file in it.

## Files and ownership

**Agent A - backend (exclusive write):**

- `netmon/__init__.py`
- `netmon/rate_window.py` - the rolling window, Contract 2
- `netmon/mock_source.py` - synthetic traffic generator on a daemon thread
- `netmon/server.py` - `ThreadingHTTPServer`, `/api/rates`, subnet filtering, static serving, argparse CLI
- `tests/` - contract tests for each of the above, plus shared fake-clock fixtures

**Agent B - frontend (exclusive write):**

- `web/index.html`, `web/style.css`, `web/app.js`

**Organizer (preflight and merge):** `.cursor/plans/network-monitor-agents.plan.md`, `docs/capture-feasibility.md`, `AGENTS.md`, `requirements.txt`, `README.md`, `.gitignore`

### Out of scope for both agents

Neither agent writes packet-capture code. No sockets, no scapy, no `netmon/capture.py`, no Npcap detection, no platform detection beyond what the CLI needs. Phase 1 must remain installable and runnable with **nothing but the standard library plus pytest**. `docs/capture-feasibility.md` is **reference material for the Phase 2 plan** and is not an instruction to implement anything; an agent that finds itself importing scapy has misread its scope and should stop and escalate.

## Agent A: backend and aggregator

Owns `netmon/` and `tests/`. Reads the contracts above. Must not create or touch `web/`.

- Implement `RateWindow` per Contract 2: a per-IP ring of `buckets` integer counters, advanced lazily by `clock()` on both `record` and `snapshot` so an idle process does not need a timer thread. Buckets skipped over are zero-filled. Rates are `count / (bucket_ms / 1000)`.
- `snapshot` advances **every** device's ring to the current bucket, not only the ones that recently recorded. This is the load-bearing detail behind the scrolling-while-silent requirement in Contract 1: advancing only inside `record` would freeze an idle device's array at whatever it held when its last packet arrived.
- Implement `mock_source.py`: a daemon thread calling `record` at bucket resolution for five fake devices on `192.168.2.0/24`, deliberately exercising every UI state - a steady ~30 pps telemetry device, a bursty ~200 pps video-ish device with jitter, a quiet ~5 pps device, one that goes silent for 4 s out of every 15 s to demo the dropout visual, and one that first appears about 8 s after startup to demo dynamic row insertion. Additionally generate two devices on a **second** subnet (`10.11.12.0/24`), so switching the subnet in the page visibly changes the rows instead of just emptying the grid - without traffic outside the default subnet the filter cannot be reviewed at all on mock data.
- Implement `server.py`: a `SimpleHTTPRequestHandler` subclass bound to `directory=web/`, intercepting `/api/rates` in `do_GET` and delegating everything else to `super()`. Parse the optional `?subnet=` query parameter, validate it with `ipaddress.ip_network`, filter `devices` to members of that network, and echo the normalized CIDR back as `subnet`; reject invalid input with the HTTP 400 error shape in Contract 1. CLI: `--port` (default 8080), `--host` (default `0.0.0.0`), `--host-ip` (the address reported as `host_ip`, default `192.168.2.1`), `--subnet` (the default subnet used when the page sends none, default `192.168.2.0/24`), `--mock`, and `--capture-status STATE` which forces the reported `capture.state` so the degraded banner can be reviewed in the browser without an unelevated Windows box to hand. Suppress per-request logging to stderr; a 2 Hz poll would otherwise flood the console.
- Unit tests against the contract, not the implementation, with an injected fake clock and no real sleeping: bucket rollover, zero-fill across skipped buckets, correct `pps` array length at every age, rate normalization, window expiry, first-sight insertion of a new IP, `idle_ms` growth, `peak_pps`, stable numeric IP sort (so `.10` sorts after `.9`), and concurrent `record`/`snapshot` under threads. Subnet filtering gets its own tests: only in-subnet devices returned, a non-`/24` prefix honored, the normalized CIDR echoed, an out-of-subnet device reappearing with history when its subnet is selected again, and each invalid-input class producing the 400 error shape. The scrolling-while-silent behavior gets a test of its own: with **no** intervening `record`, consecutive snapshots taken a few buckets apart must return arrays of the same length whose contents have shifted left by exactly that many buckets with zeros appended, and a device silent for longer than the whole window must report all zeros rather than a stale array.

Verify with `pytest` and report the output.

## Agent B: web UI

Owns `web/`. Codes against Contract 1 without waiting for Agent A - hardcode a sample payload in a local constant while developing, then delete it.

- `index.html`: minimal shell - header bar (title, editable subnet field, host IP, device count, connection indicator), a grid container, no external resources of any kind. No CDN, no webfont, no analytics; the vehicle has no internet.
- `style.css`: dark theme to sit naturally inside Cockpit, system font stack, monospace for IPs and numbers. CSS grid `grid-template-columns: var(--label-w) 1fr` so all canvases and the shared axis align. Fills the iframe with no fixed pixel width; scrolls vertically past a handful of devices.
- `app.js`:
  - Poll `/api/rates` every 500 ms, passing the current subnet as `?subnet=`. On failure show a "disconnected" state in the header and keep retrying with backoff to 2 s, without tearing down the existing rows.
  - The header's subnet field is the control for what the page watches: committing a value (Enter or blur, not per-keystroke) makes it the subnet sent on subsequent polls, and the field is seeded from the response's `subnet` on first load. Persist the last committed value in `localStorage` so a reload inside Cockpit's iframe does not send you back to the default. A 400 response shows its `error` sentence beside the field and marks it invalid, while the last good rows stay on screen; recovering from a typo needs no reload. Rows for IPs that leave the current subnet are removed by the same reconciliation that adds new ones - no special-casing.
  - Reconcile rows against `devices` by IP: create rows for new IPs, update in place otherwise. Never rebuild the whole grid on a poll.
  - Draw each row's canvas: filled area plus a 1 px line, y autoscaled to `max(peak_pps, 1)`, `devicePixelRatio` scaling for crispness, redraw on poll and on `ResizeObserver`.
  - Draw the shared axis once at the bottom: ticks at -10 s, -5 s, now, derived from `bucket_ms * buckets` rather than hardcoded.
  - Stale devices (`idle_ms >= 2000`) dim the row and show a "NO TRAFFIC" badge - but keep redrawing on every poll like any other row, so the trace carries on scrolling along the baseline and the device's old activity drains off the left edge. Dimming is a change of styling, never a pause in drawing.
  - Render `capture.state` per Contract 1: nothing for `ok`, a discreet "simulated data" tag for `mock`, and for anything else a warning banner showing `capture.detail` above the rows, with the rows still visible. Do not enumerate the failure states in JavaScript - unknown values must fall through to the banner, since Phase 2 will add states this code will never see.
  - Accessibility: the current rate is real text, not canvas-only, and each canvas carries `role="img"` with an `aria-label` naming the IP and its current rate. The banner is announced with `role="status"`.

## Verification

Automated, run by the organizer after merge:

- `pytest` passes.
- `python -m netmon.server --mock` starts and `curl http://localhost:8080/api/rates` returns a payload matching Contract 1, with `len(pps) == buckets` for every device.
- `curl "http://localhost:8080/api/rates?subnet=10.11.12.0/24"` returns only the second-subnet devices, and `?subnet=nonsense` returns HTTP 400 carrying an `error` sentence.

Browser checks, driven through the browser tools with screenshots attached to the summary:

- Rows appear and lines animate; the late device shows up mid-session.
- The dropout device gains its "NO TRAFFIC" badge and its trace keeps scrolling along the baseline while silent - its earlier activity drains off the left edge rather than the graph freezing - then it recovers.
- All row graphs stay aligned with the shared axis while the window is resized narrow and wide.
- `--capture-status npcap_missing` shows the warning banner with the rows still readable beneath it, and an invented state string also falls through to the banner rather than being ignored.
- Typing `10.11.12.0/24` into the header's subnet field swaps the rows to the second-subnet devices; switching back restores the original rows with their history. A malformed CIDR shows an inline error without blanking the graphs, and the committed subnet survives a page reload.
- The page loads and functions with no third-party packages installed, confirming Phase 1's zero-dependency claim.

Phase 1 needs **no** in-real-life testing - mock data, dev laptop, no elevation, no Npcap. Phase 2 needs all three.

## Notes on process

- **Branch:** the repo is currently on `main` with no feature branch, so I will create `feat/ui-prototype` from an up-to-date `main` and work there.
- **AGENTS.md is still the unfilled template.** I will fill it during preflight with what this plan establishes (Phase 1 stdlib-only, `pytest`, `python -m netmon.server --mock`, the architecture above) and mark IRL testing as required for Phase 2, flagging `netmon/capture.py` as the IRL-facing path and recording Administrator plus Npcap as its preconditions. Before Phase 2 starts I will need the specifics from you: which Windows machine, how the tether is connected, and what a passing observation looks like.
- **Parallel execution:** Agents A and B are independent with no shared files, so they launch in one batch. I will confirm before launching.
- A fresh auditor reviews both agents' work against this plan afterwards, including that neither agent strayed into capture code.