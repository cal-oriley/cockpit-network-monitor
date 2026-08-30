---
name: real packet capture on Windows
overview: "Phase 2 of cockpit-network-monitor: replace the mock traffic generator with a passive scapy-over-Npcap listener that reads the source IP of each packet arriving at the topside address and feeds the existing aggregator. The JSON contract the UI consumes does not change; capture.state stops being a forced CLI value and becomes derived from real conditions, including a capture that dies mid-session. Windows only, verified against a real vehicle by the developer. The phase also carries one independent UI addition: a total-traffic graph summed across the visible devices, which needs no backend work and runs in parallel with the capture stream."
todos:
  - id: total-graph
    content: "Doer U (parallel): total-traffic graph at the top of the stack, summed client-side across the visible devices, sharing the existing grid and time axis"
    status: pending
  - id: capture-module
    content: "Doer 1: netmon/capture.py - CaptureSource lifecycle, non-raising packet callback, interface derivation from host IP, platform dispatch, live state derivation, drop-count reads, plus tests/test_capture.py"
    status: pending
  - id: wire-server
    content: "Doer 2: wire it in - handler queries live capture status instead of a frozen startup value, --iface flag, real source selection in main(), MockSource.status(), update tests/test_server.py"
    status: pending
  - id: benchmark
    content: "Doer 3: benchmark harness - loopback UDP sweep measuring sustained pps, ps_drop/ps_recv and capture-thread CPU; record observed ceiling in docs/capture-feasibility.md"
    status: pending
  - id: docs-deps
    content: "Doer 4: README flags (including the missing --subnet), scapy pin in requirements.txt, correct the stale fixed-/24 reasoning in docs/capture-feasibility.md"
    status: pending
  - id: audit
    content: Launch fresh auditor over the whole phase; verify no IRL test was claimed as passed; surface verdict inline
    status: pending
  - id: irl
    content: "IRL (developer only): real vehicle on the tether - 192.168.2.2 appears, rate tracks video stream, capture.state ok, no dropped packets"
    status: pending
isProject: false
---

# Phase 2: Real Packet Capture on Windows

## Summary

Today the aggregator is fed by `netmon/mock_source.py`, a synthetic generator, and `capture.state` is whatever `--capture-status` was set to. After this phase, `netmon/capture.py` opens a passive Npcap handle on the adapter holding the topside address, reads `packet[IP].src` for every packet arriving at that address, and calls `RateWindow.record(ip)` — so the page shows real devices on the real tether. `capture.state` becomes derived from observable conditions (missing Npcap, missing interface, permission failure, unsupported platform, a sniffer that died) rather than asserted, and the handler re-reads it per request so a capture that dies at minute nine is reported at minute nine.

The capture work changes nothing about the page. Contract 1's JSON shape is unchanged, `RateWindow.record` is unchanged, and the frontend needs no edit on account of capture because it already treats the capture-state list as open. What does change, unavoidably, is `netmon/server.py`'s internal wiring — see [The server rewire is not optional](#the-server-rewire-is-not-optional).

Riding along beside that is one **unrelated UI addition**: a total-traffic graph at the top of the stack, summing the visible devices. It shares no files with the capture work and needs no backend change, so it is the phase's one genuinely parallel workstream — see [The total-traffic graph](#the-total-traffic-graph).

The monitor remains a **pure listener**: it transmits nothing, adds no load to the tether, and is not in the packet path. Promiscuous mode is not used. The costs are a one-time Npcap install (already present on the target machine) and a pip dependency on scapy, which ends Phase 1's zero-dependency runtime.

## Grounding: this plan supersedes parts of the earlier research

`docs/capture-feasibility.md` recorded the decision to use scapy over Npcap, and that decision stands — it is not revisited here. But that document was written before the UI existed and before the subnet became page-selectable, and four of its claims do not survive contact with the code as built and with scapy 2.7.0 as installed. They are corrected here because each one changes what gets implemented. Correcting the document itself is a task in this plan.

### 1. The "five lines" integration is wrong, and wrong silently

The feasibility document presents the whole capture layer as:

```python
AsyncSniffer(filter="ip dst 192.168.2.1", prn=lambda p: window.record(p[IP].src),
             store=False).start()
```

**An exception raised inside `prn` terminates the entire capture.** Scapy's sniff loop catches it, closes the socket, drops it from the poll set, and exits the thread — leaving `running` as `False` and, critically, `exception` as `None`. The failure appears nowhere but a log warning.

This is the single most important finding in the phase, because of how it interacts with a Phase 1 design choice. The aggregator deliberately scrolls every device's window whether or not it is sending, so silence renders as a line marching left along the baseline. That visual was chosen to mean "this device went quiet". A dead capture makes **every** device render exactly that way. The one failure mode Phase 1 set out to make impossible — a stalled monitor that looks like working software — is reachable, and reachable quietly.

The literal lambda is unsafe on its own terms too: `p[IP]` raises `IndexError` on any non-IPv4 frame, so a single ARP or IPv6 packet that slips past the filter kills capture permanently.

**Consequence:** the packet callback must be incapable of raising, and liveness must be polled rather than assumed. Both are requirements below, not suggestions.

### 2. `running` is not a liveness signal

`AsyncSniffer.start()` never raises, and `running` is set `True` before the socket is opened, so a setup failure (bad interface, bad filter, permission denied) leaves `running == True` on a thread that is already dead. The three states must be distinguished by combination:

| Condition | `running` | `exception` | `thread.is_alive()` |
|---|---|---|---|
| Healthy | True | None | True |
| Setup failed | **True** | set | False |
| Died mid-run (callback raised) | False | **None** | False |

`started_callback=` fires only once every socket has opened successfully, which makes it the reliable "startup succeeded" signal. This truth table is counterintuitive enough that the state-derivation function is the highest-value unit test in the phase.

### 3. Administrator is not unconditionally required

Whether elevation is needed is a property of **how Npcap was installed**, not of Windows. On the target machine Npcap has `AdminOnly=0`, and an unelevated passive capture on the tether adapter opened, filtered, ran, and stopped cleanly. Gating on `IsUserAnAdmin()` up front would report `needs_elevation` on a machine where capture works perfectly.

**Consequence:** never predict a permission failure. Attempt the capture, and use elevation state only to *explain* a failure that actually occurred.

### 4. Promiscuous mode must be turned off explicitly

The feasibility document correctly says promiscuous mode is not needed, but `conf.sniff_promisc` defaults to `True` and the socket falls back to it. Left implicit, this phase would put the adapter into promiscuous mode and contradict its own design. `promisc=False` is passed explicitly.

## The BPF filter, and why the subnet stays out of it

The filter is:

```
ip dst <host_ip>
```

and it deliberately carries **no subnet term**. This needs stating explicitly, because tightening it to something like `src net 192.168.2.0/24 and ip dst 192.168.2.1` looks like an obvious improvement and would silently break the subnet control.

Subnet selection is a **parameter of the read**, resolved per request in the handler, and two browsers may watch different subnets against one process. The capture layer therefore cannot know which subnet will be asked for; a capture-time source filter would have to be the union of every subnet any client might ever type, which collapses to no filter at all. Worse, anything the filter excludes can never be recovered by a later read — the aggregator retains history precisely so that switching subnets is non-destructive, and a capture-time subnet filter would defeat that.

A unit test asserts the constructed filter contains no subnet, as a regression guard against exactly this well-meaning "fix".

**What `ip dst <host_ip>` excludes, deliberately:** broadcast, multicast, and ARP, since `dst` must equal the host address exactly. A device that only ever broadcasts, or only ARPs, will never appear as a row. This is almost certainly right — the page is about per-device rates, not discovery — but it is an assumption about real ROV traffic that only the vehicle can confirm, so it is called out in the IRL procedure.

## Interface selection: derived, not configured

`conf.iface` defaults to whichever adapter scapy considers primary, which on a laptop is the Wi-Fi card. Sniffing it would capture the house LAN instead of the tether — wrong data, presented as plausible rows.

The interface is therefore derived from `--host-ip` by scanning scapy's interface table for the adapter carrying that IPv4 address, which is exactly the static `192.168.2.1` Blue Robotics has you set on the Ethernet port. Verified working on the target machine, resolving to the USB Ethernet adapter's `\Device\NPF_{GUID}`.

No adapter carrying the address is precisely the `interface_missing` condition — the tether is unplugged or the static IP is not set — so this is real detection rather than a guess. `--iface` exists as an override for the awkward case (two adapters sharing an address) but is never needed normally.

This also promotes `--host-ip` from cosmetic to load-bearing: it is the filter's destination, the interface selector, and the reported `host_ip`. One flag for all three is correct, because capturing on the adapter that holds the address you filter for is the only coherent combination, and a second flag would let them disagree.

## The server rewire is not optional

The Phase 1 plan claimed Phase 2 "adds a data source and nothing else, with no contract renegotiation". The JSON contract half is true. The wiring half is not.

`server.py` currently resolves capture status **once at startup** into a frozen dataclass and binds that value into every handler. There is no path by which a capture that dies later can change what `/api/rates` reports. Combined with finding 1, that means a dead sniffer would be reported as healthy forever.

The fix is small but it is a real edit to a Phase 1 file: the handler holds a **callable returning `CaptureStatus`** rather than an instance, and calls it per request. `MockSource` gains a `status()` returning the `mock` state so both sources satisfy the same shape. `--mock` and `--capture-status` keep working unchanged.

Two further wiring mismatches must be absorbed by the new module rather than left for `main()`:

- **`stop()` semantics differ incompatibly.** `MockSource.stop()` is a documented no-op when not started; `AsyncSniffer.stop()` *raises* if it is not running. Since the sniffer can die on its own, `server.py`'s unconditional `finally: source.stop()` would turn a clean `Ctrl+C` into a traceback. `CaptureSource.stop()` must never raise.
- **There is no shared source type.** `main()` currently decides between `MockSource` and `None`. It will now decide between two real sources, against the common lifecycle in the contract below.

## Interface contracts

The boundary between the capture module and the server, agreed before either task starts.

### Contract A — `CaptureSource` (Doer 1 owns; Doer 2 consumes)

```python
# netmon/capture.py

class CaptureSource:
    """Passive scapy/Npcap listener feeding RateWindow.record."""

    def __init__(self, window: RateWindow, host_ip: str,
                 iface: str | None = None) -> None: ...
    def start(self) -> None: ...                      # never raises; failure becomes state
    def stop(self, timeout: float = 2.0) -> None: ... # never raises; safe if never started
    @property
    def running(self) -> bool: ...
    def status(self) -> CaptureStatus: ...            # live, re-derived on every call


def filter_for(host_ip: str) -> str: ...              # "ip dst <host_ip>"; never a subnet
def select_interface(host_ip: str) -> str | None: ... # NPF network_name, or None
```

**`CaptureStatus` moves into `netmon/capture.py`**, and `server.py` imports it from there. It is currently declared in `server.py`, but the dependency has to run **server → capture**, not the reverse: `server.py` constructs the source, so a capture module importing back from the server would be circular. Moving the dataclass rather than redeclaring it keeps one definition, so the JSON shape provably cannot drift. Doer 1 defines it; Doer 2 deletes the old declaration and repoints the import in the same task that wires the source in.

**scapy is imported lazily, inside the functions that need it — never at module scope.** Importing `netmon.capture` must not require scapy, for three reasons that all matter: `--mock` has to keep working on a machine without scapy installed, the pure-logic tests (state derivation, platform dispatch, filter construction) must run without it, and `import scapy.all` costs seconds of arch initialization against a suite that currently runs in about nine. Platform dispatch and `CaptureStatus` therefore stay importable on any OS, and an unsupported platform reports `unsupported_platform` rather than failing at import.

`start()` and `stop()` mirror `MockSource`'s lifecycle exactly so `main()` can treat the two interchangeably. Neither raises: a failure to open, a bad filter, a missing interface, or a dead thread all surface through `status()`.

### Contract B — live capture status (Doer 2 owns)

The handler holds `Callable[[], CaptureStatus]` instead of a frozen `CaptureStatus`, and calls it while building each response. Both sources satisfy it: `CaptureSource.status` and `MockSource.status`. Forced states via `--capture-status` are supplied as a constant callable.

### Contract C — Contract 1 (the JSON API) is unchanged

No field is added, renamed, or removed. `capture.state` gains **new values** — at minimum one for a capture that died after starting — and that needs no frontend work whatsoever: the UI names only `ok` and `mock` and lets every other value fall through to its warning banner using `detail` verbatim. This is the payoff for building that field in Phase 1.

One caveat the new states must respect: a **missing** `capture` object is rendered as `ok`, so the key must always be emitted.

## Capture state derivation

`capture.state` values and what actually produces each:

| State | Real condition |
|---|---|
| `ok` | Sniffer started, thread alive, no stored exception |
| `mock` | `--mock`; produced by `MockSource.status()` |
| `unsupported_platform` | `sys.platform` is not Windows — the only platform this phase builds |
| `npcap_missing` | scapy cannot load `wpcap.dll`; `detail` names npcap.com |
| `interface_missing` | No adapter carries `--host-ip` |
| `needs_elevation` | A permission failure actually occurred on open — never predicted from an is-admin check |
| `error` | Any other stored sniffer exception; `detail` carries its message |
| `capture_died` | Started successfully, then the thread exited (see finding 1) |
| `not_running` | `status()` called before `start()` or after `stop()` |
| `dropping_packets` | Capture is running, but the kernel is discarding packets faster than a set tolerance |

**`dropping_packets` is why drop counts are read in production at all.** Appending them to `ok`'s detail is not enough: the page renders the banner only when the state is neither `ok` nor `mock`, so drops reported inside `ok` reach the JSON and are shown to nobody. Since silent kernel drops are the failure mode this whole phase exists to make visible, the condition needs its own state — which then surfaces through the existing banner with **no frontend change**, exactly the payoff the open state set was built for.

**Do not base it on `ps_drop` alone — measurement proved that misses the case.** In the sweep, a saturated capture read `ps_drop` of **zero** while only half the received packets had reached the callback: the rest were sitting in Npcap's kernel buffer, which absorbs several seconds of backlog and reports nothing wrong until it fills. The honest signal is the gap between `ps_recv` and what we actually counted, so the condition is evaluated on **received minus counted**, with `ps_drop` as corroboration rather than as the trigger.

Report it above a **ratio** rather than on any non-zero count, using the same 0.001 of received packets as the `dpkt` trigger below, so a brief blip while the capture warms up does not nag an operator forever while a sustained loss does. The `detail` sentence carries the actual received and dropped counts, since "some packets were dropped" is not actionable but "1,240 of 900,000" is. A device's rates are **undercounted** while this is true, which is the operator-facing consequence worth stating in the sentence.

`not_running` exists because `status()` is callable outside the sniffer's lifetime, and reporting that as `capture_died` would be a lie. Both are values the frontend has never seen and needs no change to render — but both must appear in the server's forced-state detail table so `--capture-status capture_died` reviews sensibly in a browser.

Forcing pcap deserves its own note: `conf.use_pcap` must be **asserted after importing `scapy.all`**, not set before. Read from `scapy.config` alone it reports `False` because the arch layer has not initialized, so an assertion in the wrong place fails spuriously. Assert both `conf.use_pcap` and that `conf.L2listen` is the pcap listen socket, since the former does not prove the latter — this is what stops scapy silently substituting its native socket, the one that cannot see incoming TCP.

## Dropped packets are a production signal, not just a benchmark reading

Silent kernel drops are how this whole failure mode would otherwise hide, so drop counts are read in normal operation rather than only during the benchmark.

Scapy 2.7.0 exposes no `stats()` wrapper, so this needs a small ctypes call against libpcap's `pcap_stats`, reached through the socket scapy created. That requires constructing the socket ourselves and passing `opened_socket=`, rather than letting `AsyncSniffer` build one from `iface=`. Verified working: `ps_recv` tracked the observed packet count exactly.

Using `opened_socket=` in production keeps the benchmark and the real path identical instead of measuring something we do not ship. Two consequences to handle: `AsyncSniffer` only auto-closes sockets it created, so ownership and cleanup are ours; and the handle chain is **private scapy API**, the most likely thing to break on upgrade. It gets wrapped in one small function with a `ponytail:` comment naming that ceiling, degrading to "drops unknown" rather than crashing if the attribute chain ever changes.

## The total-traffic graph

A single card at the **top** of the stack showing combined traffic across every device currently displayed, so overall load is readable at a glance instead of being mentally summed across rows.

**Computed client-side, with no contract change.** Each device already arrives with a fixed-length, bucket-aligned `pps` array, so the total is an element-wise sum across devices at each index — every array covers the same intervals, which is exactly what that fixed alignment was for. Requiring nothing from the server is why this can proceed while the capture work is in flight, and it is also the correct semantics: the sum is over the devices the payload actually contains, so it automatically reflects the current subnet rather than quietly including filtered-out traffic.

- **Placement and alignment:** the first card in the grid, using the same `grid-template-columns` as the device rows so its canvas lines up with theirs and with the shared time axis. It must not require a second axis.
- **Visually distinct, not device-like.** Label it as an aggregate (e.g. "All devices") rather than anything resembling an IP, and give it enough weight — accent colour, heavier line — that it does not read as just another device. It is not a row that can be confused for a device that exists.
- **Autoscaled to its own peak**, like every other row, since its magnitude is by definition larger than any single device's. The peak label is the peak of the summed series, not the largest device peak.
- **Current rate as real text**, same as device rows, plus `role="img"` and an `aria-label` naming it as the combined rate. Accessibility parity, not an afterthought.
- **Device count stays a device count** — the total card is not counted as a device in the header.
- **No stale badge.** `idle_ms` is per-device and has no meaningful aggregate; if everything goes quiet the summed trace flatlines along the baseline, which says it already. Like every row, it keeps redrawing while flat rather than freezing.
- **Empty device list:** no total card. Summing nothing is not zero traffic, it is no data, and the page already has a waiting state for that.
- **Unequal or unexpected array lengths** must not throw. The contract guarantees every `pps` is exactly `buckets` long; the sum should be built defensively against a short or missing array rather than trusting it, consistent with how the rest of `app.js` handles the payload.

Reuse the existing canvas drawing and reconciliation paths rather than adding a parallel implementation — this is one more row fed by a derived series, not a second charting mechanism.

## Files and ownership

**Doer 1 — capture module (exclusive write):**

- `netmon/capture.py`
- `tests/test_capture.py`

**Doer 2 — wiring (exclusive write, after Doer 1):**

- `netmon/server.py`
- `netmon/mock_source.py` (additive: `status()` only)
- `tests/test_server.py`, `tests/test_mock_source.py`

**Doer 3 — benchmark (exclusive write):**

- `tools/benchmark_capture.py` (new)
- The results section of `docs/capture-feasibility.md`

**Doer 4 — docs and dependencies (exclusive write):**

- `README.md`, `requirements.txt`
- The prose corrections in `docs/capture-feasibility.md`

`README.md` also needs a line for the **total-traffic graph** from task U: its overview currently describes the page as a graph per device, with no mention of the combined trace at the top of the stack.

`README.md` gets a specific instruction here, to run **last, once capture actually works**: strip every mention of the phases. The phase scaffolding existed to explain why a UI shipped with no packet capture behind it; once capture lands, a reader arriving at the project does not care that it was built in stages, and "Phase 2" reads as an unfinished promise rather than history. The README should describe the tool as it is — install, run, what the page shows, the flags — with no phase language anywhere. Phase history stays in git and in the plans, which is where the development path belongs.

**Doer U — total-traffic graph (exclusive write, parallel with the capture work):**

- `web/index.html`, `web/style.css`, `web/app.js`

This is the only task that touches `web/`, and no capture task touches it at all, so the two streams cannot collide. It must not start until the in-flight subnet-control work on those same files has landed.

**Organizer:** this plan file, `AGENTS.md`.

`docs/capture-feasibility.md` is touched by both Doer 3 and Doer 4, so it is **split in time rather than ordered by task**: Doer 4 owns the whole document during its run, including creating an empty results section. Doer 3 does **not** touch it at all while running — it owns `tools/` alone and reports its measured numbers back — and is then resumed to append those numbers once Doer 4 has finished. That lets the benchmark's several minutes of traffic sweeps overlap with the docs work instead of queueing behind it, at the cost of one extra hand-off.

### Out of scope

- macOS and Linux. The only artifact is a platform dispatch that reports `unsupported_platform`; the breadcrumbs in the feasibility document stay research.
- Cockpit iframe integration — that is Phase 3.
- Any change to the page **beyond the total-traffic graph**. No capture task touches `web/`; if a capture doer believes a frontend change is required, that is a contract problem — stop and escalate. Equally, Doer U touches no backend file and introduces no new payload field.
- Multi-interface capture. `AsyncSniffer` accepts a list of interfaces, so it is nearly free, but nobody has asked for it.
- Replacing scapy's parsing with `dpkt`. That is the documented fallback if and only if the benchmark says so — see the trigger below.

## Task sequence

Sequential, not parallel, and deliberately so: extraction, state derivation, interface selection, platform dispatch and lifecycle are one coherent module whose parts consume each other, and the server rewire is a *dependency* of the capture module rather than a peer. Splitting them would manufacture interface contracts between functions that belong in one file.

| # | Task | Owns | IRL | Depends on |
|---|---|---|---|---|
| U | Total-traffic graph | `web/` | no | in-flight subnet-control work landing |
| 1 | Capture module + its tests | `netmon/capture.py`, `tests/test_capture.py` | no | — |
| 2 | Wire it in: live status, `--iface`, source selection | `netmon/server.py`, `netmon/mock_source.py`, server/mock tests | no | 1 |
| 3 | Benchmark harness + recorded results | `tools/`, results section of the feasibility doc | partly | 2, 4 |
| 4 | Docs and dependency pin | `README.md`, `requirements.txt`, feasibility doc prose | no | 2 |
| 5 | Auditor pass over the whole phase | — | flags only | 1–4 |
| 6 | **IRL: real vehicle** | — | **yes** | 5 |

**Task U is the exception** and runs concurrently with task 1 from the start: it owns `web/` exclusively, no capture task reads or writes it, and it needs nothing from the backend. Within the capture stream itself, concurrency is limited to tasks **3** and **4** once **2** lands, and even that is ordered by the shared document: **4 first** (it creates the results section), then **3** appends to it. Tasks 1 and 2 cannot overlap.

Task 1 touches `netmon/capture.py`, which `AGENTS.md` flags as IRL-facing, so its doer carries the obligation to surface that IRL testing is required even though the task itself is agent-testable.

## Testing strategy

The trust boundary is **the packet object arriving from scapy**. Everything on our side of it is pure logic and gets tested with no hardware and no Npcap.

Testable directly:

- **Packet-to-IP extraction**, using packets built in-process. The assertions that matter are the error paths: ARP, IPv6, and truncated frames must not raise and must not stop recording.
- **State derivation** — a pure function from observable conditions to a `CaptureStatus`, table-driven. Highest-value test in the phase, because the truth table above is counterintuitive.
- **Platform dispatch** — `sys.platform` patched; assert `unsupported_platform` off Windows.
- **Interface selection** — against a fake interface table: match, no match (`interface_missing`), and two adapters sharing an address.
- **Filter construction** — `filter_for(host_ip) == "ip dst <host_ip>"`, including the no-subnet regression guard.

**Injection seam:** `CaptureSource` takes a sniffer factory, defaulting to `AsyncSniffer`. Tests pass a fake exposing `start`/`stop`/`running`/`exception`/`thread`, which drives every row of the truth table — including silent mid-run death — with no Npcap present.

Additionally, the callback-robustness tests run against scapy's **real** dispatch loop using offline packets, so that a future scapy release which changes whether a raising callback is fatal fails loudly here rather than in the field.

Two acceptance criteria for the suite itself: `pytest` must pass on a machine **without** Npcap (scapy imports fine there; `conf.use_pcap` merely goes `False`), and scapy imports stay confined to the modules that need them, since importing `scapy.all` costs seconds against a suite that currently runs in about nine.

Irreducibly IRL, and never claimed as passed by an agent: that real ROV traffic is seen and attributed correctly; that it is unicast to the host rather than broadcast or multicast; real `ps_drop` under real load; and `needs_elevation`, which is unreachable on this machine because Npcap was installed without the admin-only restriction.

## Benchmark

Three numbers together, because any one alone misleads — a healthy-looking packet rate beside a rising drop count is precisely the silent failure to catch: **sustained packets/second through the callback**, **`ps_drop` / `ps_recv`** sampled periodically rather than once at the end, and **capture-thread CPU**.

Most of it needs no vehicle. A separate-process UDP blaster against the loopback adapter drives offered load across roughly 500 / 1,000 / 2,500 / 5,000 / 10,000 / 20,000 pps, thirty seconds per step, recording all three numbers plus the generator's own send count as ground truth. This exercises the whole real stack — Npcap driver, kernel BPF filter, scapy dissection, our callback, `RateWindow.record` — and will surface a callback that is accidentally O(n). Two caveats to record with the results: loopback packet sizes and datalink differ from real Ethernet, and drop accounting may differ from a physical NIC, so absolute numbers do not transfer. It bounds the userspace ceiling, which is the question.

Worth running in the same pass, and cheap: repeat the sweep with the aggregator pre-loaded to 1,000 and 10,000 retained addresses while a 2 Hz poller hits `/api/rates`, since `snapshot()` holds the same lock the capture callback needs.

**Measured, and both estimates it replaces were optimistic.** The capture path sustains **~1,700 packets/second** at ~0.94 of a core, or roughly 550–640 µs of CPU per packet — two to six times the 100–300 µs assumed above, and the reason the ceiling sits where it does. Snapshot stalls came in **four to five times** the earlier standalone estimates once a live capture was competing for the GIL: ~100 ms mean at 1,000 retained addresses against 19 ms estimated, and ~660 ms against 178 ms at 10,000. Retention costs throughput far earlier than the "around 14,000 addresses" figure suggested — a **15% tax at 1,000** addresses and an **88% collapse at 10,000**, where the capture thread's CPU *falls* to 0.10 cores because it is blocked rather than working.

So both effects are real and which dominates depends on retention: at the handful of devices a tether actually carries, **scapy's parsing cost binds** and `dpkt` addresses the right thing; lock contention is a separate, steeper cliff that only opens if address retention runs away.

One caveat that bears directly on the `dpkt` decision: the sweep measures the whole userspace path without attributing cost *within* it. If dissection really is 100–300 µs, something else — scapy's per-packet socket and select loop, or loopback datalink handling — accounts for the rest, and `dpkt` replaces dissection only. **Profile before swapping the parser**, or the fallback may recover much less than the gap implies.

**The `dpkt` trigger, stated before measuring** so the number cannot be rationalized afterwards: swapping parsing to `dpkt` is warranted if, at **twice the observed real-vehicle packet rate**, either `ps_drop / ps_recv` exceeds 0.001 or the capture thread exceeds about half a core. Below that, scapy has adequate headroom and the change is unjustified work. `dpkt` is not currently installed, so this is a real new dependency, not a latent one.

## Accepted trade-offs and risks

**Unbounded address retention — accepted, on the developer's explicit decision.** Every distinct source IP becomes a permanent row, and the packet source address is untrusted input at a trust boundary. When the subnet was a fixed `/24` this was bounded at 254 addresses by construction; page-selectable subnets removed that ceiling and this phase does not replace it. Memory is genuinely a non-issue at roughly 0.65 KB per address, but `snapshot()` holds the lock `record` needs, so at around 14,000 retained addresses a poll stalls the sniffer for longer than a whole bucket and the monitor starts dropping the packets it exists to count. The realistic path there is capturing on the wrong adapter, which interface derivation from `--host-ip` is specifically designed to prevent; the other is deliberate source-address spoofing on a shared network, which an isolated tether makes moot. Revisit only if it bites.

Other risks, worst first:

1. **Silent capture death** — mitigated by the non-raising callback, liveness polling, and a dedicated state, all required above. This is the one that could ship and be believed.
2. **Wrong-interface capture** — mitigated by derivation from `--host-ip` and by `interface_missing` being a real detection.
3. **Startup errors not surfacing** — mitigated by `started_callback` plus the truth table; easy to get wrong, easy to test once known.
4. **Broadcast/multicast/ARP invisibility** — believed correct, unconfirmed against real traffic; in the IRL procedure.
5. **Private-API dependence** for drop counts — contained to one wrapper that degrades to "unknown", and the reason for pinning scapy to `>=2.7.0,<2.8`.
6. **Python 3.14.2 with scapy 2.7.0** is a new combination with little field exposure. Verified working here for open, filter, run, and stop.

## Verification

Agent-runnable, by the organizer after each task:

- `pytest` passes, including on a machine without Npcap.
- `python -m netmon.server --mock` still behaves exactly as it does today: five devices on `192.168.2.0/24`, two on `10.11.12.0/24`, `capture.state` of `mock`, subnet switching and its 400s unaffected.
- `python -m netmon.server` without `--mock`, with the tether connected and the vehicle absent, reports `ok` with zero devices — not a crash and not a false failure state. **No adapter currently holds `192.168.2.1`**, so until the static address is restored this run correctly reports `interface_missing` instead; the `ok` path is confirmed against an address the machine does hold.
- With the tether **unplugged**, it reports `interface_missing` and the page shows the warning banner with `detail` naming what to check.
- `--capture-status` still forces a state for banner review, including `capture_died`.
- A deliberately broken callback (test-only, via the injected fake) produces `capture_died` rather than a silently frozen page.
- Use `--port 8765` or similar: `8080` is held by an unrelated `ApplicationWebServer` process on this machine.

For the total-traffic graph specifically, in the browser against `--mock`:

- The total card sits at the top, its canvas aligned with the device canvases and the shared axis at both narrow and wide widths.
- Its trace is the element-wise sum: with the mock's bursty ~200 pps device dominating, the total's shape tracks it while sitting visibly higher than any single row, and its peak label exceeds every device peak.
- Switching the subnet to `10.11.12.0/24` re-sums over just those two devices, so the total drops accordingly rather than continuing to include filtered-out traffic.
- The header's device count is unchanged by the total card's presence.
- With the dropout device silent, the total dips but keeps scrolling; when every device is quiet the total flatlines along the baseline and keeps advancing rather than freezing.

## IRL testing — developer only

Facts are recorded in `AGENTS.md`; agents produce this procedure and **never** claim it passed.

1. Set the laptop's Ethernet adapter to static `192.168.2.1`, connect the tether, power the vehicle, confirm the adapter reports a connected link.
2. Run `python -m netmon.server --port 8765` and open the page. Elevate only if a permission failure is reported.
3. **Pass looks like:** `192.168.2.2` appears as a row within a couple of seconds, its rate visibly tracks real activity such as starting the video stream, `capture.state` reads `ok`, and no dropped packets are reported.
4. While there, confirm the two open assumptions: that expected devices all appear (nothing is invisible through being broadcast-only or ARP-only), and note the observed packet rate so the benchmark's `dpkt` trigger has a real number to double.

---

*Phase 1 (UI prototype on mock data) is `.cursor/plans/network-monitor-agents.plan.md`. Phase 3 is Cockpit iframe integration and will get its own plan.*
