---
name: record traffic to CSV
overview: "Adds a record button to the page that appends every datapoint, with timestamps, to a CSV on the machine running the monitor, and makes the whole page fluid so it survives being crammed into a small iframe. Recording is server-side so it outlives the page being closed or reloaded, is fixed to the subnet selected when it started, writes a fresh file each time it is started, and stops when the program exits."
todos:
  - id: recorder-backend
    content: "Doer A: netmon/recorder.py CSV writer on a bucket-resolution thread, POST /api/record start/stop, recording status in the payload, --recordings-dir flag, tests"
    status: pending
  - id: recorder-ui
    content: "Doer B: record button in the header showing recording state, target file and row count, driven by the server's reported state"
    status: pending
  - id: responsive
    content: "Doer B: make the page fluid for a small iframe - nothing claiming fixed height, type and spacing scaling with the viewport down to a legibility floor, everything reachable by scrolling"
    status: pending
  - id: merge-verify
    content: Merge, run pytest, record a real session against --mock and inspect the CSV for gaps and duplicates, browser-check the button across reloads and two tabs
    status: pending
  - id: audit
    content: Launch a fresh auditor over both halves; surface the verdict inline
    status: pending
isProject: false
---

# Record traffic to CSV

## Summary

Today the monitor shows a rolling 10-second window and forgets everything older. This adds a **record button** in the page header: pressing it starts appending every datapoint to a CSV file on the machine running the monitor, and pressing it again stops. Pressing record a third time starts a **new** file rather than adding to the old one. Recording stops when the program exits.

The recording is **server-side**. The button is only a control — the browser can neither append to a file nor be trusted to stay open, so closing or reloading the page leaves a recording running, and the button reflects what the server is actually doing rather than what this tab remembers doing.

Each recording is **fixed to the subnet that was selected when it started**. Changing the subnet in the page afterwards changes what you are looking at but not what is being written, so a file has one stable set of columns and one meaning for its whole length.

Alongside it, the page becomes **fluid enough to live in a small iframe**: no element claims a fixed amount of height, text and spacing scale with the available size down to a legibility floor, and everything remains reachable by scrolling. These land together because they are the same work — the record button adds content to the header at the moment the header has to stop being a fixed-height bar.

## Why the recorder needs its own thread

The obvious implementation writes a row whenever a poll happens. That is wrong here for two reasons, and both are consequences of existing design decisions rather than hypotheticals.

**Polls are not guaranteed.** The page polls twice a second, but if the browser is closed, backgrounded, or disconnected, polling stops — and a recording that silently stops collecting when you close the tab is worse than one that refuses to start, because you only discover it afterwards when the file is short.

**Poll timing does not align with buckets.** The aggregator publishes completed 250 ms buckets; a 500 ms poll would see two new buckets each time, but jitter, a slow request, or a retry after a failure would make that three, or one, or the same bucket twice. Rows would silently duplicate or go missing depending on network timing.

So the recorder runs a **daemon thread ticking at bucket resolution**, tracking the last bucket it wrote and writing every bucket that has completed since. The aggregator already zero-fills buckets that nobody recorded into, so a quiet device produces zeros rather than a gap — which is the same reasoning that makes a silent device's graph scroll instead of freezing.

**Ceiling worth stating:** the recorder can only write buckets still inside the aggregator's 10-second window. If the thread is starved for longer than that, those buckets are gone. A `ponytail:` comment should name it, and the recorder should note the gap in its own status rather than writing a silently short file. The upgrade path, if it ever matters, is a queue fed from `record`.

## File layout

- **Location:** a `recordings/` directory beside the program, overridable with `--recordings-dir`. Added to `.gitignore` — recordings are data, not source.
- **Naming:** timestamped and self-describing, e.g. `netmon-20260828-123456-192.168.2.0-24.csv`, with the subnet's `/` replaced since it is not legal in a filename. The point is that a directory listing tells you when a recording was taken and of what, without opening anything.
- **A new file per start.** Pressing record again never reopens a previous file, which is what makes "stop and restart" safe.
- **Opened in append mode** as asked, so an existing file of the same name is extended rather than truncated. In practice the timestamp makes collision unlikely, but truncating someone's data because a name repeated is not a failure mode worth having.
- **Columns:** a header row, then one row per device per bucket:

```csv
timestamp_iso,epoch_ms,ip,pps
2026-08-28T12:34:56.750-04:00,1787935496750,192.168.2.2,32.0
```

`timestamp_iso` is the **end** of the bucket the rate covers, local time with offset so it is unambiguous; `epoch_ms` is the same instant for tooling that would rather not parse dates. Both are cheap and save the reader guessing.

- **Flushed every tick**, so killing the program loses at most one bucket rather than an OS buffer's worth.

## Interface contracts

### Contract 1 amendment — `GET /api/rates` gains `recording`

```json
"recording": {
  "active": true,
  "file": "recordings/netmon-20260828-123456-192.168.2.0-24.csv",
  "subnet": "192.168.2.0/24",
  "rows": 4820,
  "started_ms": 1787935496750,
  "detail": null
}
```

- Present on **every** response, `active: false` with nulls when not recording — the page must never have to guess, and a missing key would read as "not recording" exactly when something had gone wrong.
- `subnet` is the subnet the recording is fixed to, which may differ from the payload's own `subnet` once the viewer changes what they are looking at. The page should show it when they differ, since that is precisely the confusing case.
- `rows` is the count written so far — the cheapest honest proof that recording is working.
- `detail` is null normally, and a human-readable sentence if the recording has a problem (disk error, dropped buckets). The page shows it verbatim, exactly as it already does for capture problems.

### Contract 2 — `POST /api/record`

Request body:

```json
{ "action": "start", "subnet": "192.168.2.0/24" }
{ "action": "stop" }
```

- **`start`** begins a new recording fixed to `subnet`, validated the same way `?subnet=` already is. Responds **200** with the same `recording` object the payload carries.
- **`stop`** ends the current recording and closes the file. Responds **200** with the final `recording` object, `active: false`, so the page can report how much was written.
- **`start` while already recording responds 409** with the current `recording` object rather than silently restarting. Two tabs are possible, and the loser of that race should re-sync rather than quietly destroying the other's recording by opening a new file. The page's own toggle never sends it, because it reads the live state first.
- **`stop` while not recording responds 200**, not an error — the desired end state already holds, and a second click landing twice should not produce a scary message.
- Invalid JSON, an unknown `action`, or an invalid subnet responds **400** with `{"error": "<sentence>"}`, matching the shape `?subnet=` already uses.
- A disk or permission failure responds **500** with the same `error` shape and a sentence naming the path, since that is the one failure the user can actually act on.

## Files and ownership

**Doer A — backend (exclusive write):**

- `netmon/recorder.py` (new)
- `netmon/server.py` — `do_POST`, the `recording` payload key, `--recordings-dir`, shutdown
- `tests/test_recorder.py` (new), `tests/test_server.py`
- `.gitignore` — the `recordings/` entry

**Doer B — frontend (exclusive write):**

- `web/index.html`, `web/style.css`, `web/app.js`

The two are independent given the contracts above and run in parallel.

## Doer A: the recorder

- `Recorder` following the lifecycle the other sources already use (`start`/`stop`/`status`), so `server.py` shuts it down in the same `finally` that stops the capture source. `stop()` must never raise and must be safe when nothing is recording.
- Writes are done by the recorder's own thread. The HTTP handler only starts and stops it, so a slow disk cannot stall a poll.
- The subnet filter is applied with the **existing** helper the endpoint already uses, not a second implementation — a recording that disagreed with the page about what is in a subnet would be a nasty bug to find.
- `status()` is live and cheap, since it is called on every poll.
- Close the file on stop and on shutdown. A `Ctrl+C` must leave a valid, flushed CSV.

## Doer B: the record button

- A button in the header, styled to read as a record control without shouting; the header is otherwise information, so this is the one thing in it that does something.
- **Driven by the server's reported state**, never by local optimism: the label, the active indicator and the row count all come from the `recording` object. A reload, a second tab, or a recording someone else started must all show correctly.
- Pressing it sends `start` with the currently selected subnet, or `stop`, based on the state last reported. Disable it while a request is in flight so a double-click cannot fire two starts.
- While recording, show that it is recording, the file being written, and the row count climbing — the row count is what tells the user it is actually working.
- If the recording's subnet differs from the one being viewed, say so plainly. This is the case that would otherwise have someone believing they are recording what is on screen.
- Show `recording.detail` verbatim when present, the same way capture problems are already surfaced.
- On a 409, adopt the state from the response rather than arguing with it.
- Accessibility: the button reports its pressed state, and the recording indicator is announced. The row count is text, not a graphic.

## Doer B: fluid layout for a small iframe

The page is destined for a panel in Cockpit that may be small, so it has to degrade gracefully rather than assume room. The embedded page's own viewport **is** the iframe, so viewport units and media queries behave normally and no container-query machinery is needed.

- **Nothing claims fixed height — the header least of all.** Its height follows its content, its padding and type scale with the viewport, and its items are allowed to **wrap** onto further lines when the width runs out rather than overflowing or being clipped. It now carries a title, subnet field, host, device count, connection indicator, simulated-data tag and record button, so wrapping is the normal case at small widths, not an edge case.
- **Type and spacing scale with the viewport, with a floor.** Use `clamp()` on a small number of root-level custom properties — a base font size, the label column width, the row/canvas height, the header padding — and derive the rest from them, so scaling is a handful of declarations rather than a media query per element. The floor matters more than the ceiling: text that scales below readable is worse than text that stops shrinking, so pick minimums that stay legible and let the layout scroll instead.
- **The label column shrinks and eventually yields.** `--label-w` is fixed-width by design so canvases align, so it must clamp down at narrow widths. Below the point where an IP and its rate no longer fit side by side with a useful graph, consider stacking the label above the canvas within each card — but only if alignment across rows and the shared axis is preserved, which remains non-negotiable.
- **Everything is reachable by scrolling.** At small sizes nothing may be clipped or stranded: the page scrolls as a whole, including the header, rather than trapping content in a nested scroller with no way to reach it. Watch for the existing sticky axis footer — sticky is a feature at normal sizes, but it must not consume so much of a short viewport that rows become unreadable, and it must not end up pinned over content the user cannot scroll past. If it cannot pay for itself in a very short viewport, let it scroll normally there.
- **Graph height scales too**, since a 10-second trace in a tiny panel is about shape rather than precision. Canvases already redraw on `ResizeObserver` with `devicePixelRatio` scaling, so this should need no new drawing code — verify that rather than assuming it.
- **The shared axis thins out rather than crowding.** Three labels at a narrow width will collide; drop to fewer ticks when there is no room, keeping "now" as the one that survives. This is the one part likely to need `app.js` rather than CSS alone.
- **No horizontal scrolling** at any width — the layout reflows instead.
- Keep it to the existing custom-property approach and the one grid. This should make the stylesheet smaller and more general, not add a parallel set of small-screen rules.

## Testing

Both halves' logic is testable without touching a real disk in anger:

- Bucket accounting is the risky part and gets the most attention: no duplicate rows across ticks, no gaps, correct behaviour when the thread is late, and the documented loss when it is later than the whole window. Drive it with the injected fake clock the tests already use.
- The subnet fix at start: a device outside the recorded subnet never appears, and changing the viewed subnet mid-recording does not change the file.
- The CSV itself: header written once, one row per device per bucket, timestamps matching bucket ends, and a file that parses with `csv.reader`.
- Append rather than truncate against an existing file.
- Endpoint behaviour: every response shape above, including 409 on a double start and 200 on a redundant stop.
- Shutdown closes and flushes the file.
- Write temporary files to a pytest `tmp_path`, never into the repo.

## Verification

- `pytest` passes.
- Record a real session against `--mock` for around 30 seconds, then inspect the CSV: row count consistent with devices × buckets, timestamps evenly spaced by `bucket_ms` with no repeats or holes, and the dropout device's zeros present rather than missing.
- Start, stop, and start again; confirm two separate files and that the first is untouched by the second.
- Reload the page mid-recording and confirm the button still shows recording, with the row count continuing to climb.
- Open a second tab and confirm both agree, and that a start from the second tab while recording is refused without disturbing the first.
- Change the subnet mid-recording and confirm the file keeps its original subnet while the page shows the difference.
- `Ctrl+C` mid-recording and confirm the CSV is valid and flushed.

For the fluid layout, in a browser at several sizes — including genuinely small ones, since that is the point:

- At roughly **320×240**, **400×300**, **640×480** and a comfortable large size: nothing clipped, nothing overflowing, no horizontal scrollbar, and every row plus the record button reachable by scrolling.
- The header's height changes with its content and wraps rather than overflowing; it never reserves space it is not using.
- Text remains legible at the smallest size — the floor is doing its job rather than the text scaling into illegibility.
- Row canvases stay aligned with each other and with the shared axis at **every** size tested. This is the invariant most likely to break while making things fluid.
- The axis labels thin out instead of colliding at narrow widths.
- Screenshots at the smallest and largest sizes, attached to the summary, since this is a judgement the developer will want to see rather than read about.

No in-real-life testing applies: this writes a local file and needs no hardware.

## Out of scope

- Downloading a recording through the browser, listing past recordings, or any file management in the page. The files are on the machine running the monitor, which is where the operator already is.
- Rotation, size caps, and retention. Worth revisiting once there is a sense of how long a real recording runs; a rough figure is around 100 bytes per row, so seven devices at 4 buckets a second is on the order of 10 MB an hour.
- Recording anything other than per-device rates — no capture status history, no packet contents.
- Any change to capture, the aggregator, or the graphs beyond making their container fluid.
- A separate mobile or compact *mode*. There is one layout that scales, not two layouts with a switch between them — a second mode would double the surface that has to keep its canvases aligned.

---

*Stacks on `feat/packet-capture` and lands in [PR #2](https://github.com/cal-oriley/cockpit-network-monitor/pull/2), per the developer's decision to keep one branch.*
