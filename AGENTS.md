# cockpit-network-monitor

A Python web app that runs on the topside computer at `192.168.2.1` and graphs
per-IP packet rates by passively listening to arriving traffic. The watched
subnet is chosen from the page itself and defaults to `192.168.2.0/24`. Built
for ROV operators, to be embedded as a panel in Blue Robotics Cockpit.

## Build / Test / Run

- **Build:** nothing to build — pure Python.
- **Test:** `pytest`
- **Run (real capture):** `python -m netmon.server` — needs Npcap installed and
an adapter holding `--host-ip`.
- **Run (no hardware):** `python -m netmon.server --mock` — synthetic traffic,
no Npcap and no elevation needed. This is the mode to use for UI work.
- `--port 8080` will not bind on this machine; another process holds it. Pass
`--port 8765` or similar.

## Code Style

- Python. `snake_case` for modules, functions, and variables; `PascalCase` for
classes; `UPPER_SNAKE_CASE` for constants.
- `scapy` is the only runtime dependency, pinned below 2.8 because the
drop-counter read reaches through private scapy internals. `pytest` is the only
dev dependency. Everything else is standard library and should stay that way.
- Import scapy **lazily, inside the functions that need it** — never at module
scope. `--mock` must keep working without scapy installed, the pure-logic tests
must run without it, and `import scapy.all` costs seconds of arch
initialization.

## Architecture

- `netmon/rate_window.py` — thread-safe rolling-window aggregator, deliberately
subnet-agnostic. It retains every address it has ever seen and advances every
device's window with the clock, so a silent device scrolls along the baseline
rather than freezing.
- `netmon/capture.py` — the passive scapy-over-Npcap listener. Owns
`CaptureStatus`, derives the capture interface from `--host-ip`, and reads
dropped-packet counts. Its packet callback is deliberately incapable of
raising: an exception there kills the whole capture silently, which would render
as every device flatlining.
- `netmon/mock_source.py` — synthetic traffic generator feeding the aggregator.
Interchangeable with the capture source: both expose
`start`/`stop`/`running`/`status`.
- `netmon/server.py` — stdlib `ThreadingHTTPServer` serving the `web/` directory
plus a `GET /api/rates` JSON endpoint, polled at 10 Hz by the browser. Owns
subnet filtering: the aggregator stays subnet-agnostic and the endpoint filters
on read, so the subnet is a parameter of the request rather than server state.
- `web/` — dark-themed single-page UI. Hand-rolled `<canvas>` graphs, no
libraries and no external resources.
- `tests/` — pytest unit tests. Capture is tested by injecting a fake sniffer at
the trust boundary, so the whole suite runs with no hardware and no Npcap.
- `tools/benchmark_capture.py` — measures the capture path's sustained
packets/second, dropped-packet counts and CPU cost.
- `docs/capture-feasibility.md` — packet-capture research and measured results.
- Runtime target: a Windows topside laptop at `192.168.2.1`. The page is
designed to be embedded as an iframe panel in Blue Robotics Cockpit.

## IRL Testing

- **Required?** **Yes** — real packet capture is in the default run path and can
only be confirmed against a real vehicle. `--mock` needs no IRL testing: it runs
on synthetic data with no elevation and no Npcap.
- **Hardware / setup:** this development machine, which already has
Administrator access and Npcap 1.86 installed. The vehicle connects over the
tether to the **laptop's Ethernet port**, with that adapter statically set to
`192.168.2.1` and the ROV at `192.168.2.2`.
- **Elevation:** not unconditionally required. Npcap on this machine was
installed without the admin-only restriction (`AdminOnly=0`), and an unelevated
passive capture on the tether adapter opens and runs. Treat a permission
failure as something to detect and report, never as something to predict from
an is-administrator check.
- **Put system in a testable state:** set the Ethernet adapter's static IPv4
address to `192.168.2.1`, connect the tether, power the vehicle, and confirm
the adapter reports a connected link. The capture interface is then derived
automatically from `--host-ip`; no adapter needs naming by hand.
- **Command(s) to run:** run `python -m netmon.server`, then open the served
page. Run from an elevated (Administrator) terminal if capture reports a
permission failure — see the elevation note above. Note `--port 8080` fails to
bind on this machine because another process (`ApplicationWebServer`) already
holds `0.0.0.0:8080`; it is not a reserved-port exclusion, so pass a different
port, e.g. `--port 8765`.
- **What a pass looks like:** `192.168.2.2` appears as a row within a couple of
seconds of the vehicle being connected, its rate visibly tracks real activity
such as starting the video stream, `capture.state` reads `ok`, and no dropped
packets are reported.
- **Who does what:** the developer performs and confirms every IRL step; agents
produce the procedure and never claim an IRL test passed.
- **IRL-facing paths:** `netmon/capture.py`, and `netmon/server.py`'s source
selection in `main()`. Note the tether adapter does **not** currently hold
`192.168.2.1`, so a real run reports `interface_missing` until that static
address is restored — the first step of the procedure above.

