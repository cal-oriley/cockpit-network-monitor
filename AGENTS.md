# cockpit-network-monitor

A Python web app that runs on the topside computer at `192.168.2.1` and graphs
per-IP packet rates by passively listening to arriving traffic. The watched
subnet is chosen from the page itself and defaults to `192.168.2.0/24`. Built
for ROV operators, to be embedded as a panel in Blue Robotics Cockpit.

## Build / Test / Run

- **Build:** nothing to build — pure Python, standard library only in Phase 1.
- **Test:** `pytest`
- **Run / dev:** `python -m netmon.server --mock`

## Code Style

- Python. `snake_case` for modules, functions, and variables; `PascalCase` for
classes; `UPPER_SNAKE_CASE` for constants.
- No dependencies beyond the standard library in Phase 1. `pytest` is the only
dev dependency; scapy arrives with Phase 2.

## Architecture

- `netmon/rate_window.py` — thread-safe rolling-window aggregator. This is the
Phase 1 / Phase 2 seam: Phase 2 only changes who calls `RateWindow.record`.
- `netmon/mock_source.py` — synthetic traffic generator feeding the aggregator.
- `netmon/server.py` — stdlib `ThreadingHTTPServer` serving the `web/` directory
plus a `GET /api/rates` JSON endpoint, polled at 2 Hz by the browser. Owns
subnet filtering: the aggregator stays subnet-agnostic and the endpoint filters
on read, so the subnet is a parameter of the request rather than server state.
- `web/` — dark-themed single-page UI. Hand-rolled `<canvas>` graphs, no
libraries and no external resources.
- `tests/` — pytest unit tests.
- `docs/capture-feasibility.md` — Phase 2 packet-capture research.
- Runtime target: a Windows topside laptop at `192.168.2.1`. The page is
designed to be embedded as an iframe panel in Blue Robotics Cockpit.

## IRL Testing

- **Required?** Not for Phase 1 — it runs on mock data on a dev laptop, with no
elevation and no Npcap. **Yes for Phase 2**, which captures real packets.
- **Hardware / setup (Phase 2):** this development machine, which already has
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
- **IRL-facing paths:** `netmon/capture.py` (does not exist yet — arrives in
Phase 2).

