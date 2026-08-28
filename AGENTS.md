# cockpit-network-monitor

A Python web app that runs on the topside computer at `192.168.2.1` and graphs
per-IP packet rates for devices on the `192.168.2.0/24` subnet by passively
listening to arriving traffic. Built for ROV operators, to be embedded as a
panel in Blue Robotics Cockpit.

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
  plus a `GET /api/rates` JSON endpoint, polled at 2 Hz by the browser.
- `web/` — dark-themed single-page UI. Hand-rolled `<canvas>` graphs, no
  libraries and no external resources.
- `tests/` — pytest unit tests.
- `docs/capture-feasibility.md` — Phase 2 packet-capture research.
- Runtime target: a Windows topside laptop at `192.168.2.1`. The page is
  designed to be embedded as an iframe panel in Blue Robotics Cockpit.

## IRL Testing

- **Required?** Not for Phase 1 — it runs on mock data on a dev laptop, with no
  elevation and no Npcap. **Yes for Phase 2**, which captures real packets.
- **Hardware / setup (Phase 2):** a Windows machine with Administrator rights, a
  one-time Npcap install from npcap.com, and a real vehicle connected over the
  tether with the topside adapter statically set to `192.168.2.1`.
- **Put system in a testable state:** to be supplied by the developer before
  Phase 2 starts — specifically which Windows machine, and how the tether is
  connected.
- **Command(s) to run:** to be supplied by the developer before Phase 2 starts.
- **What a pass looks like:** to be supplied by the developer before Phase 2
  starts.
- **Who does what:** the developer performs and confirms every IRL step; agents
  produce the procedure and never claim an IRL test passed.
- **IRL-facing paths:** `netmon/capture.py` (does not exist yet — arrives in
  Phase 2).
