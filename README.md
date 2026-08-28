# cockpit-network-monitor

A small Python web server that monitors live packet traffic on a subnet to detect connection dropouts.

It runs on the topside computer at `192.168.2.1` and serves a dark single page
showing, for every device on `192.168.2.0/24` that sends it a packet, a live
10-second graph of that device's packet rate. The page is sized to be embedded
as an iframe panel in Blue Robotics Cockpit.

## Phases

- **Phase 1 (current)** — the UI, the HTTP API, and the rolling-window
  aggregator, fed by a synthetic traffic source. No hardware, no elevation.
- **Phase 2** — real passive packet capture on Windows via scapy over Npcap.
- **Phase 3** — Cockpit integration and packaging.

## Quickstart

No runtime dependencies — the app needs nothing but the standard library.

```
python -m netmon.server --mock
```

Then open <http://localhost:8080>.

### Flags

- `--port` — listen port (default `8080`)
- `--host` — bind address (default `0.0.0.0`)
- `--host-ip` — address reported to the UI as the monitored host (default `192.168.2.1`)
- `--mock` — feed the aggregator with synthetic traffic
- `--capture-status STATE` — force the reported capture state, to review the status banner

## Tests

```
pip install -r requirements.txt
pytest
```

## Further reading

- [Packet capture feasibility](docs/capture-feasibility.md) — the Phase 2
  capture research: scapy over Npcap, why a stdlib raw socket was rejected,
  licensing, and the benchmark to run.
