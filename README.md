# cockpit-network-monitor

A small Python web server that monitors live packet traffic on a subnet to detect connection dropouts.

It runs on the topside computer at `192.168.2.1` and serves a dark single page
showing, for every device on the watched subnet that sends it a packet, a live
10-second graph of that device's packet rate, headed by a combined graph
summing the devices on show. The subnet is set from the page itself and
defaults to `192.168.2.0/24`. Once a device has been seen it keeps its row for
the life of the process, so a device going quiet reads as a flatline rather
than a disappearing row. The page is sized to be embedded as an iframe panel in
Blue Robotics Cockpit.

Capture is **passive**. The monitor asks the OS for copies of packets that were
already arriving at its own address and transmits nothing, so it adds no load
to the tether, is not in the packet path, and needs no promiscuous mode.

## Requirements

- **Windows**, for live capture.
- **[Npcap](https://npcap.com)**, the packet-capture driver Wireshark installs
  on Windows. Install it from [npcap.com](https://npcap.com) — it is a system
  driver, not a pip package.
- **scapy**, from `requirements.txt`.

Whether capture needs an elevated (Administrator) terminal depends on how Npcap
was installed. Run unelevated first: a refused permission is reported in the
page, which will say to restart as an administrator.

## Quickstart

```
pip install -r requirements.txt
python -m netmon.server
```

Then open <http://localhost:8080>.

To review the page with no tether, no vehicle, and no Npcap, feed it synthetic
traffic instead:

```
python -m netmon.server --mock
```

If another process on the machine already holds port 8080, either command exits
saying it cannot bind. Pass a free port and open that instead:

```
python -m netmon.server --port 8765
```

### Flags

- `--port` — listen port (default `8080`)
- `--host` — bind address (default `0.0.0.0`)
- `--host-ip` — the address to capture traffic sent to, which also selects the
  adapter to listen on and is reported to the UI as the monitored host
  (default `192.168.2.1`)
- `--subnet` — subnet used when the page does not ask for one (default `192.168.2.0/24`)
- `--iface` — capture interface, overriding the adapter derived from
  `--host-ip`; needed only when that derivation picks the wrong adapter
- `--mock` — feed the aggregator synthetic traffic instead of real packets
- `--capture-status STATE` — force the reported capture state, to review the status banner
- `--recordings-dir` — where recordings are written (default `recordings/`)

## Capture status

Anything that stops capture working — Npcap absent, no adapter holding
`--host-ip`, a refused permission, a capture that died after starting — is
reported as a banner across the top of the page, naming what to check, with the
device rows left readable. The server does not exit on a capture failure, and
`--capture-status` forces a state so the banner can be reviewed without
reproducing the condition.

## Recording

The page shows a rolling 10-second window and forgets everything older. To keep
a longer record, press **record** in the header: every datapoint is appended to
a timestamped CSV under `recordings/`, one row per device per 250 ms bucket.

```csv
timestamp_iso,epoch_ms,ip,pps
2026-08-28T12:34:56.750-04:00,1787935496750,192.168.2.2,32.0
```

Recording happens on the machine running the monitor, not in the browser, so
closing or reloading the page leaves it running — the button reports what the
server is actually doing. A recording is fixed to the subnet selected when it
started, so changing what you are looking at does not change what is written.
Pressing record again stops it; pressing it once more starts a **new** file.
Recording stops when the program exits.

## Tests

```
pip install -r requirements.txt
pytest
```

## Further reading

- [Packet capture feasibility](docs/capture-feasibility.md) — the capture
  research: scapy over Npcap, why a stdlib raw socket was rejected, the BPF
  filter, licensing, and measured throughput.
