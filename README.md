# TANGGOL

```
  personal war room
  one honeypot feeding a 3D attack globe and a live SIEM
```

TANGGOL (*tanggol* — defend) merges the classic threat-map project and
the home-SOC project into one weapon: a real honeypot on your network
generates events, SQLite stores them, detectors turn them into alerts,
and two views render the battlefield — a Three.js 3D attack globe and a
terminal-styled SIEM dashboard.

Pure Python stdlib on the backend. Zero dependencies. The globe page
pulls Three.js from a CDN at render time.

## Architecture

    honeypot (SSH-ish trap, HTTP tarpit, port-sweep decoys)
      -> Store (SQLite, thread-safe)
        -> detectors (brute-force bursts, port scans)  -> alerts
        -> siem.py  (dashboard + JSON API + POST feed)
        -> /globe   (Three.js: spinning wireframe, attack arcs from
                     random sources to your home marker, live counter)

## Run it

    # 1. the honeypot (binds 127.0.0.1:2222 ssh-ish, :8090 http, 10000-10010 sweep)
    python3 -m tanggol

    # 2. the war room + globe
    python3 -m tanggol.siem 8789
    #   dashboard: http://127.0.0.1:8789
    #   3D globe:  http://127.0.0.1:8789/globe

To expose the traps on your LAN (only ever on a network you own):

    python3 -m tanggol 0.0.0.0

## CLI

| Command | Purpose |
|---|---|
| `tanggol events` | recent events (--kind, --alerts filters) |
| `tanggol detect` | run detectors now |
| `tanggol stats` | aggregate stats: totals, top sources, by kind |
| `tanggol demo --db /tmp/x.db` | synthesize a brute-force burst + 10-port sweep, run detectors |

## Feed API (for KAB0T and other machines)

    POST /api/feed
    {"kind": "http_hit", "src": "192.168.1.99", "dst_port": 80, "detail": "GET /.env"}

Every ingest runs the detectors, so alerts land the moment the event
arrives. GET `/api/stats` and `/api/events` power any dashboard.

## Detectors

- **Brute force** — 5+ failed SSH auths from one source in 120s (verified:
  fires at 7, quiet at 4, quiet when scattered across hours)
- **Port scan** — 8+ distinct ports from one source (verified: fires at 10,
  quiet at 5)

Alerts persist in the store (`alert=1`) so they survive restarts.

## Tests

Detector logic is pure and unit-tested. Run the verification suite:

    python3 -m unittest discover tests

## Ethics

The honeypot is a log-and-refuse trap — it accepts connections, records
them, and serves nothing exploitable. Bind it only to networks you own.

## Roadmap

- [x] v0.1 — honeypot, store, detectors, SIEM dashboard, 3D globe, feed API
- [ ] v0.2 — real GeoIP on arcs (source countries, not random)
- [ ] v0.3 — Telegram alerts via KAB0T
- [ ] v0.4 — auth-log ingestion from the real sshd

## Author

**John Mark "mako" Alojado** — [github.com/Diavolo148888](https://github.com/Diavolo148888)

MIT License — see LICENSE.
