"""TANGGOL CLI — events / detect / serve / demo."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .store import Store
from .detectors import run as run_detectors


def cmd_events(args) -> None:
    store = Store()
    rows = store.recent(limit=args.limit, kind=args.kind, alerts_only=args.alerts)
    if not rows:
        print("no events yet — run the honeypot: python3 -m tanggol")
        return
    print(f"{'ID':<6} {'WHEN':<21} {'KIND':<10} {'SOURCE':<16} {'PORT':<6} DETAIL")
    for r in rows:
        mark = "[ALERT] " if r["alert"] else ""
        print(f"{r['id']:<6} {r['ts']:<21} {r['kind']:<10} {r['src']:<16} "
              f"{r['dst_port'] or '':<6} {mark}{r['detail'][:60]}")


def cmd_detect(args) -> None:
    store = Store()
    alerts = run_detectors(store)
    if not alerts:
        print("no alerts — surface looks quiet")
        return
    for a in alerts:
        print(f"[{a['kind'].upper()}] {a['reason']} (first seen: {a['first']})")


def cmd_stats(args) -> None:
    store = Store()
    s = store.stats()
    print(f"total events : {s['total']}")
    print(f"alerts       : {s['alerts']}")
    print(f"top sources  : " + ", ".join(f"{x['src']} ({x['count']})" for x in s["top_sources"]))
    print(f"by kind      : " + ", ".join(f"{x['kind']} ({x['count']})" for x in s["by_kind"]))


def cmd_demo(args) -> None:
    """Synthesize a brute-force burst + port scan, then run detectors."""
    import time
    store = Store(args.db if hasattr(args, "db") and args.db else None)
    now = time.time()
    # simulate: generate events directly with recent timestamps
    import datetime as _dt
    base = _dt.datetime.now(_dt.timezone.utc)
    for i in range(7):
        ts = (base - _dt.timedelta(seconds=60 - i * 5)).strftime("%Y-%m-%d %H:%M:%S")
        with store._lock:
            store.conn.execute(
                "INSERT INTO events(ts, kind, src, dst_port, detail, alert, alert_reason)"
                " VALUES (?,?,?,?,?,0,'')",
                (ts, "ssh_auth", "203.0.113.66", 22, f"failed auth attempt {i+1}: b'root'"),
            )
    for i in range(10):
        ts = (base - _dt.timedelta(seconds=90)).strftime("%Y-%m-%d %H:%M:%S")
        with store._lock:
            store.conn.execute(
                "INSERT INTO events(ts, kind, src, dst_port, detail, alert, alert_reason)"
                " VALUES (?,?,?,?,?,0,'')",
                (ts, "portscan", "198.51.100.23", 10000 + i, f"connect to decoy port {10000+i}"),
            )
        store.conn.commit()
    alerts = run_detectors(store)
    print("synthesized: 7 failed SSH auths from 203.0.113.66, 10-port sweep from 198.51.100.23")
    print()
    if not alerts:
        print("no alerts (unexpected — detectors should have fired)")
        return
    for a in alerts:
        print(f"[{a['kind'].upper()}] {a['reason']}")
    print()
    print("stored with alert=1 — visible in the SIEM: python3 -m tanggol.siem")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="tanggol", description="TANGGOL - personal war room")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("events", help="recent events")
    e.add_argument("--limit", type=int, default=50)
    e.add_argument("--kind", help="filter by kind")
    e.add_argument("--alerts", action="store_true", help="alerts only")
    sub.add_parser("detect", help="run detectors now")
    sub.add_parser("stats", help="aggregate stats")
    d = sub.add_parser("demo", help="synthesize attacks + run detectors")
    d.add_argument("--db", help="temp db path (default: the real one)")
    args = p.parse_args(argv)
    {"events": cmd_events, "detect": cmd_detect, "stats": cmd_stats, "demo": cmd_demo}[args.cmd](args)


if __name__ == "__main__":
    main()
