"""Detectors — turn raw honeypot events into alerts.

Brute-force bursts: N+ failed SSH auths from one source inside a window.
Port scans: M+ distinct dst ports from one source inside a window.
Both are pure functions over the event history — unit-testable.
"""

from __future__ import annotations

import datetime as _dt

BRUTE_THRESHOLD = 5      # failed auths
SCAN_THRESHOLD = 8       # distinct ports
WINDOW_SECONDS = 120


def _parse(ts: str) -> _dt.datetime:
    return _dt.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_dt.timezone.utc)


def detect_brute_force(events: list[dict],
                       threshold: int = BRUTE_THRESHOLD,
                       window: int = WINDOW_SECONDS) -> list[dict]:
    """Events: rows with ts, kind='ssh_auth', src, detail ('failed'/'ok')."""
    by_src: dict[str, list[dict]] = {}
    for e in events:
        if e.get("kind") == "ssh_auth" and "failed" in (e.get("detail") or ""):
            by_src.setdefault(e["src"], []).append(e)
    alerts = []
    for src, rows in by_src.items():
        rows.sort(key=lambda e: e["ts"])
        for i, e in enumerate(rows):
            window_rows = [r for r in rows[i:]
                           if (_parse(r["ts"]) - _parse(e["ts"])).total_seconds() <= window]
            if len(window_rows) >= threshold:
                alerts.append({
                    "kind": "brute_force", "src": src,
                    "count": len(window_rows),
                    "first": e["ts"], "last": window_rows[-1]["ts"],
                    "reason": f"{len(window_rows)} failed SSH logins in {window}s from {src}",
                })
                break  # one alert per source per pass
    return alerts


def detect_portscan(events: list[dict],
                    threshold: int = SCAN_THRESHOLD,
                    window: int = WINDOW_SECONDS) -> list[dict]:
    by_src: dict[str, set[int]] = {}
    first_ts: dict[str, str] = {}
    for e in events:
        if e.get("kind") == "portscan" and e.get("dst_port"):
            by_src.setdefault(e["src"], set()).add(e["dst_port"])
            if e["src"] not in first_ts or e["ts"] < first_ts[e["src"]]:
                first_ts[e["src"]] = e["ts"]
    alerts = []
    for src, ports in by_src.items():
        if len(ports) >= threshold:
            alerts.append({
                "kind": "portscan", "src": src,
                "count": len(ports),
                "first": first_ts[src], "last": None,
                "reason": f"{len(ports)} distinct ports touched from {src}",
            })
    return alerts


def run(store, since_limit: int = 500) -> list[dict]:
    events = store.recent(limit=since_limit)
    alerts = detect_brute_force(events) + detect_portscan(events)
    # persist alerts so they survive restarts
    for a in alerts:
        store.add_event(kind="feed", src=a["src"], detail=f"ALERT {a['kind']}: {a['reason']}",
                        alert=True, alert_reason=a["reason"])
    return alerts
