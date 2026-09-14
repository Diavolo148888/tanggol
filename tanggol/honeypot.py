"""Honeypot — the event generator.

Binds decoy services on the home network (localhost by default; pass
0.0.0.0 to expose on the LAN — only ever on a network you own):

  SSH-ish    : port 2222 — accepts, logs auth attempts, always refuses
  HTTP-tarpit: port 8090 — logs every request path
  port-sweep : logs any TCP connect to decoy ports 10000-10010

Every connection becomes an event in the store. The detectors then turn
those events into alerts. Nothing here executes payloads — this is a
log-and-refuse trap, not an attack surface.
"""

from __future__ import annotations

import socket
import sys
import threading

from .store import Store
from .detectors import run as run_detectors


def _ssh_trap(port: int, store: Store) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((BIND_HOST, port))
    except OSError as e:
        print(f"[honeypot] ssh trap failed on {port}: {e}")
        return
    srv.listen(16)
    print(f"[honeypot] ssh-ish trap on {BIND_HOST}:{port}")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            return
        threading.Thread(target=_ssh_handle, args=(conn, addr, store), daemon=True).start()


def _ssh_handle(conn: socket.socket, addr, store: Store) -> None:
    src = addr[0]
    try:
        conn.settimeout(4)
        banner = b"SSH-2.0-OpenSSH_8.2\r\n"
        conn.sendall(banner)
        tries = 0
        while tries < 4:
            data = conn.recv(512)
            if not data:
                break
            tries += 1
            store.add_event("ssh_auth", src, 22, f"failed auth attempt {tries}: {data[:60]!r}")
        conn.close()
    except OSError:
        pass


def _http_trap(port: int, store: Store) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((BIND_HOST, port))
    except OSError as e:
        print(f"[honeypot] http trap failed on {port}: {e}")
        return
    srv.listen(16)
    print(f"[honeypot] http-tarpit on {BIND_HOST}:{port}")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            return
        threading.Thread(target=_http_handle, args=(conn, addr, store), daemon=True).start()


def _http_handle(conn: socket.socket, addr, store: Store) -> None:
    src = addr[0]
    try:
        conn.settimeout(4)
        data = conn.recv(1024)
        first = data.split(b"\r\n")[0].decode("latin-1", "replace") if data else "(empty)"
        store.add_event("http_hit", src, 80, first[:120])
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.close()
    except OSError:
        pass


def _sweep_trap(ports: list[int], store: Store) -> None:
    socks = []
    for port in ports:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((BIND_HOST, port))
            s.listen(8)
            socks.append((s, port))
            print(f"[honeypot] sweep trap on {BIND_HOST}:{port}")
        except OSError:
            continue
    while socks:
        for s, port in socks:
            try:
                s.settimeout(2)
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                store.add_event("portscan", addr[0], port, f"connect to decoy port {port}")
                conn.close()
            except OSError:
                continue


BIND_HOST = "127.0.0.1"


def main(store: Store | None = None, bind: str = "127.0.0.1") -> None:
    global BIND_HOST
    BIND_HOST = bind
    store = store or Store()
    print(f"TANGGOL honeypot v0.1 — trap on {bind} (only ever on a network you own)")
    threading.Thread(target=_ssh_trap, args=(2222, store), daemon=True).start()
    threading.Thread(target=_http_trap, args=(8090, store), daemon=True).start()
    threading.Thread(target=_sweep_trap, args=(list(range(10000, 10011)), store), daemon=True).start()

    # detector loop: every 30s, run detectors and print alerts
    try:
        import time
        while True:
            time.sleep(30)
            alerts = run_detectors(store)
            for a in alerts:
                print(f"[ALERT] {a['kind']}: {a['reason']}")
    except KeyboardInterrupt:
        print("\n[honeypot] down")


if __name__ == "__main__":
    main(bind=sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
