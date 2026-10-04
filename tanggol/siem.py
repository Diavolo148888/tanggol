"""SIEM feed server — the pipeline between honeypot and the world.

GET  /            the SIEM dashboard (dark, terminal-styled)
GET  /api/events  recent events JSON
GET  /api/stats   aggregate stats JSON
GET  /api/globe   3D globe page (Three.js)
POST /api/feed    remote event ingest: {"kind","src","dst_port","detail"}
                  (for KAB0T or other machines to push events in)

Run: python3 -m tanggol.siem [port]   (default 127.0.0.1:8789)
"""

from __future__ import annotations

import html as _htm
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__
from .store import Store
from .detectors import run as run_detectors

_DASH = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TANGGOL — war room</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; background:#060809; color:#cfd8d3;
  font:13px/1.5 ui-monospace,'JetBrains Mono',Menlo,monospace; padding:32px 20px; }
.wrap { max-width:1100px; margin:0 auto; }
.brand { letter-spacing:.35em; color:#30d158; font-weight:700; font-size:12px; }
h1 { font-size:22px; color:#f2f2f2; margin:8px 0 18px; }
a { color:#30d158; }
.stats { display:flex; gap:12px; margin-bottom:22px; flex-wrap:wrap; }
.stat { flex:1; min-width:130px; border:1px solid #1c211e; background:#0b0f0d; padding:14px 16px; }
.stat .n { font-size:26px; font-weight:700; color:#30d158; }
.stat.alert .n { color:#ff3b30; }
.stat .l { color:#6d7a72; font-size:10px; letter-spacing:.2em; margin-top:2px; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { text-align:left; color:#6d7a72; padding:8px 10px; border-bottom:1px solid #1c211e; }
td { padding:7px 10px; border-bottom:1px solid #131715; }
tr.alert-row td { background:rgba(255,59,48,.08); }
.tag { font-size:10px; padding:1px 7px; border-radius:2px; letter-spacing:.1em;
  color:#30d158; border:1px solid #30d15855; }
.tag.alert { color:#ff3b30; border-color:#ff3b3055; }
.muted { color:#6d7a72; }
footer { margin-top:26px; color:#4a554e; font-size:11px; }
</style></head><body><div class="wrap">
<div class="brand">TANGGOL<b>//</b>WAR ROOM</div>
<h1>home SIEM <span class="muted">v__VER__</span> · <a href="/globe">3D globe</a></h1>
<div class="stats" id="stats"></div>
<table><thead><tr><th>WHEN</th><th>KIND</th><th>SOURCE</th><th>PORT</th><th>DETAIL</th></tr></thead>
<tbody id="events"></tbody></table>
<footer>Every event from the honeypot lands here. Alerts in red. Stdlib only.</footer>
</div>
<script>
const esc = s => { const d = document.createElement('div'); d.textContent = s ?? ''; return d.innerHTML; };
async function refresh() {
  const st = await (await fetch('/api/stats')).json();
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="n">${st.total}</div><div class="l">total events</div></div>
    <div class="stat ${st.alerts ? 'alert' : ''}"><div class="n">${st.alerts}</div><div class="l">alerts</div></div>
    ${st.top_sources.slice(0,2).map(s => `<div class="stat"><div class="n">${s.count}</div><div class="l">${esc(s.src)}</div></div>`).join('')}`;
  const ev = await (await fetch('/api/events?limit=40')).json();
  document.getElementById('events').innerHTML = ev.map(e => `
    <tr class="${e.alert ? 'alert-row' : ''}">
      <td class="muted">${esc(e.ts)}</td>
      <td><span class="tag ${e.alert ? 'alert' : ''}">${esc(e.kind)}</span></td>
      <td>${esc(e.src)}</td>
      <td>${e.dst_port ?? ''}</td>
      <td>${esc(e.detail)}</td></tr>`).join('');
}
refresh(); setInterval(refresh, 5000);
</script></body></html>"""

_GLOBE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TANGGOL — 3D globe</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#060809; overflow:hidden;
    font:12px ui-monospace,'JetBrains Mono',Menlo,monospace; color:#cfd8d3; }
  #globe { position:fixed; inset:0; }
  .hud { position:fixed; top:18px; left:20px; z-index:2; }
  .brand { letter-spacing:.35em; color:#30d158; font-weight:700; font-size:12px; }
  .count { font-size:26px; font-weight:700; color:#ff3b30; margin-top:6px; }
  .lbl { color:#6d7a72; font-size:10px; letter-spacing:.2em; }
  .back { position:fixed; bottom:18px; left:20px; color:#30d158; text-decoration:none; }
</style></head><body>
<div id="globe"></div>
<div class="hud">
  <div class="brand">TANGGOL<b>//</b>ATTACK GLOBE</div>
  <div class="count" id="count">0</div>
  <div class="lbl">attack arcs — live from the honeypot</div>
</div>
<a class="back" href="/">back to war room</a>
<script type="importmap">
{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js",
"three/addons/":"https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"}}
</script>
<script type="module">
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

const W = () => window.innerWidth, H = () => window.innerHeight;
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(45, W()/H(), 0.1, 100);
camera.position.set(0, 1.2, 3.2);
const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
renderer.setSize(W(), H());
document.getElementById('globe').appendChild(renderer.domElement);
const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;

// globe: points-on-sphere landmass illusion
const R = 1;
const sphere = new THREE.Mesh(
  new THREE.SphereGeometry(R, 48, 48),
  new THREE.MeshBasicMaterial({ color: 0x0a2018, transparent: true, opacity: 0.9 })
);
scene.add(sphere);
const wire = new THREE.Mesh(
  new THREE.SphereGeometry(R * 1.001, 24, 32),
  new THREE.MeshBasicMaterial({ color: 0x1a4a2f, wireframe: true, transparent: true, opacity: 0.25 })
);
scene.add(wire);

// home marker (Philippines approx: 12.8N, 121.7E)
function latLon(lat, lon, r = R) {
  const phi = (90 - lat) * Math.PI / 180;
  const theta = (lon + 180) * Math.PI / 180;
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta)
  );
}
const home = latLon(12.8, 121.7);
const homeDot = new THREE.Mesh(new THREE.SphereGeometry(0.02, 12, 12),
  new THREE.MeshBasicMaterial({ color: 0x30d158 }));
homeDot.position.copy(home);
scene.add(homeDot);

// random source lat/lon for demo arcs (v0.2: real geoip)
function randomSrc() {
  return latLon((Math.random() * 140 - 60), (Math.random() * 340 - 170));
}

const arcs = [];
function addArc(from, to) {
  const mid = from.clone().add(to).multiplyScalar(0.5).normalize().multiplyScalar(R * 1.35);
  const curve = new THREE.QuadraticBezierCurve3(from, mid, to);
  const geo = new THREE.TubeGeometry(curve, 32, 0.004, 6, false);
  const mat = new THREE.MeshBasicMaterial({ color: 0xff3b30, transparent: true, opacity: 0.85 });
  const mesh = new THREE.Mesh(geo, mat);
  scene.add(mesh);
  arcs.push({ mesh, born: performance.now() });
  setTimeout(() => {
    scene.remove(mesh);
    geo.dispose(); mat.dispose();
    const i = arcs.indexOf(mesh);
    if (i >= 0) arcs.splice(i, 1);
  }, 9000);
}

let count = 0;
async function poll() {
  try {
    if (window.__PRESEED__) {
      // ?shot=1: seed arcs instantly so a static capture catches a live-looking globe
      const st0 = await (await fetch('/api/stats')).json();
      for (let i = 0; i < Math.min(st0.total, 12); i++) addArc(randomSrc(), home);
      count = st0.total;
      document.getElementById('count').textContent = count;
      window.__PRESEED__ = 0;
      window.__SHOT_DONE__ = 1;  // stop the rAF loop: settle for headless capture
      return;
    }
    const st = await (await fetch('/api/stats')).json();
    const target = st.total - count;
    if (target > 0) {
      for (let i = 0; i < Math.min(target, 6); i++) addArc(randomSrc(), home);
      count = st.total;
      document.getElementById('count').textContent = count;
    }
  } catch (e) { /* feed down: keep spinning */ }
}
poll(); setInterval(poll, 3000);

(function animate() {
  if (!window.__SHOT_DONE__) requestAnimationFrame(animate);
  controls.update();
  wire.rotation.y += 0.0006;
  renderer.render(scene, camera);
})();
window.addEventListener('resize', () => {
  camera.aspect = W()/H(); camera.updateProjectionMatrix();
  renderer.setSize(W(), H());
});
</script></body></html>"""


class Api(BaseHTTPRequestHandler):
    store: Store = None

    def log_message(self, fmt, *args):
        sys.stderr.write("[siem] %s\n" % (fmt % args))

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _prerender_dash(self, body: str) -> str:
        """Inject stats + rows server-side (?shot=1) so static captures render populated."""
        st = self.store.stats()
        ev = self.store.recent(limit=40)
        esc = _htm.escape
        stats = (
            '<div class="stat"><div class="n">%d</div><div class="l">total events</div></div>'
            '<div class="stat%s"><div class="n">%d</div><div class="l">alerts</div></div>%s'
            % (st["total"], " alert" if st["alerts"] else "", st["alerts"],
               "".join('<div class="stat"><div class="n">%d</div><div class="l">%s</div></div>'
                       % (s["count"], esc(s["src"])) for s in st["top_sources"][:2]))
        )
        rows = "".join(
            '<tr class="%s"><td class="muted">%s</td>'
            '<td><span class="tag%s">%s</span></td>'
            '<td>%s</td><td>%s</td><td>%s</td></tr>'
            % ("alert-row" if e["alert"] else "", esc(e["ts"]),
               " alert" if e["alert"] else "", esc(e["kind"]),
               esc(e["src"]), "" if e["dst_port"] is None else e["dst_port"], esc(e["detail"]))
            for e in ev
        )
        body = body.replace('<div class="stats" id="stats"></div>',
                            '<div class="stats" id="stats">%s</div>' % stats)
        body = body.replace('<tbody id="events"></tbody>', '<tbody id="events">%s</tbody>' % rows)
        return body

    def _html(self, page, shot: bool = False, preseed: bool = False):
        body = page.replace("__VER__", __version__)
        if shot and preseed:
            body = body.replace("</head>", "<script>window.__PRESEED__=1</script></head>")
        if shot:
            body = self._prerender_dash(body)
        body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path).path
        q = urlparse(self.path).query
        shot = "shot=1" in q
        if p == "/" or p == "/siem":
            self._html(_DASH, shot=shot, preseed=False)
        elif p == "/globe":
            self._html(_GLOBE, shot=shot, preseed=True)
        elif p == "/api/events":
            limit = 100
            for part in q.split("&"):
                if part.startswith("limit="):
                    try: limit = min(int(part[6:]), 500)
                    except ValueError: pass
            self._json(self.store.recent(limit=limit))
        elif p == "/api/stats":
            self._json(self.store.stats())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/feed":
            return self._json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "bad JSON"}, 400)
        kind = str(payload.get("kind", "feed"))[:24]
        src = str(payload.get("src", "unknown"))[:64]
        port = payload.get("dst_port")
        detail = str(payload.get("detail", ""))[:200]
        eid = self.store.add_event(kind, src, port, detail)
        # run detectors on every ingest so alerts land fast
        alerts = run_detectors(self.store)
        self._json({"ok": True, "event_id": eid, "alerts": alerts})


def main(port: int = 8789, db: str | None = None) -> None:
    Api.store = Store(db)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Api)
    print(f"[siem] war room  on http://127.0.0.1:{port}")
    print(f"[siem] 3d globe   on http://127.0.0.1:{port}/globe")
    print(f"[siem] feed       POST /api/feed")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[siem] down")


if __name__ == "__main__":
    # usage: python3 -m tanggol.siem [port] [db_path]
    db_arg = sys.argv[2] if len(sys.argv) > 2 else None
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8789, db=db_arg)
