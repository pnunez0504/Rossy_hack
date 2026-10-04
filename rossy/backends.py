"""Backend abstraction over the ROS2 graph.

Two implementations behind one interface so the attack modules don't care how
they reach the rover:

  * RclpyBackend     - native DDS. Activates only if a ROS2 env is sourced
                       (import rclpy succeeds). This is the strongest: it IS a
                       first-class graph participant, indistinguishable from a
                       legit node. Target for micro-ROS rovers.
  * RosbridgeBackend - websocket (roslibpy) to a rosbridge_server. Works with
                       zero ROS2 install. Slightly noisier, JSON-framed.

Both expose:
    list_topics()  -> {name: type_str}
    list_nodes()   -> [name]
    list_services()-> {name: type_str}
    publisher(topic, type_str) -> callable(dict) that publishes one msg
    subscribe(topic, type_str, cb) -> subscription handle (cb gets a dict)
    call_service(name, type_str, req_dict) -> response dict
    spin_once(timeout) / close()

Message payloads are plain dicts in both backends so the attack code is uniform.
"""
from __future__ import annotations
import time, threading
from . import util

# ---- optional native ROS2 -------------------------------------------------
try:
    import rclpy
    from rclpy.node import Node
    from rosidl_runtime_py.utilities import get_message, get_service
    from rosidl_runtime_py import message_to_ordereddict, set_message_fields
    HAVE_RCLPY = True
except Exception:
    HAVE_RCLPY = False

# ---- optional rosbridge ---------------------------------------------------
try:
    import roslibpy
    HAVE_ROSLIBPY = True
except Exception:
    HAVE_ROSLIBPY = False


# ===========================================================================
# Topic classification — the secret sauce for a hands-off demo.
# Given {topic: type}, decide which is camera / pir / drive / state so the
# operator can just run `rossy jam` without naming topics by hand.
# ===========================================================================
CAMERA_TYPES = ("sensor_msgs/msg/Image", "sensor_msgs/msg/CompressedImage",
                "sensor_msgs/msg/CameraInfo")
PIR_TYPES    = ("sensor_msgs/msg/Range", "std_msgs/msg/Bool",
                "sensor_msgs/msg/Illuminance")
DRIVE_TYPES  = ("geometry_msgs/msg/Twist", "geometry_msgs/msg/TwistStamped",
                "ackermann_msgs/msg/AckermannDriveStamped")

CAMERA_HINT = ("cam", "image", "video", "rgb", "mjpeg", "frame")
PIR_HINT    = ("pir", "motion", "presence", "occupan", "proximity", "ir_", "intruder")
DRIVE_HINT  = ("cmd_vel", "cmd", "drive", "move", "teleop", "control", "motor", "wheel")
STATE_HINT  = ("odom", "battery", "joint", "status", "state", "imu")

# Infrastructure node-name fragments we exclude when judging whether a topic has
# a "real" (robot-side) publisher/subscriber vs. just tooling/our own node.
INFRA_NODES = ("rosbridge", "rosapi", "robot_state_publisher_2", "_ros2cli", "rossy")


def is_infra(node: str) -> bool:
    return any(k in node for k in INFRA_NODES)


def _norm(t: str) -> str:
    """Normalize a type string: rosbridge gives 'sensor_msgs/Image',
    rclpy gives 'sensor_msgs/msg/Image'. Collapse to the 3-part form."""
    parts = t.split("/")
    if len(parts) == 2:
        return f"{parts[0]}/msg/{parts[1]}"
    return t


def classify(topics: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """-> {'camera':[(topic,type)], 'pir':[...], 'drive':[...], 'state':[...], 'other':[...]}"""
    buckets = {"camera": [], "pir": [], "drive": [], "state": [], "other": []}
    for name, typ in sorted(topics.items()):
        nt = _norm(typ)
        low = name.lower()
        if nt in CAMERA_TYPES or any(h in low for h in CAMERA_HINT):
            buckets["camera"].append((name, typ))
        elif nt in DRIVE_TYPES or any(h in low for h in DRIVE_HINT):
            buckets["drive"].append((name, typ))
        elif nt in PIR_TYPES and (any(h in low for h in PIR_HINT) or nt == "sensor_msgs/msg/Range"):
            buckets["pir"].append((name, typ))
        elif any(h in low for h in PIR_HINT):
            buckets["pir"].append((name, typ))
        elif any(h in low for h in STATE_HINT):
            buckets["state"].append((name, typ))
        else:
            buckets["other"].append((name, typ))
    return buckets


def pick(buckets: dict, kind: str, override: str | None = None) -> tuple[str, str] | None:
    """Choose the single best topic for a kind, honoring a manual override."""
    if override:
        for b in buckets.values():
            for (n, t) in b:
                if n == override:
                    return (n, t)
        return (override, "")  # unknown type; caller may still try
    items = buckets.get(kind, [])
    return items[0] if items else None


def topic_role(be, topic: str) -> str:
    """Classify a topic by DATA-FLOW DIRECTION (robot-agnostic — ignores names).
    A topic the robot *subscribes* to is a command INPUT (inject/spoof surface);
    one it *publishes* is a sensor/state OUTPUT (sniff/jam surface)."""
    ep = be.endpoints(topic)
    real_pubs = [n for n in ep.get("pubs", []) if not is_infra(n)]
    real_subs = [n for n in ep.get("subs", []) if not is_infra(n)]
    if real_subs and not real_pubs:
        return "INPUT -> inject"
    if real_pubs and not real_subs:
        return "OUTPUT -> sniff/jam"
    if real_pubs and real_subs:
        return "bidir"
    return "idle"


# ===========================================================================
class Backend:
    name = "base"
    def list_topics(self) -> dict[str, str]: raise NotImplementedError
    def list_nodes(self) -> list[str]: raise NotImplementedError
    def list_services(self) -> dict[str, str]: raise NotImplementedError
    def publisher(self, topic, type_str): raise NotImplementedError
    def subscribe(self, topic, type_str, cb): raise NotImplementedError
    def call_service(self, name, type_str, req): raise NotImplementedError
    def endpoints(self, topic) -> dict: return {"pubs": [], "subs": []}
    def spin_once(self, timeout=0.1): pass
    def close(self): pass


# ---------------------------------------------------------------------------
class RclpyBackend(Backend):
    name = "rclpy (native DDS)"

    def __init__(self, domain_id: int | None = None):
        import os
        if domain_id is not None:
            os.environ["ROS_DOMAIN_ID"] = str(domain_id)
        rclpy.init(args=None)
        # Deliberately bland node name so we blend into the graph.
        self.node = Node("robot_state_publisher_2")
        self._pubs = {}
        self._subs = []
        self._spin = threading.Thread(target=self._spin_loop, daemon=True)
        self._alive = True
        self._spin.start()
        time.sleep(1.0)  # let discovery populate the graph

    def _spin_loop(self):
        while self._alive:
            rclpy.spin_once(self.node, timeout_sec=0.1)

    def list_topics(self):
        return {n: ts[0] for n, ts in self.node.get_topic_names_and_types() if ts}

    def list_nodes(self):
        out = []
        for name, ns in self.node.get_node_names_and_namespaces():
            out.append((ns.rstrip("/") + "/" + name) if ns != "/" else "/" + name)
        return out

    def list_services(self):
        return {n: ts[0] for n, ts in self.node.get_service_names_and_types() if ts}

    def endpoints(self, topic):
        def full(i):
            ns = i.node_namespace.rstrip("/")
            return f"{ns}/{i.node_name}" if ns else "/" + i.node_name
        try:
            pubs = [full(i) for i in self.node.get_publishers_info_by_topic(topic)]
            subs = [full(i) for i in self.node.get_subscriptions_info_by_topic(topic)]
        except Exception:
            pubs, subs = [], []
        return {"pubs": pubs, "subs": subs}

    def publisher(self, topic, type_str):
        msg_cls = get_message(_norm(type_str))
        if topic not in self._pubs:
            self._pubs[topic] = self.node.create_publisher(msg_cls, topic, 10)
        pub = self._pubs[topic]

        def send(fields: dict):
            msg = msg_cls()
            try:
                set_message_fields(msg, fields)
            except Exception as e:
                util.warn(f"field set failed ({e}); sending default-constructed msg")
            pub.publish(msg)
        return send

    def subscribe(self, topic, type_str, cb):
        msg_cls = get_message(_norm(type_str))

        def _wrap(msg):
            try:
                cb(dict(message_to_ordereddict(msg)))
            except Exception:
                cb({"_raw": repr(msg)[:200]})
        sub = self.node.create_subscription(msg_cls, topic, _wrap, 10)
        self._subs.append(sub)
        return sub

    def call_service(self, name, type_str, req):
        srv_cls = get_service(_norm(type_str))
        cli = self.node.create_client(srv_cls, name)
        if not cli.wait_for_service(timeout_sec=3.0):
            raise TimeoutError(f"service {name} not available")
        request = srv_cls.Request()
        try:
            set_message_fields(request, req or {})
        except Exception:
            pass
        fut = cli.call_async(request)
        t0 = time.time()
        while not fut.done() and time.time() - t0 < 5.0:
            time.sleep(0.02)
        return dict(message_to_ordereddict(fut.result())) if fut.done() and fut.result() else {}

    def close(self):
        self._alive = False
        try:
            self.node.destroy_node()
            rclpy.shutdown()
        except Exception:
            pass


# ---------------------------------------------------------------------------
class RosbridgeBackend(Backend):
    name = "rosbridge (websocket)"

    def __init__(self, host: str, port: int = 9090):
        self.client = roslibpy.Ros(host=host, port=port)
        self.client.run()
        t0 = time.time()
        while not self.client.is_connected and time.time() - t0 < 5.0:
            time.sleep(0.05)
        if not self.client.is_connected:
            raise ConnectionError(f"rosbridge not reachable at ws://{host}:{port}")
        self._topics = {}

    def _rosapi(self, service, typ, req=None):
        svc = roslibpy.Service(self.client, service, typ)
        return svc.call(roslibpy.ServiceRequest(req or {}))

    def list_topics(self):
        r = self._rosapi("/rosapi/topics", "rosapi/Topics")
        names = r.get("topics", [])
        types = r.get("types", [])
        if types and len(types) == len(names):
            return dict(zip(names, types))
        out = {}
        for n in names:
            try:
                tr = self._rosapi("/rosapi/topic_type", "rosapi/TopicType", {"topic": n})
                out[n] = tr.get("type", "")
            except Exception:
                out[n] = ""
        return out

    def list_nodes(self):
        try:
            return self._rosapi("/rosapi/nodes", "rosapi/Nodes").get("nodes", [])
        except Exception:
            return []

    def list_services(self):
        try:
            r = self._rosapi("/rosapi/services", "rosapi/Services")
            names = r.get("services", [])
            out = {}
            for n in names:
                try:
                    tr = self._rosapi("/rosapi/service_type", "rosapi/ServiceType", {"service": n})
                    out[n] = tr.get("type", "")
                except Exception:
                    out[n] = ""
            return out
        except Exception:
            return {}

    def endpoints(self, topic):
        def names(service, typ, key):
            try:
                return self._rosapi(service, typ, {"topic": topic}).get(key, [])
            except Exception:
                return []
        return {"pubs": names("/rosapi/publishers", "rosapi/Publishers", "publishers"),
                "subs": names("/rosapi/subscribers", "rosapi/Subscribers", "subscribers")}

    def publisher(self, topic, type_str):
        t = roslibpy.Topic(self.client, topic, _norm(type_str).replace("/msg/", "/"))
        t.advertise()
        self._topics[topic] = t

        def send(fields: dict):
            t.publish(roslibpy.Message(fields))
        return send

    def subscribe(self, topic, type_str, cb):
        t = roslibpy.Topic(self.client, topic, _norm(type_str).replace("/msg/", "/"))
        t.subscribe(cb)
        self._topics[topic + "#sub"] = t
        return t

    def call_service(self, name, type_str, req):
        return self._rosapi(name, type_str.replace("/srv/", "/"), req)

    def close(self):
        for t in self._topics.values():
            try:
                t.unadvertise()
            except Exception:
                pass
        try:
            self.client.terminate()
        except Exception:
            pass


# ---------------------------------------------------------------------------
def connect(rosbridge: str | None = None, domain_id: int | None = None,
            prefer: str = "auto", peers: str | None = None,
            discovery_server: str | None = None) -> Backend:
    """Choose a backend. `rosbridge` is 'host' or 'host:port' or 'ws://host:port'.

    `peers` / `discovery_server` make NATIVE DDS reach off-network (e.g. over a
    Tailscale 100.x address), since DDS's default multicast discovery never
    crosses routers/NAT/overlays. Must be applied before rclpy.init().
    """
    want_bridge = rosbridge is not None or prefer == "rosbridge"

    if not want_bridge and prefer in ("auto", "rclpy") and HAVE_RCLPY:
        if peers or discovery_server:
            _configure_dds_unicast(peers, discovery_server)
        util.info("using native rclpy backend (sourced ROS2 env detected)")
        return RclpyBackend(domain_id=domain_id)

    if rosbridge or prefer == "rosbridge":
        if not HAVE_ROSLIBPY:
            raise RuntimeError("roslibpy not installed — `pip install roslibpy`")
        host, port = _parse_ws(rosbridge or "127.0.0.1:9090")
        util.info(f"using rosbridge backend ws://{host}:{port}")
        return RosbridgeBackend(host, port)

    # auto with no ROS2 env and no bridge given
    raise RuntimeError(
        "No backend available. Either `source /opt/ros/<distro>/setup.bash` "
        "for native DDS, or pass --rosbridge HOST:9090.")


def _configure_dds_unicast(peers: str | None, discovery_server: str | None) -> None:
    """Point native DDS at explicit unicast endpoints so it works across
    networks (Tailscale, VPN, routed LANs). Sets env BEFORE rclpy.init so the
    RMW picks it up. Covers both common RMWs:
      * Cyclone DDS  -> CYCLONEDDS_URI inline XML with <Peers>
      * Fast DDS     -> initial-peers profile XML, or ROS_DISCOVERY_SERVER
    Multicast is left enabled, so on-LAN discovery still works too (true hybrid).
    """
    import os, tempfile
    rmw = os.environ.get("RMW_IMPLEMENTATION", "(default)")
    util.info(f"configuring DDS unicast discovery (active RMW: {rmw})")

    if discovery_server:
        # Fast DDS discovery server: a known unicast rendezvous point.
        os.environ["ROS_DISCOVERY_SERVER"] = discovery_server
        os.environ.setdefault("ROS_SUPER_CLIENT", "true")  # see the whole graph via the server
        util.ok(f"Fast DDS discovery server -> {discovery_server}")

    if peers:
        plist = [p.strip() for p in peers.split(",") if p.strip()]
        # Cyclone DDS: inline XML string is accepted directly in CYCLONEDDS_URI.
        peer_xml = "".join(f'<Peer address="{p}"/>' for p in plist)
        os.environ["CYCLONEDDS_URI"] = (
            "<CycloneDDS><Domain><Discovery>"
            "<ParticipantIndex>auto</ParticipantIndex>"
            f"<Peers>{peer_xml}</Peers>"
            "</Discovery></Domain></CycloneDDS>")
        # Fast DDS: write an initial-peers profile and point the env at it.
        locs = "".join(
            f"<locator><udpv4><address>{p.split(':')[0]}</address></udpv4></locator>"
            for p in plist)
        fast = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<dds xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">'
            '<profiles><participant profile_name="rossy_unicast" is_default_profile="true">'
            f"<rtps><builtin><initialPeersList>{locs}</initialPeersList></builtin></rtps>"
            "</participant></profiles></dds>")
        f = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, prefix="rossy_dds_")
        f.write(fast)
        f.close()
        os.environ["FASTRTPS_DEFAULT_PROFILES_FILE"] = f.name
        os.environ.setdefault("FASTDDS_DEFAULT_PROFILES_FILE", f.name)
        util.ok(f"DDS unicast peers -> {', '.join(plist)}  (Cyclone + Fast DDS set)")


def _parse_ws(s: str) -> tuple[str, int]:
    s = s.replace("ws://", "").replace("wss://", "")
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, 9090
