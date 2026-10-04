"""Layer-3/4 recon: find the rover and its control planes on the WiFi.

No nmap dependency — pure sockets + threads. Sweeps a CIDR (or a single host)
for the ports that matter to a ROS2 / ESP32 rover and fingerprints them.

── UPGRADE (active RTPS/SPDP discovery) ─────────────────────────────────────
The original recon classified a host as a "ROS2 rover" whenever a *UDP* port
(7400/7401/7410/8888) didn't actively refuse the probe. But UDP has no reliable
"closed" signal — a silent host, a firewall that drops instead of sending ICMP,
or NAT in the path all read as "open". So it flagged essentially *every* live
host as a rover: a guesser, not a detector.

The fix is to speak the protocol. `spdp_probe()` sends a real **SPDP**
(Simple Participant Discovery Protocol) participant-announcement — the same
"hello" every ROS2/DDS node multicasts on startup — and listens for the
announcements that genuine participants send back. A host that answers *is*
running ROS2; a non-ROS host stays silent. That turns "this UDP port might be
open" into "this host is confirmed ROS2, here's its participant GUID", which is
what makes the hybrid's autonomous bot-discovery trustworthy.
"""
from __future__ import annotations
import ipaddress, socket, struct, os, time, concurrent.futures as cf
from . import util

# port -> (label, how-to-attack hint)
PORTS = {
    7400: ("DDS discovery (RTPS)", "native ROS2 graph — use scan/inject/jam via rclpy"),
    7401: ("DDS user traffic (RTPS)", "native ROS2 data — participant present"),
    7410: ("DDS discovery (alt domain)", "ROS_DOMAIN_ID != 0"),
    8888: ("micro-ROS agent (UDP)", "ESP32 micro-ROS bridge — likely the rover MCU"),
    9090: ("rosbridge websocket", "use --rosbridge HOST:9090 for topic pub/sub"),
    80:   ("HTTP", "Arduino web control — run `rossy web`"),
    8080: ("HTTP-alt", "Arduino web control — run `rossy web`"),
    81:   ("HTTP/ESP32-CAM stream", "MJPEG camera stream — eavesdrop target"),
    443:  ("HTTPS", "web control (TLS)"),
    22:   ("SSH", "companion computer (Pi/Jetson) running the ROS2 stack"),
    11311:("ROS1 master (legacy)", "ROS1 — not ROS2, but exploitable if present"),
}
TCP_PORTS = [p for p in PORTS if p not in (7400, 7401, 7410, 8888)]
UDP_PORTS = [7400, 7401, 7410, 8888]
_UDP_SET = set(UDP_PORTS)          # these are "unverified" unless SPDP confirms


# ===========================================================================
# Reliable TCP probing (a listening service really is there) + best-effort UDP.
# ===========================================================================
def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _udp_probe(ip: str, port: int, timeout: float) -> bool:
    """UDP is best-effort and UNVERIFIED: 'open' here only means 'did not refuse'.
    It never proves a service — that's what the SPDP probe below is for. We keep
    it only as a cheap hint that something *might* be listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"RTPS\x02\x01", (ip, port))
            try:
                s.recvfrom(1024)
                return True          # someone answered -> definitely open
            except socket.timeout:
                return True          # no refusal -> open|filtered (UNVERIFIED)
    except OSError:
        return False                 # ICMP unreachable surfaces here


def _banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            if port in (80, 8080, 81, 443):
                s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = s.recv(256)
            line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
            for ln in data.split(b"\r\n"):
                if ln.lower().startswith(b"server:"):
                    line += "  (" + ln.decode("latin1", "replace") + ")"
            return line.strip()
    except OSError:
        return ""


def _hosts(target: str) -> list[str]:
    if "/" in target:
        return [str(h) for h in ipaddress.ip_network(target, strict=False).hosts()]
    return [target]


def scan(target: str, timeout: float = 0.6, workers: int = 256) -> dict:
    """Return {ip: [(port, label, hint, banner), ...]} for hosts with hits."""
    hosts = _hosts(target)
    util.info(f"sweeping {len(hosts)} host(s) across {len(TCP_PORTS)} TCP + {len(UDP_PORTS)} UDP ports")
    jobs: list[tuple] = []
    for ip in hosts:
        for p in TCP_PORTS:
            jobs.append(("tcp", ip, p))
        for p in UDP_PORTS:
            jobs.append(("udp", ip, p))

    found: dict[str, list] = {}

    def work(job):
        proto, ip, p = job
        is_open = _tcp_probe(ip, p, timeout) if proto == "tcp" else _udp_probe(ip, p, timeout)
        return (ip, p, is_open)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, p, is_open in ex.map(work, jobs):
            if is_open:
                found.setdefault(ip, []).append(p)

    results: dict[str, list] = {}
    for ip, ports in sorted(found.items()):
        rows = []
        for p in sorted(set(ports)):
            label, hint = PORTS.get(p, ("?", ""))
            b = _banner(ip, p, timeout) if p in (80, 8080, 81, 443, 22) else ""
            rows.append((p, label, hint, b))
        results[ip] = rows
    return results


# ===========================================================================
# UPGRADE: active RTPS/SPDP discovery — positively confirm ROS2 participants.
# References: OMG DDSI-RTPS 2.x §8.4.2 (SPDP), §9.6 (wire format & port math).
# ===========================================================================
_RTPS_MAGIC   = b"RTPS"
_RTPS_PROTO   = b"\x02\x01"        # protocol version 2.1 (accepted by 2.x receivers)
_RTPS_VENDOR  = b"\x01\x0f"        # eProsima vendor id — blend in with Fast DDS
_SPDP_MCAST   = "239.255.0.1"      # well-known SPDP metatraffic multicast group
# Default RTPS port math: port = PB + DG*domainId + {d0 multicast | d1 unicast} (+ PG*participantId)
_PB, _DG, _PG, _d0, _d1 = 7400, 250, 2, 0, 10
# builtin entity ids that identify an SPDP participant-announcement DATA submessage
_EID_SPDP_READER = b"\x00\x01\x00\xc7"
_EID_SPDP_WRITER = b"\x00\x01\x00\xc2"
_EID_PARTICIPANT = b"\x00\x00\x01\xc1"


def _spdp_mcast_port(domain: int) -> int:
    return _PB + _DG * domain + _d0


def _spdp_ucast_port(domain: int, pid: int) -> int:
    return _PB + _DG * domain + _d1 + _PG * pid


def _spdp_param(pid: int, value: bytes) -> bytes:
    """One RTPS ParameterList entry: id(2) + length(2) + value (padded to 4)."""
    value = value + b"\x00" * ((-len(value)) % 4)
    return struct.pack("<HH", pid, len(value)) + value


def _build_spdp_announcement(my_ip: str, my_port: int, guid_prefix: bytes) -> bytes:
    """Craft a minimal-but-valid SPDP DATA(p) advertising US as a new participant.

    The key field is the METATRAFFIC_UNICAST_LOCATOR (my_ip:my_port): per RTPS,
    when an existing participant receives a new participant's SPDP, it replies by
    sending its OWN announcement to that locator. So a reply to my_port is proof
    the host runs ROS2 — no guessing from unanswered ports.
    """
    ip4 = socket.inet_aton(my_ip)
    locator = struct.pack("<II", 1, my_port) + b"\x00" * 12 + ip4   # kind=UDPv4, port, addr
    params = b"".join([
        _spdp_param(0x0015, b"\x02\x01\x00\x00"),                   # PROTOCOL_VERSION 2.1
        _spdp_param(0x0016, b"\x01\x0f\x00\x00"),                   # VENDORID
        _spdp_param(0x0050, guid_prefix + _EID_PARTICIPANT),        # PARTICIPANT_GUID
        _spdp_param(0x0032, locator),                               # METATRAFFIC_UNICAST_LOCATOR (reply here!)
        _spdp_param(0x0031, locator),                               # DEFAULT_UNICAST_LOCATOR
        _spdp_param(0x0002, struct.pack("<II", 100, 0)),            # PARTICIPANT_LEASE_DURATION = 100s
        _spdp_param(0x0058, struct.pack("<I", 0x0000003f)),         # BUILTIN_ENDPOINT_SET (participant+pub+sub)
        struct.pack("<HH", 0x0001, 0),                              # PID_SENTINEL (ends the list)
    ])
    serialized = b"\x00\x03\x00\x00" + params                       # PL_CDR_LE encapsulation + options
    data_body = (b"\x00\x00" + struct.pack("<H", 16)                 # extraFlags, octetsToInlineQos
                 + _EID_SPDP_READER + _EID_SPDP_WRITER
                 + struct.pack("<II", 0, 1)                          # writerSN = {high:0, low:1}
                 + serialized)
    submsg = struct.pack("<BBH", 0x15, 0x05, len(data_body)) + data_body  # DATA, flags E|D
    header = _RTPS_MAGIC + _RTPS_PROTO + _RTPS_VENDOR + guid_prefix       # 20-byte RTPS header
    return header + submsg


def _local_ip(target: str = "8.8.8.8") -> str:
    """Our source IP on the route toward `target` — this is the address we embed
    as the SPDP return locator, so replies must be able to reach it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def spdp_probe(hosts: list[str], domains=(0,), pids: int = 12,
               listen_secs: float = 3.0) -> dict:
    """Announce ourselves to each host's metatraffic ports (+ the SPDP multicast
    group) and collect the announcements real ROS2 participants send back.
    Returns {ip: {'guids': set(hex)}} for every host that answered.

    NOTE on reachability: replies come to the locator we advertise, so the prober
    must sit where the target can route back to us. Behind WSL2 NAT our source IP
    (172.x) is unreachable from the LAN, so no replies arrive — the same reason
    native DDS can't cross WSL NAT. Run from a host on the target's own network
    (native Linux, or WSL in mirrored mode) for SPDP confirmation to work.
    """
    if not hosts:
        return {}
    found: dict[str, dict] = {}
    my_ip = _local_ip(hosts[0])
    guid_prefix = b"\xff\xee" + os.urandom(10)        # unique per run; lets us ignore our own echo

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except OSError:
        pass
    rx.bind(("0.0.0.0", 0))                            # ephemeral port we both send from and listen on
    my_port = rx.getsockname()[1]
    pkt = _build_spdp_announcement(my_ip, my_port, guid_prefix)

    # fire the announcement at every candidate participant port, then multicast
    for d in domains:
        for ip in hosts:
            for pid in range(pids):
                try:
                    rx.sendto(pkt, (ip, _spdp_ucast_port(d, pid)))
                except OSError:
                    pass
        try:
            rx.sendto(pkt, (_SPDP_MCAST, _spdp_mcast_port(d)))
        except OSError:
            pass

    # collect SPDP replies (unicast back to our locator) for a short window
    rx.settimeout(0.5)
    deadline = time.time() + listen_secs
    while time.time() < deadline:
        try:
            data, addr = rx.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        # a valid RTPS packet whose GUID isn't ours == a real participant answered
        if data[:4] == _RTPS_MAGIC and data[8:20] != guid_prefix:
            rec = found.setdefault(addr[0], {"guids": set()})
            rec["guids"].add(data[8:20].hex())
    rx.close()
    return found


# ===========================================================================
def classify_host(rows: list, confirmed: bool = False) -> str:
    ports = {r[0] for r in rows}
    if confirmed:                                          # SPDP said so — definitive
        return "ROS2 host (SPDP-CONFIRMED)"
    if 9090 in ports:
        return "rosbridge host"
    if ports & {80, 8080, 81}:
        return "ESP32 web-control / camera"
    if 22 in ports:
        return "companion computer"
    # bare UDP DDS ports are NOT proof on their own — say so honestly
    if ports & _UDP_SET:
        return "possible ROS2 (UDP unverified — probe from the target's LAN to confirm)"
    return "unknown"


def run(target: str, timeout: float, workers: int) -> dict:
    util.rule("NETWORK RECON")
    res = scan(target, timeout=timeout, workers=workers)
    hosts = _hosts(target)

    # ---- UPGRADE: active RTPS/SPDP confirmation (replaces UDP guessing) ----
    util.info("active RTPS/SPDP probe for live ROS2 participants ...")
    spdp = spdp_probe(hosts)
    if spdp:
        for ip, rec in spdp.items():
            util.hit(f"CONFIRMED ROS2 participant at {ip}  (guid {next(iter(rec['guids']))[:16]}…)")
    else:
        util.warn("no SPDP replies — no ROS2 on this segment, OR replies can't route "
                  "back to us (e.g. running behind WSL NAT; probe from the target's LAN)")

    all_ips = set(res) | set(spdp)
    if not all_ips:
        util.warn("no hosts responded on rover-relevant ports. Check you're on the "
                  "rover's subnet and widen the timeout (-t 1.5).")
        return {"scan": res, "spdp": spdp}

    for ip in sorted(all_ips):
        rows = res.get(ip, [])
        confirmed = ip in spdp
        util.hit(f"{ip}  ->  {classify_host(rows, confirmed)}")
        table_rows = []
        for (p, label, hint, b) in rows:
            # UPGRADE: label bare-UDP hits as unverified so they aren't mistaken for proof
            svc = label if p not in _UDP_SET else label + "  [unverified]"
            table_rows.append([p, svc, hint, b or "-"])
        if confirmed:
            table_rows.append([7400, "RTPS/SPDP  [CONFIRMED]",
                               "native ROS2 graph — use scan/jam/teleop via rclpy",
                               "live participant"])
        util.table(f"{ip}", ["port", "service", "attack hint", "banner"], table_rows)

    util.ok(f"recon complete: {len(all_ips)} live host(s), {len(spdp)} SPDP-confirmed ROS2. "
            f"Pick a confirmed/rosbridge host for `scan`, a web host for `web`.")
    return {"scan": res, "spdp": spdp}
