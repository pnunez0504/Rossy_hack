# Rossy — ROS2 / ESP32-S3 Rover Exploit Toolkit

Offensive toolkit for **authorized** security testing of a self-built ESP32-S3
rover and its ROS2 stack (UTSA Rowdy Hack). It demonstrates the consequences of
running ROS2 **without SROS2 security**: the DDS graph has no auth, so any
participant on the WiFi can discover, eavesdrop, spoof, drive, and kill the robot.

## What it does

| Command | Capability | Mechanism |
|---|---|---|
| `recon` | find the rover on the network | port sweep: DDS 7400+, micro-ROS UDP 8888, rosbridge 9090, ESP32 web 80/81/8080 |
| `scan` | map the ROS2 graph | lists nodes/topics/services, **auto-classifies** camera / PIR / drive |
| `sniff` | eavesdrop camera + PIR | subscribes to sensor topics, saves frames to `./loot/` |
| `jam` | interrupt camera / PIR | high-rate spoof publishing — subscribers read our samples, not the sensor |
| `teleop` | remote-control hijack | publishes `geometry_msgs/Twist` to the drive topic (scripted or WASD) |
| `shutdown` | kill the robot | lifecycle/kill **services** → e-stop topics → zero-velocity flood |
| `web …` | ESP32 Arduino web vector | discovers the control API, replays drive cmds, taps camera, hits off endpoint |
| `pwn` | end-to-end demo | recon → scan → jam → teleop → shutdown in one shot |

## Backends (hybrid, auto-selected)

1. **Native rclpy (DDS)** — strongest; you are a real graph participant,
   indistinguishable from a legit node. Used automatically when a ROS2 env is
   sourced. Target for a **micro-ROS** rover.
2. **rosbridge (websocket)** — zero ROS2 install needed; pass `--rosbridge HOST:9090`.
3. **HTTP** — the `web` subcommand; no ROS2 at all.

## Install

```bash
pip install -r requirements.txt          # rich, requests, roslibpy, pyyaml
# For the native DDS backend, instead/also install ROS2 and source it:
#   source /opt/ros/humble/setup.bash     # (run.sh does this automatically)
```

## Usage

```bash
./run.sh recon 192.168.4.0/24                 # 1. find the rover
./run.sh scan                                 # 2. map the graph (native DDS)
./run.sh scan --rosbridge 192.168.4.2:9090    #    ...or via rosbridge
./run.sh sniff --kinds camera,pir -d 15        # 3. prove eavesdropping
./run.sh jam camera --mode black -d 30         # 4a. blind the camera
./run.sh jam pir --mode always-off -d 30       # 4b. defeat motion detection
./run.sh teleop -i                             # 5. interactive WASD hijack
./run.sh teleop --topic /cmd_vel --linear 0.3 --angular 0.5 -d 5
./run.sh shutdown -d 5                          # 6. kill chain
# ESP32 Arduino web server vector:
./run.sh web discover 192.168.4.1
./run.sh web drive 192.168.4.1 forward
./run.sh web camera 192.168.4.1 --stream :81/stream -d 5
./run.sh web shutdown 192.168.4.1
# one-shot demo:
./run.sh pwn --web 192.168.4.1
```

Every auto-chosen topic can be overridden (`--topic`, `--camera`, `--pir`,
`--drive`). See `config/profile.example.yaml` for a per-rover override sheet.


## Target-side bridge (`bridge/patrolbot_bridge.py`)

Runs on the **ROS 2 target computer** (Ubuntu 22.04 + ROS 2 Humble), joined to
the robot's `PatrolBot` Wi-Fi AP. It relays standard ROS 2 topics to the robot's
unauthenticated HTTP control channel, so a ROS-side action — legitimate **or**
injected by Rossy — physically moves the guard. This is what makes the demo land:

| ROS 2 topic | Type | Effect |
|---|---|---|
| `/cmd_vel` | `Twist` | drive |
| `/patrolbot/detection_enable` | `Bool` | `false` = blind the sensor |
| `/patrolbot/estop` | `Bool` | `true` = halt |

```bash
source /opt/ros/humble/setup.bash
pip install requests
python3 bridge/patrolbot_bridge.py
```

## Loot

`sniff` and `web camera` write captured frames to `./loot/` as proof of access.

## Legal / scope

Only for hardware **you own** or are explicitly authorized to test. This is a
hackathon security demo against the author's own rover.
