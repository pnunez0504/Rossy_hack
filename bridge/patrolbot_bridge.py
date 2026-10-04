#!/usr/bin/env python3
"""
patrolbot_bridge.py -- ROS 2 <-> PatrolBot bridge node.

Runs on the ROS 2 target computer (Ubuntu 22.04 + ROS 2 Humble).
It subscribes to standard ROS 2 topics and relays them to the robot's
unauthenticated HTTP control channel, and republishes the robot's sensor
state back onto ROS 2 topics. This is what makes a ROS-side action
(legitimate OR injected by the exploit tool) physically move the guard.

The three demo impacts map to three ROS 2 topics -- all unauthenticated
by DDS default, which is the whole security thesis:

  1. Remote control  : publish to  /cmd_vel                  (Twist)
  2. Sensor spoofing : publish to  /patrolbot/detection_enable (Bool, False = blind)
  3. Shutdown        : publish to  /patrolbot/estop          (Bool, True = halt)
                       ...or just kill this node -> the cmd_vel watchdog stops the bot.

NETWORK: this computer must be joined to the robot's "PatrolBot" Wi-Fi AP
so it can reach http://192.168.4.1.

Deps:  pip install requests   (rclpy comes with your ROS 2 install)
Run:   source /opt/ros/humble/setup.bash
       python3 patrolbot_bridge.py

Test from another terminal (also sourced):
  ros2 topic pub /cmd_vel geometry_msgs/Twist "{linear: {x: 0.5}}" -1
  ros2 topic pub /cmd_vel geometry_msgs/Twist "{angular: {z: 0.5}}" -1
  ros2 topic pub /patrolbot/detection_enable std_msgs/Bool "{data: false}" -1
  ros2 topic pub /patrolbot/estop std_msgs/Bool "{data: true}" -1
  ros2 topic echo /patrolbot/intruder_detected
"""

import time
import requests
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from std_msgs.msg import Bool, String

ROBOT_IP      = "192.168.4.1"   # PatrolBot AP address
LINEAR_DEAD   = 0.05            # ignore |linear.x| below this
ANGULAR_DEAD  = 0.05            # ignore |angular.z| below this
CMD_MIN_GAP   = 0.20            # min seconds between HTTP commands (don't flood)
WATCHDOG_S    = 1.5             # if no cmd_vel for this long while moving, stop
POLL_HZ       = 2.0            # watchdog/telemetry tick rate
HTTP_TIMEOUT  = 2.0            # seconds; WSL's network path needs more than 0.5s
ENABLE_TELEMETRY = False       # OFF: the ESP32 web server is single-threaded, so
                               # polling /status competes with movement commands and
                               # causes timeouts. Turn on only if you need the PIR
                               # topics and aren't actively driving.


class PatrolBotBridge(Node):
    def __init__(self):
        super().__init__("patrolbot_bridge")

        # --- ROS -> robot ---
        self.create_subscription(Twist, "/cmd_vel", self.on_cmd_vel, 10)
        self.create_subscription(Bool, "/patrolbot/detection_enable",
                                 self.on_detection_enable, 10)
        self.create_subscription(Bool, "/patrolbot/estop", self.on_estop, 10)

        # --- robot -> ROS (telemetry) ---
        self.pub_intruder = self.create_publisher(Bool,   "/patrolbot/intruder_detected", 10)
        self.pub_status   = self.create_publisher(String, "/patrolbot/status", 10)
        self.create_timer(1.0 / POLL_HZ, self.poll_status)

        self._last_cmd       = None
        self._last_cmd_time  = 0.0
        self._last_cmdvel_rx = time.time()
        self._moving         = False

        self.get_logger().info(f"PatrolBot bridge up. Target robot: http://{ROBOT_IP}")

    # ---------- HTTP helper ----------
    def _send(self, endpoint):
        try:
            # Connection: close -> don't hold the ESP32's single server slot open.
            requests.get(f"http://{ROBOT_IP}/{endpoint}", timeout=HTTP_TIMEOUT,
                         headers={"Connection": "close"})
            return True
        except requests.RequestException as e:
            self.get_logger().warning(f"robot '{endpoint}' failed: {e}")
            return False

    def _drive(self, cmd):
        """Rate-limited, de-duplicated movement command."""
        now = time.time()
        if cmd == self._last_cmd and cmd != "stop":
            return
        if now - self._last_cmd_time < CMD_MIN_GAP:
            return
        if self._send(cmd):
            self._last_cmd = cmd
            self._last_cmd_time = now
            self._moving = (cmd != "stop")

    # ---------- ROS -> robot ----------
    def on_cmd_vel(self, msg: Twist):
        self._last_cmdvel_rx = time.time()
        lx, az = msg.linear.x, msg.angular.z
        if   lx >  LINEAR_DEAD:  self._drive("forward")
        elif lx < -LINEAR_DEAD:  self._drive("backward")
        elif az >  ANGULAR_DEAD: self._drive("left")   # +z = counter-clockwise
        elif az < -ANGULAR_DEAD: self._drive("right")
        else:                    self._drive("stop")

    def on_detection_enable(self, msg: Bool):
        # False = blind the guard (sensor spoof). True = restore.
        self._send("unmute" if msg.data else "mute")
        self.get_logger().info(
            f"detection_enable={msg.data} -> {'unmute' if msg.data else 'MUTE (blinded)'}")

    def on_estop(self, msg: Bool):
        # True = halt (availability impact). False = resume.
        self._send("halt" if msg.data else "resume")
        self.get_logger().info(f"estop={msg.data} -> {'HALT' if msg.data else 'resume'}")

    # ---------- watchdog + telemetry ----------
    def poll_status(self):
        # Watchdog: if commands stopped arriving while moving, stop the bot.
        # (Killing the cmd_vel publisher / this node's upstream -> guard halts.)
        if self._moving and (time.time() - self._last_cmdvel_rx) > WATCHDOG_S:
            self._send("stop")
            self._moving = False
            self.get_logger().info("cmd_vel watchdog fired -> stop")

        # Telemetry: poll robot /status, republish as ROS topics.
        # OFF by default -- competes with movement commands on the ESP32's
        # single-threaded web server. See ENABLE_TELEMETRY above.
        if not ENABLE_TELEMETRY:
            return
        try:
            r = requests.get(f"http://{ROBOT_IP}/status", timeout=HTTP_TIMEOUT,
                             headers={"Connection": "close"})
            data = r.json()
        except (requests.RequestException, ValueError):
            return
        intr = Bool()
        intr.data = bool(data.get("frontPIR") or data.get("rearPIR"))
        self.pub_intruder.publish(intr)
        s = String()
        s.data = r.text
        self.pub_status.publish(s)


def main():
    rclpy.init()
    node = PatrolBotBridge()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node._send("stop")   # fail safe: stop the robot when the bridge dies
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
