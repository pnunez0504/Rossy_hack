#!/usr/bin/env python3
"""fake_rover — a stand-in for the real ESP32-S3 rover, for exploit testing.

It mimics the exact ROS2 interface the real rover will expose, so the Rossy
toolkit can be developed and demoed before the firmware is finished:

  PUBLISHES
    /rover/camera/image_raw  sensor_msgs/Image   (10 Hz, a moving green bar)
    /rover/pir               std_msgs/Bool       ( 1 Hz, motion on/off)
  SUBSCRIBES
    /cmd_vel                 geometry_msgs/Twist (drive commands -> motors)
  SERVICE
    /rover/shutdown          std_srvs/Trigger    (power-off hook)

Why these exact names/types: they match Rossy's auto-classifier, so `scan`,
`jam camera`, `jam pir`, `teleop`, and `shutdown` all target them with no flags.
When the real ESP32 comes online, it publishes/subscribes the SAME topics and
this node simply goes away — nothing in Rossy changes.
"""
import math
import rclpy
from rclpy.node import Node
from sensor_msgs.msg import Image
from std_msgs.msg import Bool
from geometry_msgs.msg import Twist
from std_srvs.srv import Trigger


class FakeRover(Node):
    def __init__(self):
        super().__init__('fake_rover')

        # --- publishers / subscriber / service ---
        self.cam_pub = self.create_publisher(Image, '/rover/camera/image_raw', 10)
        self.pir_pub = self.create_publisher(Bool, '/rover/pir', 10)
        self.create_subscription(Twist, '/cmd_vel', self.on_cmd, 10)
        self.create_service(Trigger, '/rover/shutdown', self.on_shutdown)

        # --- state ---
        self.W, self.H = 160, 120      # small frame keeps pure-Python render cheap
        self.frame = 0
        self.motion = False
        self.powered = True

        # --- timers drive the periodic publishing ---
        self.create_timer(0.1, self.tick_camera)   # 10 Hz
        self.create_timer(1.0, self.tick_pir)       # 1 Hz

        self.get_logger().info(
            'fake_rover ONLINE — cam=/rover/camera/image_raw  pir=/rover/pir  '
            'drive=/cmd_vel  kill=/rover/shutdown')

    # ---- camera: a green bar sweeping left<->right on a dark field ----------
    # Visually obvious when jammed: Rossy's `jam camera` replaces this with a
    # solid black (or white) frame, so in rqt_image_view the bar freezes/vanishes.
    def tick_camera(self):
        if not self.powered:
            return
        W, H = self.W, self.H
        bar = int((math.sin(self.frame / 10.0) * 0.5 + 0.5) * (W - 1))
        row = bytearray(W * 3)
        for x in range(W):
            i = x * 3
            if abs(x - bar) < 4:
                row[i:i + 3] = b'\x00\xff\x00'          # green bar
            else:
                row[i:i + 3] = b'\x14\x14\x28'          # dark blue-grey field
        msg = Image()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = 'camera_link'
        msg.height = H
        msg.width = W
        msg.encoding = 'rgb8'
        msg.is_bigendian = 0
        msg.step = W * 3
        msg.data = bytes(row) * H       # every row identical (vertical bar)
        self.cam_pub.publish(msg)
        self.frame += 1

    # ---- PIR: flip motion state each second (simple, easy to see when jammed) -
    def tick_pir(self):
        if not self.powered:
            return
        self.motion = not self.motion
        self.pir_pub.publish(Bool(data=self.motion))
        self.get_logger().info(f'PIR motion = {self.motion}')

    # ---- drive: this is the motor command sink -----------------------------
    # Logged at WARN so hijacked commands from Rossy's teleop stand out clearly
    # in the console during the demo. Replace the body with real motor control
    # (or let the ESP32 own this topic) for the live rover.
    def on_cmd(self, msg: Twist):
        self.get_logger().warn(
            f'DRIVE CMD  linear.x={msg.linear.x:+.2f} m/s  '
            f'angular.z={msg.angular.z:+.2f} rad/s')

    # ---- shutdown service ---------------------------------------------------
    def on_shutdown(self, request, response):
        self.get_logger().error('*** /rover/shutdown CALLED — powering down rover ***')
        self.powered = False
        response.success = True
        response.message = 'rover shutting down'
        return response


def main(args=None):
    rclpy.init(args=args)
    node = FakeRover()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
