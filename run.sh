#!/usr/bin/env bash
# Rossy launcher. Sources a ROS2 env if present (enables the native DDS backend),
# then runs the CLI. Falls back cleanly to rosbridge/web if ROS2 isn't installed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
for d in /opt/ros/*/setup.bash; do
  if [ -f "$d" ]; then
    # shellcheck disable=SC1090
    source "$d"
    echo "[run.sh] sourced $d (ROS_DISTRO=${ROS_DISTRO:-?}) -> native DDS backend available"
    break
  fi
done
exec python3 -m rossy "$@"
