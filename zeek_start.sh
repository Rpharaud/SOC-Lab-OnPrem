#!/bin/bash

# Manual way to run zeek and create  log folder in the event that the autostart isn't working.

LOG_DIR=~/SOC-Lab-OnPrem/zeek-logs
mkdir -p "$LOG_DIR"
cd "$LOG_DIR"
sudo zeek -i enp0s1 /opt/zeek/share/zeek/site/local.zeek
