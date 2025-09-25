#!/usr/bin/env python3
"""
Fanotify monitoring rule for suspicious file access
"""

import os
import sys
from pathlib import Path

# Monitored paths
MONITORED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/home/*/.ssh/",
    "/tmp/",
    "/var/log/"
]

# Suspicious patterns
SUSPICIOUS_PATTERNS = [
    "*.exe",
    "*.bat",
    "*.ps1",
    "*.vbs",
    "*.scr"
]

# Events to monitor
EVENTS = [
    "FAN_ACCESS",
    "FAN_MODIFY",
    "FAN_OPEN",
    "FAN_CLOSE_WRITE"
]

def monitor_file_access():
    """Monitor file access using fanotify"""
    pass

if __name__ == "__main__":
    monitor_file_access()