#!/usr/bin/env python3
"""
OpenCanary → Home Assistant Notifier
Watches the OpenCanary log file and sends formatted webhook notifications
to Home Assistant when honeypot activity is detected.

Configuration via environment variables or .env file:
  OPENCANARY_LOG      Path to OpenCanary log file (default: /var/tmp/opencanary.log)
  HA_WEBHOOK_URL      Full Home Assistant webhook URL
"""

import subprocess
import json
import os
import sys
import requests

# ── Configuration ────────────────────────────────────────────────────────────
LOG_FILE    = os.getenv("OPENCANARY_LOG", "/var/tmp/opencanary.log")
HA_WEBHOOK  = os.getenv("HA_WEBHOOK_URL", "")

if not HA_WEBHOOK:
    print("ERROR: HA_WEBHOOK_URL environment variable is not set.")
    print("Example: export HA_WEBHOOK_URL=http://homeassistant.local:8123/api/webhook/your-id")
    sys.exit(1)

# ── Logtype mapping ───────────────────────────────────────────────────────────
LOGTYPES = {
    2000: "FTP",   2001: "FTP",
    3000: "HTTP",  3001: "HTTP",  3002: "HTTP",  3003: "HTTP",
    4000: "SSH",   4001: "SSH",   4002: "SSH",
    6001: "Telnet",6002: "Telnet",
    8001: "MySQL", 9003: "MySQL",
    14001:"RDP",
    17001:"Redis",
}

# Logtypes to ignore (system messages, non-actionable events)
IGNORE_LOGTYPES = {1001, 6002, 9003}

ICONS = {
    "SSH":    "🔐",
    "HTTP":   "🌐",
    "RDP":    "🖥️",
    "FTP":    "📁",
    "Telnet": "📟",
    "MySQL":  "🗄️",
    "Redis":  "⚡",
}

# ── Event parser ─────────────────────────────────────────────────────────────
def parse_event(line):
    try:
        e = json.loads(line)
        lt = e.get("logtype")
        if lt in IGNORE_LOGTYPES or lt not in LOGTYPES:
            return None
        service = LOGTYPES[lt]
        ld = e.get("logdata", {})
        detail = ""
        if lt == 4002:
            detail = f"{ld.get('USERNAME','?')} / {ld.get('PASSWORD','?')}"
        elif lt in (3001, 6001):
            detail = f"{ld.get('USERNAME','?')} / {ld.get('PASSWORD','?')}"
        elif lt in (4000, 4001):
            detail = ld.get("REMOTEVERSION", "")
        elif lt in (3000, 3002, 3003):
            detail = ld.get("PATH", "")
        elif lt == 17001:
            detail = ld.get("CMD", "")
        return {
            "service":  service,
            "src":      e.get("src_host", "?"),
            "dst_port": e.get("dst_port", "?"),
            "detail":   detail,
        }
    except Exception:
        return None

# ── HA webhook sender ─────────────────────────────────────────────────────────
def send_to_ha(event):
    icon = ICONS.get(event["service"], "⚠️")
    lines = [
        f"{icon} {event['service']} détecté",
        f"IP : {event['src']}",
        f"Port : {event['dst_port']}",
    ]
    if event["detail"]:
        lines.append(f"Détail : {event['detail']}")
    payload = {
        "title":    f"🍯 OpenCanary — {event['service']}",
        "message":  "\n".join(lines),
        "service":  event["service"],
        "src":      event["src"],
        "dst_port": str(event["dst_port"]),
        "detail":   event["detail"],
    }
    try:
        requests.post(HA_WEBHOOK, json=payload, timeout=5)
    except Exception as ex:
        print(f"[WARN] Webhook error: {ex}")

# ── Main loop ─────────────────────────────────────────────────────────────────
def tail_log():
    proc = subprocess.Popen(
        ["tail", "-F", "-n", "0", LOG_FILE],
        stdout=subprocess.PIPE,
        text=True
    )
    for line in proc.stdout:
        event = parse_event(line.strip())
        if event:
            print(f"[ALERT] {event['service']} from {event['src']}")
            send_to_ha(event)

if __name__ == "__main__":
    print(f"OpenCanary HA Notifier started — watching {LOG_FILE}")
    tail_log()
