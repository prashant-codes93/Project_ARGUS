"""
Reference collector agent (Layer 1 - example only, not imported by the app).

This is a template for what a real collector looks like: a separate
process that watches a data source and POSTs each event to the backend
API. Replace read_events() with real log tailing / API polling / syslog
listening logic, and this becomes a deployable collector.

Run standalone:
    python collectors/sample_agent.py
"""

import os
import time
import requests

API_URL = os.getenv("ARGUS_API_URL", "http://localhost:5000/api/events")
API_KEY = os.getenv("API_KEY", "dev-api-key")


def read_events():
    """Placeholder source of events. Swap for a real log tail / API poll."""
    yield {"type": "login", "user": "demo-user", "src_ip": "10.0.0.5", "severity": "low"}


def send_event(event: dict) -> None:
    resp = requests.post(
        API_URL,
        json=event,
        headers={"X-API-Key": API_KEY, "X-Source": "sample-agent"},
        timeout=5,
    )
    resp.raise_for_status()


if __name__ == "__main__":
    for evt in read_events():
        send_event(evt)
        time.sleep(1)
