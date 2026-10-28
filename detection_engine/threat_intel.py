"""
Threat intelligence layer (Layer 4).

TODO for the dev team: KNOWN_MALICIOUS_IPS below is a placeholder so the
pipeline is testable offline. Replace check_threat_intel() with a real
call to a feed (e.g. AbuseIPDB, OTX, a commercial feed) using
THREAT_INTELLIGENCE_API_KEY from config, and add caching - don't call an
external API on every single event in production.
"""

import os

THREAT_INTEL_API_KEY = os.getenv("THREAT_INTELLIGENCE_API_KEY", "")

# Placeholder IOC list - swap for a real feed lookup.
KNOWN_MALICIOUS_IPS = {"45.83.64.1", "185.220.101.1", "192.0.2.55"}


def check_threat_intel(event: dict) -> int:
    """Returns 1 if the event's source or dest IP matches a known-bad IOC."""
    hit = event["source_ip"] in KNOWN_MALICIOUS_IPS or event["dest_ip"] in KNOWN_MALICIOUS_IPS
    return 1 if hit else 0
