### This module periodically snapshots its operational state (the active blocklist) to a local file, ensuring the internal state survives a process crash.
###
### MITIGATION (Attack Scenario 2 - Checkpoint Poisoning):
### Every checkpoint is signed with an HMAC-SHA256 tag computed from a secret
### shared only by the firewall nodes. On boot, load_state() recomputes the tag
### and rejects the file if it is missing or doesn't match. A tampered checkpoint
### (e.g. from adversarial_audit.py) is discarded and the node rolls back to the
### known-good DEFAULT_BLACKLIST, so llamallama.com stays reachable.

import hashlib
import hmac
import json
import os
import time

STATE_FILE = "server_state.json"
DEFAULT_BLACKLIST = ["10.0.5.50", "192.168.1.99", "172.16.0.4"]

# Shared secret between the Primary and Secondary firewall nodes. In a real
# deployment this would come from a secrets manager / protected key store that
# the attacker cannot read; here it can be overridden via an environment var.
SECRET_KEY = os.environ.get("CHECKPOINT_SECRET", "vulcan-firewall-checkpoint-key").encode()


def _sign(blacklist):
    """Compute an HMAC-SHA256 tag over a canonical encoding of the blacklist."""
    message = json.dumps(blacklist, sort_keys=True).encode()
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()


def load_state():
    """The standby node loads the most recent checkpoint upon boot,
    but only if its HMAC signature verifies."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            blacklist = state.get("BLACKLIST")
            tag = state.get("HMAC", "")
            if isinstance(blacklist, list) and hmac.compare_digest(_sign(blacklist), tag):
                print(f"[CHECKPOINT] ✅ Signature verified. Loaded blacklist: {blacklist}")
                return blacklist
            print("[CHECKPOINT] 🚨 INTEGRITY CHECK FAILED: checkpoint is unsigned or tampered with!")
            print("[CHECKPOINT] Rejecting it and rolling back to the known-good default blacklist.")
        except (json.JSONDecodeError, OSError, AttributeError):
            print("[CHECKPOINT] ⚠️ Checkpoint unreadable; using default blacklist.")
    return DEFAULT_BLACKLIST.copy()


def state_saver_daemon(blacklist_ref, interval=3.0):
    """The primary node periodically snapshots its operational state (signed) to shared storage."""
    while True:
        snapshot = list(blacklist_ref)
        with open(STATE_FILE, "w") as f:
            json.dump({"BLACKLIST": snapshot, "HMAC": _sign(snapshot)}, f)
        time.sleep(interval)
