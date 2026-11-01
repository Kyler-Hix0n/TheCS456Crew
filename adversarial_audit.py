"""
adversarial_audit.py  --  Attack Scenario 2 for MP1.1 Fault Detection

Audits the TRUST BOUNDARY of the Passive Redundancy (Warm Standby +
Checkpointing) design. The Primary firewall periodically writes its BLACKLIST
to a plaintext file (server_state.json) via checkpointing.py. That file is:

    - unauthenticated  (no signature / HMAC / integrity check)
    - unencrypted      (plain JSON on local disk)
    - trusted blindly  (the Secondary loads it verbatim on failover)

load_state() in checkpointing.py only guards against JSON *corruption*
(a decode error). It does NOT verify that the contents are legitimate. So a
well-formed-but-poisoned file passes every check and is loaded as gospel.

This script demonstrates the integrity gap: an attacker who can write to the
checkpoint file controls the Secondary's entire policy after failover. We use
that to make the Secondary block a site that was never supposed to be blocked
(llamallama.com), i.e. a self-inflicted denial of service that survives a crash.

Scenario (all local, your own machine):
    1. Start the Primary:     python firewall.py PRIMARY 8001
       (checkpointing.py begins writing server_state.json every few seconds)
    2. Run this audit:        python adversarial_audit.py
       (waits for the file, then overwrites it with a poisoned blacklist)
    3. Crash / kill the Primary. The Monitor spawns the Secondary on 8002.
    4. The Secondary calls load_state(), loads the POISONED blacklist, and
       now blocks llamallama.com even though the Primary never did.

Fix (what the write-up should recommend): sign the checkpoint (e.g. HMAC with a
key the attacker can't read), restrict file permissions, and have load_state()
reject any state that fails integrity verification instead of trusting it.
"""
import json
import os
import time

# Must match STATE_FILE in checkpointing.py.
CHECKPOINT_FILE = "server_state.json"
# Must match the key load_state() reads in checkpointing.py.
STATE_KEY = "BLACKLIST"

# The IP that llamallama.com resolves to in server.py's DNS_RECORDS. Poisoning
# the blacklist with it means the Secondary will issue a BLOCK verdict for
# llamallama.com after failover. (The firewall matches on IP.)
LLAMALLAMA_IP = "10.0.99.99"

# A well-formed blacklist that the victim's load_state() will accept happily.
POISONED_BLACKLIST = [
    "10.0.5.50",
    "192.168.1.99",
    "172.16.0.4",
    LLAMALLAMA_IP,        # <-- the injected, unauthorized entry
]

POLL_INTERVAL = 1.0
# The Primary rewrites the checkpoint every few seconds (checkpointing.py), so a
# one-shot poison gets overwritten before failover unless the crash is instant.
# We re-poison on a tight loop to keep the malicious state on disk until the
# Primary dies and the Secondary loads it.
REPOISON_INTERVAL = 0.5


def wait_for_checkpoint():
    """Block until the Primary has created the checkpoint file at least once."""
    print(f"[AUDIT] Waiting for the Primary to create '{CHECKPOINT_FILE}'...")
    while not os.path.exists(CHECKPOINT_FILE):
        time.sleep(POLL_INTERVAL)
    print(f"[AUDIT] Found '{CHECKPOINT_FILE}'. Trust boundary is now reachable.")


def show_current_state():
    """Print whatever the Primary currently has on disk (pre-attack)."""
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            data = json.load(f)
        print(f"[AUDIT] Legitimate blacklist on disk: {data.get(STATE_KEY)}")
    except (json.JSONDecodeError, OSError) as e:
        print(f"[AUDIT] Could not read current state ({e}); proceeding anyway.")


def poison_checkpoint():
    """Overwrite the checkpoint with a well-formed but unauthorized blacklist."""
    payload = {STATE_KEY: POISONED_BLACKLIST}
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(payload, f)


def hold_poison():
    """Keep the poisoned state on disk until interrupted.

    The Primary's state_saver_daemon rewrites the checkpoint every few seconds,
    so a single write would be reverted before failover. We re-write faster than
    the Primary does, so whenever the Primary dies the last-written file on disk
    is ours -- and that is exactly what the Secondary loads via load_state()."""
    print(f"[AUDIT] 💉 Poisoning '{CHECKPOINT_FILE}' and holding it...")
    print(f"[AUDIT] Injected entry: {LLAMALLAMA_IP} (llamallama.com)")
    print(f"[AUDIT] Blacklist the Secondary will load: {POISONED_BLACKLIST}")
    print("[AUDIT] Re-poisoning to outrace the Primary's checkpoint writes.")
    print("[AUDIT] Now crash/kill the Primary; leave this running until failover.")
    print("[AUDIT] Press Ctrl+C once the Secondary is up to stop re-poisoning.")
    try:
        while True:
            poison_checkpoint()
            time.sleep(REPOISON_INTERVAL)
    except KeyboardInterrupt:
        print("\n[AUDIT] Stopped re-poisoning.")


def main():
    print("=" * 68)
    print(" MP1.1 Adversarial Audit -- Scenario 2: Checkpoint Poisoning")
    print("=" * 68)
    wait_for_checkpoint()
    show_current_state()
    hold_poison()
    print("[AUDIT] If the Secondary came up, llamallama.com is now BLOCKED.")
    print("[AUDIT] Takeaway: unauthenticated local state == single point of")
    print("[AUDIT] compromise for passive redundancy. Sign & verify the file.")


if __name__ == "__main__":
    main()
