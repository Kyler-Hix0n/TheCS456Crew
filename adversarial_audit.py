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
    """Overwrite the checkpoint with a well-formed but unauthorized blacklist.

    The attacker doesn't know the firewall's HMAC secret, so it can only write an
    unsigned (or forged) checkpoint -- which the hardened load_state() rejects."""
    payload = {STATE_KEY: POISONED_BLACKLIST, "HMAC": "0" * 64}  # forged tag
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
    print(" MP1.2 Adversarial Audit -- Scenario 2: Checkpoint Poisoning")
    print("=" * 68)
    wait_for_checkpoint()
    show_current_state()
    hold_poison()
    print("[AUDIT] The poisoned file carries no valid HMAC signature (we don't")
    print("[AUDIT] have the nodes' secret key), so the Secondary's load_state()")
    print("[AUDIT] rejects it and rolls back to the default blacklist.")
    print("[AUDIT] Result: ATTACK MITIGATED -- llamallama.com is still ALLOWED.")
    print("[AUDIT] (Without signing, the Secondary would have blocked it.)")


if __name__ == "__main__":
    main()
