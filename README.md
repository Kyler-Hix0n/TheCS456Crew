# README

### Critical Service Process: 
- firewall.py
-  non-deterministic crash, 5% chance for a crash to occur when accessing a website
-  lines 53-56 of firewall.py (updated for part 2)

### Heartbeat Monitor Process: 
- monitor.py
- triggers explicit failure alerts upon a crash.

### Adversarial Audit Script: 
- redPajama.py 
- A standalone script or utility designed to attempt heartbeat spoofing, message replay, or false liveness injection against the monitor.

### Role Distribution: 
- CONTRIBUTIONS.md 
- Includes individual contributions and link to the unlisted youtube video

# updates from part 2:
### Replica/Secondary Process:
- File: firewall.py
- Update: The firewall script was modified to accept command-line arguments for its role and port (e.g., python firewall.py SECONDARY 8002). It now includes its specific role in the UDP heartbeat (b"HEARTBEAT:PRIMARY" or b"HEARTBEAT:SECONDARY") so the monitor can accurately track which node is transmitting.
  
### State Sync/Checkpointing module:
- File: checkpointing.py
- Implementation: A checkpointing file that periodically exports the blacklist to a local JSON file so the state survives a crash.
- File: firewall.py
- Update: The firewall now uses command line arguments to determine if it is the primary or backup node, then updates the heartbeat payload to include its role, and uses the checkpointing module to load and save the blacklist.


### updated Monitor Failover Controller:
- File: monitor.py
- Update: The monitor now manages the automated failover. If it registers 3 consecutive missed heartbeats from the primary node, it utilizes Python's subprocess module to automatically spawn the secondary firewall instance on port 8002. It also verifies the role embedded in the heartbeats to prevent split-brain conflicts from delayed primary packets.


### adversarial Audit script:
- File: adversarial_audit.py
- Update: New audit script for Attack Scenario 2 (Checkpoint Poisoning). It waits for the primary to create server_state.json, then repeatedly overwrites it (every 0.5s, faster than the primary's checkpoint writes) with a well-formed but unauthorized blacklist that adds llamallama.com's IP (10.0.99.99) and a forged HMAC tag. Without signing, the secondary would load this poisoned state after failover and block llamallama.com. With the HMAC check in checkpointing.py, the forged checkpoint is rejected and llamallama.com stays reachable.
