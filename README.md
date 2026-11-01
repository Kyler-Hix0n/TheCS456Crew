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


### updated Monitor Failover Controller:
- File: monitor.py
- Update: The monitor now manages the automated failover. If it registers 3 consecutive missed heartbeats from the primary node, it utilizes Python's subprocess module to automatically spawn the secondary firewall instance on port 8002. It also verifies the role embedded in the heartbeats to prevent split-brain conflicts from delayed primary packets.

### adversarial Audit script:
