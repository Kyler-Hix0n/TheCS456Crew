## Courtney LaCroix: 
- created basic server.py file. Has a basic firewall (Blocked IP address) and a 5% chance to crash when accessing a website
- set up and recorded video for submission
  
### part 2:
- Updating Monitor.py and server.py
- Worked on getting the failover mechanism finished for early testing
- Architecture design diagram and redundancy explanation 
  
## Kyle James: 
- created the monitor.py file. Uses passive monitoring on port 8000 to track unidirectional heartbeats from the firewall agent, as well as added ANSI color-coded terminal interface to provide clear real-time tracking.
- created doc for team submssion
  
### part 2:
- words
  
## Kyler Hixon:
- created the redPajama.py file to take down the firewall
- split up the server code into a firewall and a separate server to keep the webpage running and the firewall running as a separate script (like a service you'd buy), and added an image to show when the blocked website was accessed by the wrong person. 
- implemented the spoofed heartbeat status to trick monitor into thinking the server is still protected.

### part 2:
- created adversarial_audit.py, which attacks the checkpointing trust boundary. It waits for the Primary to create server_state.json, reads the current blacklist, then keeps overwriting the file every 0.5s (faster than the Primary's 3s checkpoint) with a poisoned blacklist that adds llamallama.com's IP. When the Primary crashes and the Monitor fails over, the Secondary loads the poisoned file and blocks llamallama.com, since load_state() never checks creditability.


### Video Demo
- https://youtu.be/GqX8A49K10c
- NEW VIDEO WITH UPDATED ATTACKER https://youtu.be/2bhPfWA3cJo
