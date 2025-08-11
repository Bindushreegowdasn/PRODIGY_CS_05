"""
Task-05: Network Packet Analyzer
Captures and analyzes network packets.
Displays source & destination IP addresses, protocols, and payload data.

⚠️ Use only on networks you own or have permission to monitor.
"""

from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process each captured packet
def packet_callback(packet):
    if IP in packet:  # Only process IP packets
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = ""
        src_port = ""
        dst_port = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = packet.proto

        print(f"[+] {src_ip}:{src_port} --> {dst_ip}:{dst_port} | Protocol: {protocol}")

        # Show payload if present
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"    Payload: {payload[:50]!r}")  # First 50 bytes
            except:
                pass
        print("-" * 60)

# Start sniffing
print("Starting Packet Capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
