import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    """Callback function executed on every intercepted packet."""
    # Ensure the packet has an IP layer (Network Layer / Layer 3)
    if not packet.haslayer(IP):
        return

    # Extract Layer 3 (IP) details
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    ip_proto = packet[IP].proto
    packet_len = len(packet)

    protocol_name = "UNKNOWN"
    src_port = "-"
    dst_port = "-"

    # Inspect Layer 4 (Transport Layer)
    if packet.haslayer(TCP):
        protocol_name = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol_name = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol_name = "ICMP"

    # Display the network header details
    print("=" * 60)
    print(f"Protocol : {protocol_name} (Proto ID: {ip_proto})")
    print(f"Source   : {src_ip}:{src_port}")
    print(f"Dest     : {dst_ip}:{dst_port}")
    print(f"Length   : {packet_len} bytes")

    # Inspect Layer 7 (Application Payload) if present
    if packet.haslayer(Raw):
        payload_bytes = packet[Raw].load
        # Convert printable bytes to readable text; replace unprintable bytes with '.'
        printable_ascii = "".join(
            chr(byte) if 32 <= byte <= 126 else "." for byte in payload_bytes[:64]
        )
        print(f"Payload  : {printable_ascii} ... [{len(payload_bytes)} bytes total]")
    else:
        print("Payload  : [No raw payload present]")


def main():
    print("[*] Starting packet capture...")
    print("[*] Listening on all active interfaces (Ctrl+C to stop)...")

    try:
        # sniff() captures packets live:
        # - prn: calls analyze_packet() on every received packet
        # - store=False: drops packets from RAM after analyzing (prevents memory leaks)
        # - count=30: captures 30 packets then exits (remove count to run continuously)
        sniff(prn=analyze_packet, store=False, count=30)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print(
            "\n[!] Error: Raw packet capture requires elevated root/administrator privileges."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()