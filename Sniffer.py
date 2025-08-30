from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from datetime import datetime

def analyze_packet(packet):
    print("\n" + "="*60)
    print("Packet Captured at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_layer = packet.getlayer(DNS)
        query_name = dns_layer.qd.qname.decode('utf-8')
        print(f"DNS Query: {query_name}")

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            if payload.startswith("GET") or payload.startswith("POST") or payload.startswith("HEAD"):
                print("HTTP Request Detected:")
                print(payload.split("\r\n")[0])
                for line in payload.split("\r\n")[1:]:
                    if line == "":
                        break
                    print(" ", line)

            elif "Host:" in payload:
                print("HTTP Fragment Detected:")
                print(payload[:100])

            else:
                print("Raw Data:")
                print(payload[:100])

        except Exception as e:
            print("Could not decode payload:", e)

def start_sniffing(interface="enp0s3", packet_count=10):
    print(f"Sniffing on interface: {interface}")
    sniff(iface=interface, prn=analyze_packet, store=0, count=packet_count)

if __name__ == "__main__":
    start_sniffing(interface="enp0s3", packet_count=10)
