from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from datetime import datetime

def packet_info(packet):
    
    #Extract and print basic info from each packet

    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # ARP Packets - Layer 2
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        op = "Who has" if packet[ARP].op == 1 else "is-at"
        print(f"[{timestamp}] ARP  | {src_ip} -> {dst_ip} : {op}")
        return
    
    # IP Packets - Layer 3+
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # TCP
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Identify common app protocols on top of TCP
            if dport == 80 or sport == 80:
                protocol = "HTTP"
            elif dport == 21 or sport == 21:
                protocol = "FTP"
            elif dport == 443 or sport == 443:
                protocol = "HTTPS"
            else:
                protocol = "TCP"
            
            print(f"[{timestamp}] {protocol} | {src_ip}:{sport} -> {dst_ip}:{dport}")
        
        # UDP
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if dport == 53 or sport == 53:
                protocol = "DNS"
                # Try to show DNS query name
                if packet.haslayer(DNS) and packet[DNS].qd:
                    try:
                        qname = packet[DNS].qd.qname.decode()
                        print(f"[{timestamp}] DNS  | {src_ip} -> {dst_ip} : Query {qname}")
                        return
                    except:
                        pass
            else:
                protocol = "UDP"
            
            print(f"[{timestamp}] {protocol} | {src_ip}:{sport} -> {dst_ip}:{dport}")
        
        # ICMP
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            print(f"[{timestamp}] ICMP | {src_ip} -> {dst_ip} : Type {icmp_type}")
        
        # Other IP protocols
        else:
            proto_num = packet[IP].proto
            print(f"[{timestamp}] IP:{proto_num} | {src_ip} -> {dst_ip}")

def main():
    print("="*70)
    print("Wireshark-style Sniffer Started... Press Ctrl+C to stop")
    print("Protocols: TCP, UDP, ICMP, ARP, DNS, HTTP, FTP, HTTPS")
    print("="*70)
    sniff(prn=packet_info, store=False)

if __name__ == "__main__":
    main()