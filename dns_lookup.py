# dns_lookup.py
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSRR
import datetime
import threading

# Global cache of IP to domain lookups
ip_to_domain = {}

def process_dns(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
            domain = packet[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            for i in range(packet[DNS].ancount):
                ans = packet[DNS].an[i]
                if isinstance(ans, DNSRR) and ans.type == 1:  # A record
                    ip = ans.rdata
                    ip_to_domain[ip] = {
                        "domain": domain,
                        "timestamp": datetime.datetime.now()
                    }
                    print(f"[DNS] {domain} → {ip}")
    except Exception as e:
        print(f"[⚠️ DNS Error] {e}")

def get_ip_to_domain():
    return ip_to_domain
def start_dns_sniffer():
    sniff(filter="udp port 53", prn=process_dns, store=False)

# Start in background automatically when imported
threading.Thread(target=start_dns_sniffer, daemon=True).start()
