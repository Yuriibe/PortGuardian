# port_watchdog.py
import psutil
import time
import dns.resolver
import json

SUSPICIOUS_IPS = {
    "discord.com": "discord.com",
    "ngrok.io": "ngrok.io",
    "pastebin.com": "pastebin.com",
    "raw.githubusercontent.com": "raw.githubusercontent.com"
}

with open("trusted_process.json", "r") as file:
    trusted_process = json.load(file)


def resolve_ips(domain) -> list:
    """
       Resolve IPs (A-Records) of a domain.

       param:
           domain (str): Domain: 'pastebin.com'

       Returns:
           list: list of ips as strings
       """
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [rdata.address for rdata in answers]
    except Exception as e:
        print(f"[!] DNS resolution failed for {domain}: {e}")
        return []


def populate_suspicious_ips(ip_domain_map) -> dict:
    """
    Takes a Dictionary of suspicious domains and add matching ips
    :param ip_domain_map: (dict)
    :return:
    """
    domain_to_label = {}
    # Create a reverse mapping of known domains (label) to expand
    for ip, label in list(ip_domain_map.items()):
        if not ip.replace(".", "").isdigit():  # crude check for domain vs IP
            domain_to_label[label] = ip
            del ip_domain_map[ip]

    # Resolve and add all IPs
    for label, domain in domain_to_label.items():
        for ip in resolve_ips(domain):
            print(f"[+] {label} → {ip}")
            ip_domain_map[ip] = label

    return ip_domain_map


print("\n🚨 Final Suspicious IPs:")
for ip, label in SUSPICIOUS_IPS.items():
    print(f"  → {ip} : {label}")

SUSPICIOUS_IPS = populate_suspicious_ips(SUSPICIOUS_IPS)


def monitor_connections():
    seen_connections = set()  # Set to keep track of already detected connections to avoid duplicate alerts
    print("🚨 Watching for suspicious outbound connections...\n")
    while True:
        for conn in psutil.net_connections(
                kind='inet'):  # Loop through all active internet (IPv4/IPv6) connections on the system
            if not conn.raddr:
                continue

            if conn.status != 'ESTABLISHED':
                continue

            remote_ip = conn.raddr.ip

            if remote_ip.startswith("127.") or remote_ip.startswith("::1"):
                continue

            key = (conn.pid, remote_ip, conn.status)

            if key in seen_connections:
                continue
            seen_connections.add(key)  # add detection to already seen detected connections

            if remote_ip in SUSPICIOUS_IPS:
                try:
                    proc = psutil.Process(conn.pid)  # get process info by PID
                    proc_name = proc.name()  # get name of process
                    if proc_name.lower() in trusted_process:  # skip if trusted process is detected
                        continue
                except:
                    proc_name = "Unknown"

                print(f"\n⚠️ Suspicious Connection Detected!")
                print(f"  → IP: {remote_ip}")
                print(f"  → Domain: {SUSPICIOUS_IPS[remote_ip]}")
                print(f"  → Process: {proc_name} (PID: {conn.pid})")
                print(f"  → Status: {conn.status}")
        time.sleep(0.03)


if __name__ == "__main__":
    monitor_connections()
