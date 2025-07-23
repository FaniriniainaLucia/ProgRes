from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP
import threading
import random
import socket
import subprocess
import psutil

nat_table = {}
reverse_nat = {}
nfqueue = NetfilterQueue()
nf_thread = None

PUBLIC_IP = "10.0.0.1"

def generate_nat_port():
    return random.randint(40000, 60000)

def start_nat(lan_iface, wan_iface, public_ip):
    global PUBLIC_IP
    PUBLIC_IP = public_ip
    print(f"🟢 NAT Python lancé : {lan_iface} → {wan_iface} (IP WAN : {PUBLIC_IP})")

    # Activer le forwarding IP dynamiquement
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

    # Nettoyer les anciennes règles
    subprocess.call("iptables -F", shell=True)
    subprocess.call("iptables -t nat -F", shell=True)

    # Accepter le forwarding
    subprocess.call("iptables -P FORWARD ACCEPT", shell=True)

    # Rediriger tout le trafic vers NFQUEUE
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 1", shell=True)

    global nf_thread
    nf_thread = threading.Thread(target=run_nfqueue, daemon=True)
    nf_thread.start()

def stop_nat():
    nfqueue.unbind()

    # Désactiver l'IP forwarding
    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)

    # Supprimer les règles iptables
    subprocess.call("iptables -F", shell=True)
    subprocess.call("iptables -t nat -F", shell=True)
    subprocess.call("iptables -P FORWARD DROP", shell=True)

    print("🔴 NAT Python stoppé.")

def run_nfqueue():
    nfqueue.bind(1, process_packet)
    nfqueue.run()

def process_packet(pkt):
    scapy_pkt = IP(pkt.get_payload())

    if scapy_pkt.haslayer(TCP) or scapy_pkt.haslayer(UDP):
        proto = "TCP" if scapy_pkt.haslayer(TCP) else "UDP"
        layer = scapy_pkt[TCP] if proto == "TCP" else scapy_pkt[UDP]

        if is_private_ip(scapy_pkt[IP].src):  # Sortant
            nat_port = generate_nat_port()
            original_key = (scapy_pkt[IP].src, layer.sport, proto)
            nat_key = (PUBLIC_IP, nat_port, proto)

            nat_table[original_key] = nat_key
            reverse_nat[nat_key] = original_key

            scapy_pkt[IP].src = PUBLIC_IP
            layer.sport = nat_port
            del scapy_pkt[IP].chksum
            del layer.chksum

            pkt.set_payload(bytes(scapy_pkt))
            print(f"🔁 SNAT {original_key} → {nat_key}")

        elif scapy_pkt[IP].dst == PUBLIC_IP:  # Entrant
            nat_key = (scapy_pkt[IP].dst, layer.dport, proto)
            if nat_key in reverse_nat:
                original_key = reverse_nat[nat_key]
                scapy_pkt[IP].dst = original_key[0]
                layer.dport = original_key[1]
                del scapy_pkt[IP].chksum
                del layer.chksum
                pkt.set_payload(bytes(scapy_pkt))
                print(f"🔁 DNAT {nat_key} → {original_key}")
            else:
                print("❌ Paquet inconnu, rejeté")
                pkt.drop()
                return

    pkt.accept()

def is_private_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")

def get_iface_ip(iface_name):
    addrs = psutil.net_if_addrs().get(iface_name)
    for addr in addrs:
        if addr.family.name == "AF_INET":
            return addr.address
    return "0.0.0.0"

def get_nat_table():
    return dict(nat_table)
