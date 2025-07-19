# nat_core.py
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP
import threading
import random
import socket

nat_table = {}
reverse_nat = {}
nfqueue = NetfilterQueue()
nf_thread = None

# IP publique de l’interface WAN (à modifier dynamiquement)
PUBLIC_IP = "10.0.0.1"

def generate_nat_port():
    return random.randint(40000, 60000)

# nat_core.py (extrait modifié)

def start_nat(lan_iface, wan_iface, public_ip):
    global PUBLIC_IP
    PUBLIC_IP = public_ip
    print(f"🟢 NAT Python lancé : {lan_iface} → {wan_iface} (IP WAN : {PUBLIC_IP})")

    # reste du code inchangé...


    # Rediriger TOUT le trafic dans NFQUEUE (on suppose tout passe par FORWARD)
    import subprocess
    subprocess.call("iptables -F", shell=True)
    subprocess.call("iptables -t nat -F", shell=True)
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 1", shell=True)

    global nf_thread
    nf_thread = threading.Thread(target=run_nfqueue, daemon=True)
    nf_thread.start()

def stop_nat():
    nfqueue.unbind()
    import subprocess
    subprocess.call("iptables -F", shell=True)
    subprocess.call("iptables -t nat -F", shell=True)
    print("🔴 NAT Python stoppé.")

def run_nfqueue():
    nfqueue.bind(1, process_packet)
    nfqueue.run()

def process_packet(pkt):
    scapy_pkt = IP(pkt.get_payload())

    if scapy_pkt.haslayer(TCP) or scapy_pkt.haslayer(UDP):
        proto = "TCP" if scapy_pkt.haslayer(TCP) else "UDP"
        layer = scapy_pkt[TCP] if proto == "TCP" else scapy_pkt[UDP]

        if is_private_ip(scapy_pkt[IP].src):  # Trafic sortant
            nat_port = generate_nat_port()
            original_key = (scapy_pkt[IP].src, layer.sport, proto)
            nat_key = (PUBLIC_IP, nat_port, proto)

            # Enregistrement dans la table NAT
            nat_table[original_key] = nat_key
            reverse_nat[nat_key] = original_key

            # Modification du paquet
            scapy_pkt[IP].src = PUBLIC_IP
            layer.sport = nat_port
            del scapy_pkt[IP].chksum
            del layer.chksum

            pkt.set_payload(bytes(scapy_pkt))
            print(f"🔁 SNAT {original_key} → {nat_key}")

        elif scapy_pkt[IP].dst == PUBLIC_IP:  # Trafic entrant
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
    import psutil
    addrs = psutil.net_if_addrs().get(iface_name)
    for addr in addrs:
        if addr.family.name == "AF_INET":
            return addr.address
    return "0.0.0.0"
    
def get_nat_table():
    return dict(nat_table)
