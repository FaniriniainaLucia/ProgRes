from scapy.all import sniff, AsyncSniffer, IP, TCP, UDP, send
import logging
import ipaddress
import random

# Réduction des logs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Interfaces réseau
sniff_iface = "wlp0s20f3"           # LAN
out_iface = "enx02da2de90c04"       # WAN
real_source_ip = "192.168.45.2"     # IP NAT publique

# Sous-réseau local
local_network = ipaddress.IPv4Network("10.42.0.0/24")

# Tables NAT
nat_table = {}        # (lan_ip, lan_port, dst_ip, dst_port, proto) → nat_port
reverse_nat = {}      # (dst_ip, nat_port, proto) → (lan_ip, lan_port)
used_nat_ports = set()

def get_free_nat_port():
    while True:
        port = random.randint(10000, 60000)
        if port not in used_nat_ports:
            used_nat_ports.add(port)
            return port

def is_external(ip):
    try:
        return ipaddress.IPv4Address(ip) not in local_network
    except ValueError:
        return True

# === Paquets sortants (LAN → WAN) ===
def process_packet(pkt):
    if IP not in pkt:
        return
    ip_pkt = pkt[IP]

    proto = None
    l4 = None
    if pkt.haslayer(TCP):
        proto = "TCP"
        l4 = pkt[TCP]
    elif pkt.haslayer(UDP):
        proto = "UDP"
        l4 = pkt[UDP]
    else:
        return

    if not is_external(ip_pkt.dst):
        return

    nat_port = get_free_nat_port()
    nat_table[(ip_pkt.src, l4.sport, ip_pkt.dst, l4.dport, proto)] = nat_port
    reverse_nat[(ip_pkt.dst, nat_port, proto)] = (ip_pkt.src, l4.sport)

    # Affichage
    flag_str = ""
    if proto == "TCP":
        flags = l4.flags
        if flags & 0x02: flag_str += "SYN "
        if flags & 0x10: flag_str += "ACK "
        if flags & 0x01: flag_str += "FIN "
    print(f"[{proto}] {ip_pkt.src}:{l4.sport} → {ip_pkt.dst}:{l4.dport} [{flag_str.strip()}]")

    print(f"[+] NAT: {ip_pkt.src}:{l4.sport} → {real_source_ip}:{nat_port} ({proto})")

    # Construction du paquet NATé
    fwd_pkt = pkt.copy()
    fwd_pkt[IP].src = real_source_ip
    fwd_pkt[l4.name].sport = nat_port
    del fwd_pkt[IP].len, fwd_pkt[IP].chksum, fwd_pkt[l4.name].chksum

    try:
        send(fwd_pkt, verbose=0)
    except Exception as e:
        print(f"[!] Erreur d'envoi: {e}")

# === Paquets de retour (WAN → LAN) ===
def start_return_sniffer():
    def handle_response(pkt):
        if IP not in pkt:
            return
        ip_pkt = pkt[IP]

        # On ne traite que les paquets qui reviennent vers notre IP publique
        if ip_pkt.dst != real_source_ip:
            return

        # Identifier le protocole et couche 4
        proto = None
        l4 = None
        if pkt.haslayer(TCP):
            proto = "TCP"
            l4 = pkt[TCP]
        elif pkt.haslayer(UDP):
            proto = "UDP"
            l4 = pkt[UDP]
        else:
            return  # Ignore les autres types

        key = (ip_pkt.dst, l4.dport, proto)
        print(f"[↩] {proto} {ip_pkt.src}:{l4.sport} → {ip_pkt.dst}:{l4.dport}")

        if key not in reverse_nat:
            print(f"[x] ❌ Pas de correspondance NAT pour {key}")
            print(f"[debug] Clés reverse_nat connues : {list(reverse_nat.keys())}")
            return

        # Correspondance trouvée
        lan_ip, lan_port = reverse_nat[key]
        print(f"[=] ✅ Correspondance NAT trouvée : {ip_pkt.src}:{l4.sport} → {lan_ip}:{lan_port} ({proto})")


    return AsyncSniffer(iface=out_iface, prn=handle_response, filter="ip", store=0)

# === Lancement ===
if __name__ == "__main__":
    print(f"[*] Démarrage du NAT entre {sniff_iface} (LAN) et {out_iface} (Internet)")

    sniffer = start_return_sniffer()
    sniffer.start()

    try:
        sniff(iface=sniff_iface, prn=process_packet, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé.")
    finally:
        sniffer.stop()
