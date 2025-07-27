#!/usr/bin/env python3
import argparse
import logging
import random
import threading
import time
from ipaddress import ip_network, ip_address,IPv4Network
import psutil

from scapy.all import (
    AsyncSniffer,
    IP, TCP, UDP, ICMP,
    send,
    get_if_list, get_if_addr
)

# ——————————————————————————————————————————————
# 1) Logging
# ——————————————————————————————————————————————
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("nat.log"), logging.StreamHandler()]
)
logger = logging.getLogger("nat")

def get_network_from_iface(iface):
    try:
        addrs = psutil.net_if_addrs().get(iface)
        if not addrs:
            raise ValueError(f"Aucune adresse trouvée pour l'interface {iface}")
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
                netmask = addr.netmask
                network = IPv4Network(f"{ip}/{netmask}", strict=False)
                logger.info(f"Détection automatique du réseau LAN: {ip}/{netmask} -> {network}")
                return network
        raise ValueError(f"Aucune adresse IPv4 valide trouvée sur l'interface {iface}")
    except Exception:
        logger.exception(f"Erreur lors de la détection du réseau de l'interface {iface}")
        raise

# ——————————————————————————————————————————————
# 2) Parse des arguments
# ——————————————————————————————————————————————
try:
    parser = argparse.ArgumentParser(
        description="NAT IP simple couche 3 (sans IPv6) avec AsyncSniffer"
    )
    parser.add_argument("--lan-iface", help="Interface LAN")
    parser.add_argument("--wan-iface", help="Interface WAN")
    parser.add_argument("--lan-net", help="Réseau LAN (ex. 192.168.1.0/24)")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout des entrées NAT (sec)")
    args = parser.parse_args()

    if not args.lan_iface or not args.wan_iface:
        ifaces = get_if_list()
        print("Interfaces disponibles :")
        for idx, iface in enumerate(ifaces):
            print(f" [{idx}] {iface} (IP: {get_if_addr(iface)})")
        if not args.lan_iface:
            idx = int(input("Sélectionne l'index de l'interface LAN : "))
            args.lan_iface = ifaces[idx]
        if not args.wan_iface:
            idx = int(input("Sélectionne l'index de l'interface WAN : "))
            args.wan_iface = ifaces[idx]

    LAN_IFACE = args.lan_iface
    WAN_IFACE = args.wan_iface
    WAN_IP = ip_address(get_if_addr(WAN_IFACE))
    if args.lan_net:
        LAN_NET = ip_network(args.lan_net)
    else:
        LAN_NET = get_network_from_iface(args.lan_iface)
    TTL = args.timeout

    print(f"Interface LAN   : {LAN_IFACE} -> IP: {get_if_addr(LAN_IFACE)}")
    print(f"Réseau LAN      : {LAN_NET}")
    print(f"Interface WAN   : {WAN_IFACE} -> IP: {WAN_IP}")
    print(f"Timeout NAT     : {TTL} secondes")
except Exception:
    logger.exception("Erreur lors de la configuration initiale.")
    exit(1)

# ——————————————————————————————————————————————
# 3) Tables NAT
# ——————————————————————————————————————————————
nat_table = {}
reverse_nat = {}
timestamps = {}

# ——————————————————————————————————————————————
# 4) Obtenir un port libre
# ——————————————————————————————————————————————
def get_free_port():
    try:
        while True:
            p = random.randint(1025, 65535)
            if all(v[1] != p for v in nat_table.values()):
                return p
    except Exception:
        logger.exception("Erreur dans get_free_port()")

# ——————————————————————————————————————————————
# 5) Nettoyage périodique
# ——————————————————————————————————————————————
def cleaner():
    try:
        while True:
            now = time.time()
            expired = [k for k, t in timestamps.items() if now - t > TTL]
            for k in expired:
                w = nat_table.pop(k, None)
                if w:
                    reverse_nat.pop(w, None)
                    logger.info(f"Timeout NAT supprimé : {k} -> {w}")
                timestamps.pop(k, None)
            time.sleep(TTL / 2)
    except Exception:
        logger.exception("Erreur dans le thread cleaner()")

threading.Thread(target=cleaner, daemon=True).start()

# ——————————————————————————————————————————————
# 6) Traitement des paquets LAN (SNAT)
# ——————————————————————————————————————————————
def handle_lan(pkt):
    try:
        if not pkt.haslayer(IP): return
        ip = pkt[IP]
        logger.warning(f"Paquet LAN sniffé {(ip.dst)}")
        if ip.dst in LAN_NET: return

        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP) or pkt.getlayer(ICMP)
        sport = getattr(l4, "sport", None)
        if sport is None: return

        key = (ip.src, sport)
        timestamps[key] = time.time()

        if key in nat_table:
            wtuple = nat_table[key]
        else:
            p = get_free_port()
            wtuple = (str(WAN_IP), p)
            nat_table[key] = wtuple
            reverse_nat[wtuple] = key
            logger.info(f"Nouveau NAT : {key} -> {wtuple}")

        new = pkt.copy()
        new[IP].src = wtuple[0]
        if hasattr(new.getlayer(l4.name), "sport"):
            new.getlayer(l4.name).sport = wtuple[1]

        del new[IP].chksum
        if new.haslayer(TCP): del new[TCP].chksum
        if new.haslayer(UDP): del new[UDP].chksum
        if new.haslayer(ICMP): del new[ICMP].chksum

        send(new, iface=WAN_IFACE, verbose=False)
        proto = {1:'ICMP', 6:'TCP',17:'UDP'}.get(new.proto, str(new.proto))
        flags = getattr(new.getlayer(TCP), 'flags', '')
        logger.info(f"SNAT {ip.src}:{sport} -> {new[IP].src}:{wtuple[1]} (proto={proto}{' flags='+str(flags) if flags else ''})")

    except Exception:
        logger.exception("Erreur dans handle_lan()")

# ——————————————————————————————————————————————
# 7) Traitement des paquets WAN (DNAT)
# ——————————————————————————————————————————————
def handle_wan(pkt):
    try:
        if not pkt.haslayer(IP): return
        ip = pkt[IP]
        if ip.dst != str(WAN_IP): return

        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP) or pkt.getlayer(ICMP)
        dport = getattr(l4, 'dport', None)
        if dport is None: return

        rev = reverse_nat.get((str(WAN_IP), dport))
        if not rev:
            logger.warning(f"No mapping pour {(ip.dst, dport)}")
            return

        new = pkt.copy()
        new[IP].dst = rev[0]
        if hasattr(new.getlayer(l4.name), 'dport'):
            new.getlayer(l4.name).dport = rev[1]

        del new[IP].chksum
        if new.haslayer(TCP): del new[TCP].chksum
        if new.haslayer(UDP): del new[UDP].chksum
        if new.haslayer(ICMP): del new[ICMP].chksum

        send(new, iface=LAN_IFACE, verbose=False)
        proto = {1:'ICMP',6:'TCP',17:'UDP'}.get(new.proto, str(new.proto))
        flags = getattr(new.getlayer(TCP), 'flags', '')
        logger.info(f"DNAT {ip.src}:{l4.sport} -> {new[IP].dst}:{rev[1]} (proto={proto}{' flags='+str(flags) if flags else ''})")
    except Exception:
        logger.exception("Erreur dans handle_wan()")


# ——————————————————————————————————————————————
# 8) Démarrage
# ——————————————————————————————————————————————
if __name__ == "__main__":
    try:
        logger.info(f"LAN={LAN_IFACE}({LAN_NET}), WAN={WAN_IFACE}({WAN_IP})")
        lan_sniffer = AsyncSniffer(iface=LAN_IFACE, prn=handle_lan, filter="ip", store=False)
        wan_sniffer = AsyncSniffer(iface=WAN_IFACE, prn=handle_wan, filter="ip", store=False)

        lan_sniffer.start()
        wan_sniffer.start()
        logger.info("Sniffers démarrés (Ctrl+C pour stop)")

        lan_sniffer.join()
        wan_sniffer.join()
    except KeyboardInterrupt:
        logger.info("Arrêt en cours…")
        lan_sniffer.stop()
        wan_sniffer.stop()
        logger.info("Terminé.")
    except Exception:
        logger.exception("Erreur critique dans le bloc main()")
