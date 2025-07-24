# nat_engine.py - Version refactorisée et nettoyée

from scapy.all import (
    sniff, sendp, IP, TCP, UDP, Ether, get_if_hwaddr, get_if_addr,
    get_if_list, ARP, sr1, AsyncSniffer
)
import threading
import random
import subprocess
import time

from core.logger import get_logger

logger = get_logger("NAT")

# Tables NAT globales
nat_table = {}  # (src_ip, src_port, proto) -> (wan_ip, public_port)
reverse_nat_table = {}  # (wan_ip, public_port, proto) -> (src_ip, src_port)
used_ports = set()
lock = threading.Lock()

# Sniffers globaux
lan_sniffer = None
wan_sniffer = None

def get_free_port():
    """Obtient un port libre pour la translation NAT."""
    for _ in range(50000):
        port = random.randint(1024, 65535)
        if port not in used_ports:
            used_ports.add(port)
            return port
    raise RuntimeError("Aucun port libre trouvé pour NAT")

def check_interface_status(iface):
    """Vérifie si l'interface est active et configurée."""
    try:
        if iface not in get_if_list():
            logger.error(f"Interface {iface} n'existe pas")
            return False
        
        ip = get_if_addr(iface)
        if ip == "0.0.0.0":
            logger.warning(f"Interface {iface} n'a pas d'adresse IP configurée")
            return False
            
        logger.info(f"Interface {iface} : IP={ip}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de {iface}: {e}")
        return False

def get_lan_network(lan_ip):
    """Détermine le réseau LAN à partir de l'IP de l'interface (réseau /24)."""
    parts = lan_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"

def get_gateway_mac(wan_iface):
    """Obtient l'adresse MAC de la passerelle par défaut."""
    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        
        for line in result.stdout.split('\n'):
            if 'default via' in line and wan_iface in line:
                gateway_ip = line.split()[2]  # IP après "via"
                logger.info(f"Passerelle détectée: {gateway_ip}")
                
                # Requête ARP pour obtenir la MAC
                arp_resp = sr1(ARP(pdst=gateway_ip), timeout=2, verbose=0)
                if arp_resp:
                    logger.info(f"MAC passerelle: {arp_resp.hwsrc}")
                    return arp_resp.hwsrc
                break
        
        # Fallback: utiliser la MAC de l'interface
        logger.warning("Impossible d'obtenir la MAC de la passerelle")
        return get_if_hwaddr(wan_iface)
        
    except Exception as e:
        logger.warning(f"Erreur obtention MAC passerelle: {e}")
        return "ff:ff:ff:ff:ff:ff"

def create_nat_packet(packet, new_src_ip, new_sport, dest_mac, src_iface):
    """Crée un nouveau paquet avec translation NAT."""
    new_packet = packet.copy()
    
    # Modifier Ethernet
    new_packet[Ether].dst = dest_mac
    new_packet[Ether].src = get_if_hwaddr(src_iface)
    
    # Modifier IP
    new_packet[IP].src = new_src_ip
    new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
    
    # Modifier port source
    if new_packet.haslayer(TCP):
        new_packet[TCP].sport = new_sport
        del new_packet[TCP].chksum
    elif new_packet.haslayer(UDP):
        new_packet[UDP].sport = new_sport
        del new_packet[UDP].chksum
    
    # Supprimer checksum IP pour recalcul
    del new_packet[IP].chksum
    
    return new_packet

def handle_outgoing(packet, lan_iface, wan_iface, wan_ip, wan_mac, lan_network):
    """Traite les paquets sortants (LAN → WAN)."""
    try:
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        
        # Vérifier que le paquet vient du LAN et va vers l'extérieur
        if not ip.src.startswith(lan_network) or ip.dst.startswith(lan_network):
            return

        # Supporter TCP et UDP uniquement
        if ip.haslayer(TCP):
            proto, l4 = "TCP", ip[TCP]
        elif ip.haslayer(UDP):
            proto, l4 = "UDP", ip[UDP]
        else:
            return

        key = (ip.src, l4.sport, proto)
        logger.info(f"NAT sortant: {ip.src}:{l4.sport} → {ip.dst}:{l4.dport} ({proto})")

        # Gestion de la table NAT
        with lock:
            if key not in nat_table:
                public_port = get_free_port()
                nat_table[key] = (wan_ip, public_port)
                reverse_nat_table[(wan_ip, public_port, proto)] = key
                logger.info(f"Nouvelle entrée NAT: {ip.src}:{l4.sport} → {wan_ip}:{public_port}")
            else:
                public_port = nat_table[key][1]

        # Créer et envoyer le paquet modifié
        new_packet = create_nat_packet(packet, wan_ip, public_port, wan_mac, wan_iface)
        sendp(new_packet, iface=wan_iface, verbose=0)
        
    except Exception as e:
        logger.error(f"Erreur dans handle_outgoing: {e}")

def handle_incoming(packet, wan_iface, lan_iface, wan_ip):
    """Traite les paquets entrants (WAN → LAN)."""
    try:
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        
        # Vérifier que le paquet est destiné à notre IP WAN
        if ip.dst != wan_ip:
            return

        if ip.haslayer(TCP):
            proto, l4 = "TCP", ip[TCP]
        elif ip.haslayer(UDP):
            proto, l4 = "UDP", ip[UDP]
        else:
            return

        key = (wan_ip, l4.dport, proto)

        with lock:
            nat_entry = reverse_nat_table.get(key)

        if not nat_entry:
            return

        orig_ip, orig_port, _ = nat_entry
        logger.info(f"NAT entrant: {ip.src}:{l4.sport} → {orig_ip}:{orig_port} ({proto})")

        # Créer le paquet de retour
        new_packet = packet.copy()
        new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"  # Broadcast pour simplifier
        new_packet[Ether].src = get_if_hwaddr(lan_iface)
        new_packet[IP].dst = orig_ip
        new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
        
        if proto == "TCP":
            new_packet[TCP].dport = orig_port
            del new_packet[TCP].chksum
        else:
            new_packet[UDP].dport = orig_port
            del new_packet[UDP].chksum
        
        del new_packet[IP].chksum
        
        sendp(new_packet, iface=lan_iface, verbose=0)
        
    except Exception as e:
        logger.error(f"Erreur dans handle_incoming: {e}")

def start_nat(lan_iface, wan_iface):
    """Lance les sniffers NAT asynchrones."""
    global lan_sniffer, wan_sniffer

    # Vérifications des interfaces
    if not check_interface_status(lan_iface) or not check_interface_status(wan_iface):
        return False

    try:
        wan_ip = get_if_addr(wan_iface)
        lan_ip = get_if_addr(lan_iface)
        lan_network = get_lan_network(lan_ip)
        wan_mac = get_gateway_mac(wan_iface)

        logger.info(f"Configuration NAT: LAN={lan_iface} ({lan_ip}), WAN={wan_iface} ({wan_ip})")
        logger.info(f"Réseau LAN: {lan_network}, MAC passerelle: {wan_mac}")

    except Exception as e:
        logger.error(f"Erreur récupération interfaces: {e}")
        return False

    # Création des handlers
    def handle_lan(pkt):
        handle_outgoing(pkt, lan_iface, wan_iface, wan_ip, wan_mac, lan_network)

    def handle_wan(pkt):
        handle_incoming(pkt, wan_iface, lan_iface, wan_ip)

    try:
        # Démarrage des sniffers asynchrones
        lan_sniffer = AsyncSniffer(
            iface=lan_iface,
            prn=handle_lan,
            filter="ip and not arp",
            store=False
        )
        
        wan_sniffer = AsyncSniffer(
            iface=wan_iface,
            prn=handle_wan,
            filter=f"ip and dst host {wan_ip}",
            store=False
        )

        lan_sniffer.start()
        wan_sniffer.start()

        logger.info("✅ NAT démarré avec succès")
        return True

    except Exception as e:
        logger.error(f"Erreur démarrage NAT: {e}")
        return False

def stop_nat():
    """Arrête le NAT et nettoie les tables."""
    global nat_table, reverse_nat_table, used_ports, lan_sniffer, wan_sniffer

    logger.info("Arrêt du NAT...")

    # Arrêt des sniffers
    if lan_sniffer:
        lan_sniffer.stop()
        lan_sniffer = None

    if wan_sniffer:
        wan_sniffer.stop()
        wan_sniffer = None

    time.sleep(0.5)  # Attendre l'arrêt complet

    # Nettoyage des tables
    with lock:
        nat_table.clear()
        reverse_nat_table.clear()
        used_ports.clear()

    logger.info("✅ NAT arrêté et tables nettoyées")
    return True

def get_nat_stats():
    """Retourne les statistiques du NAT."""
    with lock:
        return {
            "active_connections": len(nat_table),
            "used_ports": len(used_ports)
        }
