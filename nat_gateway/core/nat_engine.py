# nat_engine_v2.py - Version refactorisée avec ARP et filtres protocoles

from scapy.all import (
    sniff, sendp, IP, TCP, UDP, ICMP, Ether, get_if_hwaddr, get_if_addr,
    get_if_list, ARP, sr1, AsyncSniffer, conf
)
import threading
import random
import time
import psutil
from collections import defaultdict

from core.logger import get_logger

logger = get_logger("NAT")

# Tables NAT globales
nat_table = {}  # (src_ip, src_port, proto) -> (wan_ip, public_port)
reverse_nat_table = {}  # (wan_ip, public_port, proto) -> (src_ip, src_port)
arp_cache = {}  # ip -> mac_address
used_ports = set()
lock = threading.Lock()

# Configuration protocoles supportés
SUPPORTED_PROTOCOLS = {
    'TCP': {'layer': TCP, 'has_ports': True, 'enabled': False},
    'UDP': {'layer': UDP, 'has_ports': True, 'enabled': False}, 
    'ICMP': {'layer': ICMP, 'has_ports': False, 'enabled': False},
    'ALL': {'layer': None, 'has_ports': False, 'enabled': False}  # Tous les protocoles
}

# Statistiques
nat_stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'packets_by_protocol': defaultdict(int),
    'bytes_by_protocol': defaultdict(int),
    'start_time': None
}

# Sniffers globaux
lan_sniffer = None
wan_sniffer = None

def get_protocol_config():
    """Retourne la configuration actuelle des protocoles."""
    return SUPPORTED_PROTOCOLS.copy()

def set_protocol_enabled(protocol, enabled):
    """Active/désactive un protocole."""
    if protocol in SUPPORTED_PROTOCOLS:
        SUPPORTED_PROTOCOLS[protocol]['enabled'] = enabled
        logger.info(f"Protocole {protocol}: {'activé' if enabled else 'désactivé'}")
        return True
    return False

def get_enabled_protocols():
    """Retourne la liste des protocoles activés."""
    return [proto for proto, config in SUPPORTED_PROTOCOLS.items() if config['enabled']]

def reset_protocol_config():
    """Remet à zéro la configuration des protocoles."""
    for protocol in SUPPORTED_PROTOCOLS:
        SUPPORTED_PROTOCOLS[protocol]['enabled'] = False

def get_free_port():
    """Obtient un port libre pour la translation NAT."""
    for _ in range(50000):
        port = random.randint(1024, 65535)
        if port not in used_ports:
            used_ports.add(port)
            return port
    raise RuntimeError("Aucun port libre trouvé pour NAT")

def update_arp_cache(ip, mac):
    """Met à jour le cache ARP."""
    with lock:
        arp_cache[ip] = mac
        logger.debug(f"ARP Cache mis à jour: {ip} -> {mac}")

def get_mac_from_arp_cache(ip):
    """Récupère une MAC depuis le cache ARP."""
    with lock:
        return arp_cache.get(ip)

def resolve_mac_address(ip, iface):
    """Résout l'adresse MAC d'une IP de manière cross-platform."""
    # Vérifier d'abord le cache
    cached_mac = get_mac_from_arp_cache(ip)
    if cached_mac:
        return cached_mac
    
    try:
        # Utiliser psutil pour obtenir les infos réseau
        net_if_addrs = psutil.net_if_addrs()
        
        # Vérifier si c'est une IP locale (même interface)
        if iface in net_if_addrs:
            for addr in net_if_addrs[iface]:
                if addr.family.name == 'AF_INET' and addr.address == ip:
                    # C'est l'IP de notre interface
                    try:
                        mac = get_if_hwaddr(iface)
                        update_arp_cache(ip, mac)
                        return mac
                    except:
                        pass
        
        # Requête ARP pour les autres IPs
        logger.debug(f"Résolution ARP pour {ip}")
        arp_resp = sr1(ARP(pdst=ip), timeout=2, verbose=0, iface=iface)
        if arp_resp and arp_resp.haslayer(ARP):
            mac_addr = arp_resp.hwsrc
            update_arp_cache(ip, mac_addr)
            logger.info(f"MAC résolue pour {ip}: {mac_addr}")
            return mac_addr
        
        # Fallback: utiliser la table ARP système via psutil
        return get_system_arp_entry(ip)
        
    except Exception as e:
        logger.warning(f"Impossible de résoudre MAC pour {ip}: {e}")
        return "ff:ff:ff:ff:ff:ff"  # Broadcast fallback

def get_system_arp_entry(ip):
    """Récupère une entrée ARP depuis la table système."""
    try:
        # Utiliser psutil pour lire les connexions réseau
        # Note: psutil n'a pas d'API ARP directe, mais on peut parser /proc/net/arp sur Linux
        import os
        if os.name == 'posix':  # Linux/Unix
            try:
                with open('/proc/net/arp', 'r') as f:
                    for line in f.readlines()[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00':
                                update_arp_cache(ip, mac)
                                return mac
            except:
                pass
        
        # Pour Windows et autres OS, utiliser une approche différente
        return None
        
    except Exception as e:
        logger.debug(f"Erreur lecture table ARP système: {e}")
        return None

def get_gateway_info(wan_iface):
    """Obtient les informations de la passerelle par défaut (IP + MAC)."""
    try:
        import netifaces
        
        gws = netifaces.gateways()
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            gateway_ip, iface = gws['default'][netifaces.AF_INET]
            if iface == wan_iface:
                mac = resolve_mac_address(gateway_ip, wan_iface)
                if mac and mac != "ff:ff:ff:ff:ff:ff":
                    logger.info(f"Passerelle détectée: {gateway_ip} -> {mac}")
                    return gateway_ip, mac
                else:
                    logger.warning(f"MAC non résolue pour {gateway_ip}, fallback sur MAC interface WAN")
            else:
                logger.warning(f"La passerelle par défaut {gateway_ip} ne passe pas par {wan_iface}")
        
        # Fallback : utiliser MAC de l'interface
        try:
            wan_mac = get_if_hwaddr(wan_iface)
            logger.warning("Utilisation de la MAC de l'interface WAN comme fallback")
            return None, wan_mac
        except:
            return None, "ff:ff:ff:ff:ff:ff"
            
    except Exception as e:
        logger.error(f"Erreur obtention passerelle: {e}")
        return None, "ff:ff:ff:ff:ff:ff"


def check_interface_status(iface):
    """Vérifie si l'interface est active et configurée."""
    try:
        if iface not in get_if_list():
            logger.error(f"Interface {iface} n'existe pas")
            return False
        
        # Utiliser psutil pour vérifier le statut
        if_stats = psutil.net_if_stats().get(iface)
        if not if_stats or not if_stats.isup:
            logger.error(f"Interface {iface} n'est pas active")
            return False
        
        ip = get_if_addr(iface)
        if ip == "0.0.0.0":
            logger.warning(f"Interface {iface} n'a pas d'adresse IP configurée")
            return False
            
        logger.info(f"Interface {iface} : IP={ip}, Status=UP")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de {iface}: {e}")
        return False

def get_lan_network(lan_ip):
    """Détermine le réseau LAN à partir de l'IP de l'interface."""
    parts = lan_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"

def should_process_packet(packet):
    """Détermine si un paquet doit être traité selon les filtres de protocole."""
    if not packet.haslayer(IP):
        return False
    
    # Si "ALL" est activé, traiter tous les paquets
    if SUPPORTED_PROTOCOLS['ALL']['enabled']:
        return True
    
    # Vérifier les protocoles spécifiques
    for proto_name, config in SUPPORTED_PROTOCOLS.items():
        if proto_name == 'ALL' or not config['enabled']:
            continue
            
        if config['layer'] and packet.haslayer(config['layer']):
            return True
    
    return False

def get_packet_protocol_info(packet):
    """Extrait les informations de protocole d'un paquet."""
    if packet.haslayer(TCP):
        return "TCP", packet[TCP], True
    elif packet.haslayer(UDP):
        return "UDP", packet[UDP], True
    elif packet.haslayer(ICMP):
        return "ICMP", packet[ICMP], False
    else:
        return "OTHER", None, False

def update_stats(protocol, packet_size):
    """Met à jour les statistiques."""
    with lock:
        nat_stats['total_packets'] += 1
        nat_stats['total_bytes'] += packet_size
        nat_stats['packets_by_protocol'][protocol] += 1
        nat_stats['bytes_by_protocol'][protocol] += packet_size

def create_nat_packet(packet, new_src_ip, new_sport, dest_mac, src_iface):
    """Crée un nouveau paquet avec translation NAT."""
    new_packet = packet.copy()
    
    # Modifier Ethernet
    new_packet[Ether].dst = dest_mac
    new_packet[Ether].src = get_if_hwaddr(src_iface)
    
    # Modifier IP
    new_packet[IP].src = new_src_ip
    new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
    
    # Modifier port source selon le protocole
    if new_packet.haslayer(TCP):
        new_packet[TCP].sport = new_sport
        del new_packet[TCP].chksum
    elif new_packet.haslayer(UDP):
        new_packet[UDP].sport = new_sport
        del new_packet[UDP].chksum
    # ICMP n'a pas de ports, on utilise l'ID
    elif new_packet.haslayer(ICMP):
        new_packet[ICMP].id = new_sport
        del new_packet[ICMP].chksum
    
    # Supprimer checksum IP pour recalcul
    del new_packet[IP].chksum
    
    return new_packet

def handle_outgoing(packet, lan_iface, wan_iface, wan_ip, wan_mac, lan_network):
    """Traite les paquets sortants (LAN → WAN)."""
    try:
        if not should_process_packet(packet):
            return

        ip = packet[IP]
        
        # Vérifier que le paquet vient du LAN et va vers l'extérieur
        if not ip.src.startswith(lan_network) or ip.dst.startswith(lan_network):
            return

        proto_name, l4, has_ports = get_packet_protocol_info(packet)
        
        # Mise à jour des statistiques
        update_stats(proto_name, len(packet))

        if has_ports:
            # Protocoles avec ports (TCP, UDP)
            src_port = l4.sport
            key = (ip.src, src_port, proto_name)
        else:
            # Protocoles sans ports (ICMP)
            if proto_name == "ICMP":
                src_port = getattr(l4, 'id', 0)  # Utiliser l'ID ICMP
            else:
                src_port = 0
            key = (ip.src, src_port, proto_name)

        logger.info(f"NAT sortant: {ip.src}:{src_port} → {ip.dst} ({proto_name})")

        # Gestion de la table NAT
        with lock:
            if key not in nat_table:
                if has_ports or proto_name == "ICMP":
                    public_port = get_free_port()
                else:
                    public_port = src_port
                    
                nat_table[key] = (wan_ip, public_port)
                reverse_nat_table[(wan_ip, public_port, proto_name)] = key
                logger.info(f"Nouvelle entrée NAT: {ip.src}:{src_port} → {wan_ip}:{public_port}")
            else:
                public_port = nat_table[key][1]

        # Résoudre la MAC de destination si nécessaire
        if wan_mac == "ff:ff:ff:ff:ff:ff":
            dest_mac = resolve_mac_address(ip.dst, wan_iface)
            if not dest_mac:
                dest_mac = wan_mac
        else:
            dest_mac = wan_mac

        # Créer et envoyer le paquet modifié
        new_packet = create_nat_packet(packet, wan_ip, public_port, dest_mac, wan_iface)
        sendp(new_packet, iface=wan_iface, verbose=0)
        
    except Exception as e:
        logger.error(f"Erreur dans handle_outgoing: {e}")

def handle_incoming(packet, wan_iface, lan_iface, wan_ip):
    """Traite les paquets entrants (WAN → LAN)."""
    try:
        if not should_process_packet(packet):
            return

        ip = packet[IP]
        
        # Vérifier que le paquet est destiné à notre IP WAN
        if ip.dst != wan_ip:
            return

        proto_name, l4, has_ports = get_packet_protocol_info(packet)
        
        # Mise à jour des statistiques
        update_stats(proto_name, len(packet))

        if has_ports:
            dst_port = l4.dport
        else:
            if proto_name == "ICMP":
                dst_port = getattr(l4, 'id', 0)
            else:
                dst_port = 0

        key = (wan_ip, dst_port, proto_name)

        with lock:
            nat_entry = reverse_nat_table.get(key)

        if not nat_entry:
            return

        orig_ip, orig_port, _ = nat_entry
        logger.info(f"NAT entrant: {ip.src} → {orig_ip}:{orig_port} ({proto_name})")

        # Résoudre la MAC de destination
        dest_mac = resolve_mac_address(orig_ip, lan_iface)
        if not dest_mac:
            dest_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast fallback

        # Créer le paquet de retour
        new_packet = packet.copy()
        new_packet[Ether].dst = dest_mac
        new_packet[Ether].src = get_if_hwaddr(lan_iface)
        new_packet[IP].dst = orig_ip
        new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
        
        if proto_name == "TCP":
            new_packet[TCP].dport = orig_port
            del new_packet[TCP].chksum
        elif proto_name == "UDP":
            new_packet[UDP].dport = orig_port
            del new_packet[UDP].chksum
        elif proto_name == "ICMP":
            new_packet[ICMP].id = orig_port
            del new_packet[ICMP].chksum
        
        del new_packet[IP].chksum
        
        sendp(new_packet, iface=lan_iface, verbose=0)
        
    except Exception as e:
        logger.error(f"Erreur dans handle_incoming: {e}")

def start_nat(lan_iface, wan_iface):
    """Lance les sniffers NAT asynchrones."""
    global lan_sniffer, wan_sniffer

    # Vérifier qu'au moins un protocole est activé
    enabled_protocols = get_enabled_protocols()
    if not enabled_protocols:
        logger.error("Aucun protocole activé. Activez au moins un protocole avant de démarrer le NAT.")
        return False

    logger.info(f"Protocoles activés: {', '.join(enabled_protocols)}")

    # Vérifications des interfaces
    if not check_interface_status(lan_iface) or not check_interface_status(wan_iface):
        return False

    try:
        wan_ip = get_if_addr(wan_iface)
        lan_ip = get_if_addr(lan_iface)
        lan_network = get_lan_network(lan_ip)
        gateway_ip, wan_mac = get_gateway_info(wan_iface)

        logger.info(f"Configuration NAT: LAN={lan_iface} ({lan_ip}), WAN={wan_iface} ({wan_ip})")
        logger.info(f"Réseau LAN: {lan_network}, Passerelle: {gateway_ip}, MAC: {wan_mac}")

        # Initialiser les statistiques
        with lock:
            nat_stats['start_time'] = time.time()
            nat_stats['total_packets'] = 0
            nat_stats['total_bytes'] = 0
            nat_stats['packets_by_protocol'].clear()
            nat_stats['bytes_by_protocol'].clear()

    except Exception as e:
        logger.error(f"Erreur récupération interfaces: {e}")
        return False

    # Création des handlers
    def handle_lan(pkt):
        handle_outgoing(pkt, lan_iface, wan_iface, wan_ip, wan_mac, lan_network)

    def handle_wan(pkt):
        handle_incoming(pkt, wan_iface, lan_iface, wan_ip)

    try:
        # Construire le filtre BPF selon les protocoles activés
        filter_parts = []
        if SUPPORTED_PROTOCOLS['ALL']['enabled']:
            bpf_filter = "ip"
        else:
            if SUPPORTED_PROTOCOLS['TCP']['enabled']:
                filter_parts.append("tcp")
            if SUPPORTED_PROTOCOLS['UDP']['enabled']:
                filter_parts.append("udp")
            if SUPPORTED_PROTOCOLS['ICMP']['enabled']:
                filter_parts.append("icmp")
            
            if filter_parts:
                bpf_filter = f"ip and ({' or '.join(filter_parts)})"
            else:
                bpf_filter = "ip"

        logger.info(f"Filtre BPF utilisé: {bpf_filter}")

        # Démarrage des sniffers asynchrones
        lan_sniffer = AsyncSniffer(
            iface=lan_iface,
            prn=handle_lan,
            filter=bpf_filter,
            store=False
        )
        
        wan_sniffer = AsyncSniffer(
            iface=wan_iface,
            prn=handle_wan,
            filter=f"{bpf_filter} and dst host {wan_ip}",
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
    global nat_table, reverse_nat_table, used_ports, lan_sniffer, wan_sniffer, arp_cache

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
        arp_cache.clear()

    logger.info("✅ NAT arrêté et tables nettoyées")
    return True

def get_nat_stats():
    """Retourne les statistiques du NAT."""
    with lock:
        uptime = time.time() - nat_stats['start_time'] if nat_stats['start_time'] else 0
        return {
            "active_connections": len(nat_table),
            "used_ports": len(used_ports),
            "total_packets": nat_stats['total_packets'],
            "total_bytes": nat_stats['total_bytes'],
            "uptime_seconds": int(uptime),
            "arp_cache_entries": len(arp_cache),
            "protocols_stats": dict(nat_stats['packets_by_protocol']),
            "bytes_by_protocol": dict(nat_stats['bytes_by_protocol'])
        }

def get_arp_table():
    """Retourne la table ARP actuelle."""
    with lock:
        return arp_cache.copy()

def clear_nat_tables():
    """Vide les tables NAT sans arrêter le service."""
    with lock:
        nat_table.clear()
        reverse_nat_table.clear()
        used_ports.clear()
    logger.info("Tables NAT vidées")
    return True