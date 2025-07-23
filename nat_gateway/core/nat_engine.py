# nat_engine.py - Version corrigée avec gestion d'erreurs améliorée

from scapy.all import (
    sniff, sendp, IP, TCP, UDP, Ether, get_if_hwaddr, get_if_addr,
    get_if_list, conf, ARP, sr1 , AsyncSniffer
)
import threading
import random
import socket
import time

from core.logger import get_logger

logger = get_logger("NAT")

nat_table = {}  # (src_ip, src_port, proto) -> (wan_ip, public_port)
reverse_nat_table = {}  # (wan_ip, public_port, proto) -> (src_ip, src_port)
used_ports = set()
lock = threading.Lock()

lan_thread = None
wan_thread = None
stop_event = threading.Event()

def get_free_port():
    for _ in range(50000):  # évite boucle infinie
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
    """Détermine le réseau LAN à partir de l'IP de l'interface."""
    # Pour un réseau /24 typique
    parts = lan_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}"

def get_gateway_mac(wan_iface, wan_ip):
    """Obtient l'adresse MAC de la passerelle par défaut."""
    try:
        # Obtenir la passerelle par défaut
        import subprocess
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        
        for line in result.stdout.split('\n'):
            if 'default via' in line and wan_iface in line:
                parts = line.split()
                gateway_ip = parts[2]  # IP après "via"
                logger.info(f"Passerelle détectée: {gateway_ip}")
                
                # Faire une requête ARP pour obtenir la MAC
                arp_req = ARP(pdst=gateway_ip)
                arp_resp = sr1(arp_req, timeout=2, verbose=0)
                
                if arp_resp:
                    logger.info(f"MAC passerelle: {arp_resp.hwsrc}")
                    return arp_resp.hwsrc
                break
        
        # Fallback: utiliser la MAC de l'interface elle-même
        logger.warning("Impossible d'obtenir la MAC de la passerelle, utilisation de l'interface")
        return get_if_hwaddr(wan_iface)
        
    except Exception as e:
        logger.warning(f"Erreur obtention MAC passerelle: {e}")
        # En dernier recours, utiliser broadcast
        return "ff:ff:ff:ff:ff:ff"

def handle_outgoing(packet, lan_iface, wan_iface, wan_ip, wan_mac, lan_network):
    """Traite les paquets sortants (LAN → WAN) - VERSION ROBUSTE."""
    try:
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        
        # AFFICHER TOUS LES PAQUETS pour debug
        logger.info(f"🔍 PAQUET LAN: {ip.src} → {ip.dst} (réseau LAN: {lan_network})")
        
        # Vérifier que le paquet vient bien du LAN
        if not ip.src.startswith(lan_network):
            logger.info(f"❌ Ignoré - source {ip.src} pas dans {lan_network}")
            return
            
        # Ignorer les paquets vers le réseau local
        if ip.dst.startswith(lan_network):
            logger.info(f"❌ Ignoré - destination {ip.dst} dans le LAN")
            return
        
        logger.info(f"✅ PAQUET VALIDE pour NAT: {ip.src} → {ip.dst}")

        if ip.haslayer(TCP):
            proto = "TCP"
            l4 = ip[TCP]
        elif ip.haslayer(UDP):
            proto = "UDP"
            l4 = ip[UDP]
        else:
            logger.info(f"❌ Protocole non supporté: {ip.proto}")
            return

        key = (ip.src, l4.sport, proto)
        logger.info(f"🔑 Clé NAT: {key}")
        logger.info("🔒 Tentative d'acquisition du verrou NAT...")

        with lock:
            logger.info("🔓 Verrou acquis !")
            if key not in nat_table:
                public_port = get_free_port()
                nat_table[key] = (wan_ip, public_port)
                reverse_nat_table[(wan_ip, public_port, proto)] = key
                logger.info(f"🆕 NAT CRÉÉ : {ip.src}:{l4.sport} → {wan_ip}:{public_port} ({proto})")
            else:
                public_port = nat_table[key][1]
                logger.info(f"🔄 NAT existant: {ip.src}:{l4.sport} → {wan_ip}:{public_port}")

        logger.info(f"📦 Début construction du paquet NAT...")

        # Méthode plus simple : modifier le paquet existant
        try:
            # Faire une copie du paquet
            new_packet = packet.copy()
            
            # Modifier la couche Ethernet
            new_packet[Ether].dst = wan_mac
            new_packet[Ether].src = get_if_hwaddr(wan_iface)
            
            # Modifier la couche IP
            new_packet[IP].src = wan_ip
            new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
            
            # Modifier la couche transport
            if proto == "TCP":
                new_packet[TCP].sport = public_port
            else:  # UDP
                new_packet[UDP].sport = public_port
            
            # Supprimer les checksums pour qu'ils soient recalculés
            del new_packet[IP].chksum
            if proto == "TCP":
                del new_packet[TCP].chksum
            else:
                del new_packet[UDP].chksum
            
            logger.info(f"📤 Envoi du paquet NAT...")
            
            try:
                logger.info("📦 Début construction du paquet NAT...")
                logger.info(f"🧾 Paquet brut avant envoi:\n{new_packet.summary()}")
                logger.info(f"🧾 Dest: {new_packet[Ether].dst} | Src: {new_packet[Ether].src}")

                sendp(new_packet, iface=wan_iface, verbose=0)
            except Exception as e:
                logger.error(f"💥 Erreur lors de sendp: {e}")
                import traceback
                logger.error(traceback.format_exc())

            
        except Exception as e:
            logger.error(f"❌ Erreur construction/envoi paquet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return
        
    except Exception as e:
        logger.error(f"❌ Erreur dans handle_outgoing: {e}")
        import traceback
        logger.error(traceback.format_exc())
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
            proto = "TCP"
            l4 = ip[TCP]
        elif ip.haslayer(UDP):
            proto = "UDP"
            l4 = ip[UDP]
        else:
            return

        key = (wan_ip, l4.dport, proto)

        with lock:
            nat_entry = reverse_nat_table.get(key)

        if not nat_entry:
            logger.debug(f"❌ Paquet entrant inconnu pour {wan_ip}:{l4.dport} ({proto}) — ignoré")
            return

        # Clé NAT inverse stockée comme (src_ip, src_port, proto)
        orig_ip, orig_port, _ = nat_entry

        logger.info(f"📥 PAQUET ENTRANT NAT: {ip.src}:{l4.sport} → {orig_ip}:{orig_port}")

        try:
            # Faire une copie et modifier
            new_packet = packet.copy()
            
            # Modifier Ethernet - utiliser broadcast pour simplifier
            new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
            new_packet[Ether].src = get_if_hwaddr(lan_iface)
            
            # Modifier IP
            new_packet[IP].dst = orig_ip
            new_packet[IP].ttl = max(1, new_packet[IP].ttl - 1)
            
            # Modifier transport
            if proto == "TCP":
                new_packet[TCP].dport = orig_port
            else:
                new_packet[UDP].dport = orig_port
            
            # Supprimer checksums
            del new_packet[IP].chksum
            if proto == "TCP":
                del new_packet[TCP].chksum
            else:
                del new_packet[UDP].chksum
            
            sendp(new_packet, iface=lan_iface, verbose=0)
            logger.info(f"✅ PAQUET RETRANSMIS vers LAN: {ip.src}:{l4.sport} → {orig_ip}:{orig_port}")
            
        except Exception as e:
            logger.error(f"💥 Erreur retransmission vers LAN: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
    except Exception as e:
        logger.error(f"💥 Erreur dans handle_incoming: {e}")
        import traceback
        logger.error(traceback.format_exc())

def start_nat(lan_iface, wan_iface):
    """Lance les sniffer NAT asynchrones."""
    global lan_sniffer, wan_sniffer

    if not check_interface_status(lan_iface):
        logger.error(f"Interface LAN {lan_iface} non disponible")
        return False

    if not check_interface_status(wan_iface):
        logger.error(f"Interface WAN {wan_iface} non disponible")
        return False

    try:
        wan_ip = get_if_addr(wan_iface)
        lan_ip = get_if_addr(lan_iface)
        lan_network = get_lan_network(lan_ip)

        logger.info(f"🧪 Configuration NAT:")
        logger.info(f"  LAN: {lan_iface} ({lan_ip}) - Réseau: {lan_network}")
        logger.info(f"  WAN: {wan_iface} ({wan_ip})")

        wan_mac = get_gateway_mac(wan_iface, wan_ip)
        logger.info(f"  MAC passerelle: {wan_mac}")
    except Exception as e:
        logger.error(f"Erreur récupération interfaces: {e}")
        return False

    # Handler LAN
    def handle_lan(pkt):
        try:
            handle_outgoing(pkt, lan_iface, wan_iface, wan_ip, wan_mac, lan_network)
        except Exception as e:
            logger.error(f"Erreur dans handle_lan: {e}")

    # Handler WAN
    def handle_wan(pkt):
        try:
            handle_incoming(pkt, wan_iface, lan_iface, wan_ip)
        except Exception as e:
            logger.error(f"Erreur dans handle_wan: {e}")

    try:
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

        logger.info("✅ Sniffers NAT asynchrones lancés")
        return True

    except Exception as e:
        logger.error(f"Erreur démarrage sniffers: {e}")
        return False



def stop_nat():
    """Arrête le NAT et nettoie les sniffeurs et tables."""
    global nat_table, reverse_nat_table, used_ports
    global lan_sniffer, wan_sniffer

    logger.info("⛔ Arrêt du NAT...")

    if lan_sniffer:
        lan_sniffer.stop()
        logger.info("LAN sniffer arrêté")
        lan_sniffer = None

    if wan_sniffer:
        wan_sniffer.stop()
        logger.info("WAN sniffer arrêté")
        wan_sniffer = None

    time.sleep(0.5)

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

def test_capture(interface, duration=5):
    """Teste la capture de paquets sur une interface."""
    logger.info(f"Test de capture sur {interface} pendant {duration} secondes...")
    
    packet_count = [0]
    
    def count_packet(pkt):
        packet_count[0] += 1
        if packet_count[0] <= 3:
            logger.info(f"Test - Paquet #{packet_count[0]}: {pkt.summary()}")
    
    try:
        logger.info(f"Tentative 1: Capture basique sur {interface}")
        sniff(iface=interface, prn=count_packet, timeout=duration, store=0, count=10)
        
        if packet_count[0] == 0:
            logger.warning(f"Aucun paquet capturé, tentative sans paramètres...")
            packet_count[0] = 0
            sniff(iface=interface, prn=count_packet, timeout=2, store=0)
        
        result = packet_count[0] > 0
        logger.info(f"Test terminé: {packet_count[0]} paquets capturés - {'✅ Succès' if result else '❌ Échec'}")
        
        return result
        
    except Exception as e:
        logger.error(f"Erreur pendant le test de capture: {e}")
        return False

def debug_scapy_config():
    """Affiche la configuration de Scapy pour debug."""
    from scapy.all import conf
    logger.info(f"Configuration Scapy:")
    logger.info(f"  Interface par défaut: {conf.iface}")
    logger.info(f"  Interfaces disponibles: {get_if_list()}")
    
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            mac = get_if_hwaddr(iface)
            logger.info(f"  {iface}: IP={ip}, MAC={mac}")
        except Exception as e:
            logger.warning(f"  {iface}: Erreur - {e}")

def cleanup_expired_connections():
    """Nettoie périodiquement les connexions expirées."""
    pass