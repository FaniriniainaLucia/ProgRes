# packet_capture.py - Interface de capture de paquets style Wireshark

from scapy.all import *
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import struct
import socket

from core.logger import get_logger

logger = get_logger("PacketCapture")

@dataclass
class PacketInfo:
    """Informations détaillées d'un paquet capturé."""
    timestamp: float
    frame_number: int
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None
    ttl: Optional[int] = None
    id: Optional[int] = None
    checksum: Optional[str] = None
    payload_size: int = 0
    raw_data: str = ""
    detailed_info: Dict[str, Any] = None
    interface: str = ""
    direction: str = ""  # "outgoing", "incoming", "local"

class PacketCapture:
    """Gestionnaire de capture de paquets avec analyse détaillée."""
    
    def __init__(self, max_packets=10000):
        self.packets = deque(maxlen=max_packets)
        self.packet_count = 0
        self.capture_active = False
        self.lock = threading.Lock()
        self.filters = {
            'protocol': [],
            'src_ip': '',
            'dst_ip': '',
            'port': '',
            'interface': ''
        }
        self.statistics = defaultdict(int)
        
    def analyze_packet(self, packet, interface="", direction="") -> PacketInfo:
        """Analyse complète d'un paquet réseau."""
        timestamp = time.time()
        
        with self.lock:
            self.packet_count += 1
            frame_number = self.packet_count
        
        # Informations de base
        packet_info = PacketInfo(
            timestamp=timestamp,
            frame_number=frame_number,
            src_ip="",
            dst_ip="",
            protocol="Unknown",
            length=len(packet),
            interface=interface,
            direction=direction,
            detailed_info={}
        )
        
        try:
            # Analyse de la couche Ethernet
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info.detailed_info['ethernet'] = {
                    'src_mac': eth.src,
                    'dst_mac': eth.dst,
                    'type': f"0x{eth.type:04x}"
                }
            
            # Analyse de la couche IP
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info.src_ip = ip.src
                packet_info.dst_ip = ip.dst
                packet_info.ttl = ip.ttl
                packet_info.id = ip.id
                packet_info.detailed_info['ip'] = {
                    'version': ip.version,
                    'ihl': ip.ihl,
                    'tos': ip.tos,
                    'len': ip.len,
                    'id': ip.id,
                    'flags': self._decode_ip_flags(ip.flags),
                    'frag': ip.frag,
                    'ttl': ip.ttl,
                    'proto': ip.proto,
                    'chksum': f"0x{ip.chksum:04x}",
                    'src': ip.src,
                    'dst': ip.dst,
                    'options': getattr(ip, 'options', [])
                }
            
            # Analyse des protocoles de transport
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info.protocol = "TCP"
                packet_info.src_port = tcp.sport
                packet_info.dst_port = tcp.dport
                packet_info.flags = self._decode_tcp_flags(tcp.flags)
                packet_info.detailed_info['tcp'] = {
                    'sport': tcp.sport,
                    'dport': tcp.dport,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'dataofs': tcp.dataofs,
                    'reserved': tcp.reserved,
                    'flags': self._decode_tcp_flags(tcp.flags),
                    'window': tcp.window,
                    'chksum': f"0x{tcp.chksum:04x}",
                    'urgptr': tcp.urgptr,
                    'options': getattr(tcp, 'options', [])
                }
                
                # Analyse du payload TCP
                if tcp.payload:
                    packet_info.payload_size = len(tcp.payload)
                    packet_info.detailed_info['tcp']['payload'] = self._analyze_tcp_payload(tcp)
                    
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info.protocol = "UDP"
                packet_info.src_port = udp.sport
                packet_info.dst_port = udp.dport
                packet_info.detailed_info['udp'] = {
                    'sport': udp.sport,
                    'dport': udp.dport,
                    'len': udp.len,
                    'chksum': f"0x{udp.chksum:04x}"
                }
                
                # Analyse du payload UDP
                if udp.payload:
                    packet_info.payload_size = len(udp.payload)
                    packet_info.detailed_info['udp']['payload'] = self._analyze_udp_payload(udp)
                    
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info.protocol = "ICMP"
                packet_info.detailed_info['icmp'] = {
                    'type': icmp.type,
                    'type_name': self._get_icmp_type_name(icmp.type),
                    'code': icmp.code,
                    'chksum': f"0x{icmp.chksum:04x}",
                    'id': getattr(icmp, 'id', 0),
                    'seq': getattr(icmp, 'seq', 0)
                }
            
            # Analyse d'autres protocoles
            if packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info.protocol = "ARP"
                packet_info.src_ip = arp.psrc
                packet_info.dst_ip = arp.pdst
                packet_info.detailed_info['arp'] = {
                    'hwtype': arp.hwtype,
                    'ptype': f"0x{arp.ptype:04x}",
                    'hwlen': arp.hwlen,
                    'plen': arp.plen,
                    'op': arp.op,
                    'op_name': "request" if arp.op == 1 else "reply" if arp.op == 2 else "unknown",
                    'hwsrc': arp.hwsrc,
                    'psrc': arp.psrc,
                    'hwdst': arp.hwdst,
                    'pdst': arp.pdst
                }
            
            # Données brutes (hexdump)
            packet_info.raw_data = self._generate_hexdump(bytes(packet))
            
            # Statistiques
            self.statistics[packet_info.protocol] += 1
            self.statistics['total_packets'] += 1
            self.statistics['total_bytes'] += packet_info.length
            
        except Exception as e:
            logger.error(f"Erreur analyse paquet: {e}")
            packet_info.detailed_info['error'] = str(e)
        
        return packet_info
    
    def _decode_ip_flags(self, flags):
        """Décode les flags IP."""
        flag_names = []
        if flags & 0x4000:  # Don't Fragment
            flag_names.append("DF")
        if flags & 0x2000:  # More Fragments
            flag_names.append("MF")
        if flags & 0x8000:  # Reserved
            flag_names.append("Reserved")
        return ",".join(flag_names) if flag_names else "None"
    
    def _decode_tcp_flags(self, flags):
        """Décode les flags TCP."""
        flag_names = []
        if flags & 0x01:  # FIN
            flag_names.append("FIN")
        if flags & 0x02:  # SYN
            flag_names.append("SYN")
        if flags & 0x04:  # RST
            flag_names.append("RST")
        if flags & 0x08:  # PSH
            flag_names.append("PSH")
        if flags & 0x10:  # ACK
            flag_names.append("ACK")
        if flags & 0x20:  # URG
            flag_names.append("URG")
        if flags & 0x40:  # ECE
            flag_names.append("ECE")
        if flags & 0x80:  # CWR
            flag_names.append("CWR")
        return ",".join(flag_names) if flag_names else "None"
    
    def _get_icmp_type_name(self, icmp_type):
        """Retourne le nom du type ICMP."""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply"
        }
        return icmp_types.get(icmp_type, f"Type {icmp_type}")
    
    def _analyze_tcp_payload(self, tcp):
        """Analyse le payload TCP pour détecter les protocoles d'application."""
        if not tcp.payload:
            return {"type": "empty", "size": 0}
        
        payload_bytes = bytes(tcp.payload)
        payload_str = payload_bytes.decode('utf-8', errors='ignore')[:200]  # Premiers 200 chars
        
        analysis = {
            "size": len(payload_bytes),
            "preview": payload_str,
            "type": "data"
        }
        
        # Détecter HTTP
        if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
            analysis["type"] = "HTTP Request"
            lines = payload_str.split('\r\n')
            if lines:
                analysis["http_method"] = lines[0]
        elif payload_str.startswith('HTTP/'):
            analysis["type"] = "HTTP Response"
            lines = payload_str.split('\r\n')
            if lines:
                analysis["http_status"] = lines[0]
        
        # Détecter FTP
        elif tcp.dport == 21 or tcp.sport == 21:
            analysis["type"] = "FTP"
        
        # Détecter SMTP
        elif tcp.dport == 25 or tcp.sport == 25:
            analysis["type"] = "SMTP"
        
        # Détecter DNS sur TCP
        elif tcp.dport == 53 or tcp.sport == 53:
            analysis["type"] = "DNS"
        
        # Détecter SSH
        elif tcp.dport == 22 or tcp.sport == 22:
            analysis["type"] = "SSH"
        
        return analysis
    
    def _analyze_udp_payload(self, udp):
        """Analyse le payload UDP."""
        if not udp.payload:
            return {"type": "empty", "size": 0}
        
        payload_bytes = bytes(udp.payload)
        
        analysis = {
            "size": len(payload_bytes),
            "type": "data"
        }
        
        # Détecter DNS
        if udp.dport == 53 or udp.sport == 53:
            analysis["type"] = "DNS"
            try:
                # Analyse basique du DNS
                if len(payload_bytes) >= 12:  # Header DNS minimum
                    dns_id = struct.unpack('>H', payload_bytes[0:2])[0]
                    flags = struct.unpack('>H', payload_bytes[2:4])[0]
                    analysis["dns_id"] = dns_id
                    analysis["dns_qr"] = "Response" if flags & 0x8000 else "Query"
                    analysis["dns_opcode"] = (flags >> 11) & 0xF
            except:
                pass
        
        # Détecter DHCP
        elif udp.dport in [67, 68] or udp.sport in [67, 68]:
            analysis["type"] = "DHCP"
        
        # Détecter NTP
        elif udp.dport == 123 or udp.sport == 123:
            analysis["type"] = "NTP"
        
        return analysis
    
    def _generate_hexdump(self, data, width=16):
        """Génère un hexdump du paquet."""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<{width*3}}  {ascii_part}")
        return '\n'.join(lines[:50])  # Limiter à 50 lignes
    
    def add_packet(self, packet, interface="", direction=""):
        """Ajoute un paquet à la capture."""
        if not self.capture_active:
            return
        
        packet_info = self.analyze_packet(packet, interface, direction)
        
        # Appliquer les filtres
        if self._packet_matches_filters(packet_info):
            with self.lock:
                self.packets.append(packet_info)
    
    def _packet_matches_filters(self, packet_info):
        """Vérifie si un paquet correspond aux filtres."""
        # Filtre par protocole
        if self.filters['protocol'] and packet_info.protocol not in self.filters['protocol']:
            return False
        
        # Filtre par IP source
        if self.filters['src_ip'] and self.filters['src_ip'] not in packet_info.src_ip:
            return False
        
        # Filtre par IP destination
        if self.filters['dst_ip'] and self.filters['dst_ip'] not in packet_info.dst_ip:
            return False
        
        # Filtre par port
        if self.filters['port']:
            try:
                port = int(self.filters['port'])
                if packet_info.src_port != port and packet_info.dst_port != port:
                    return False
            except ValueError:
                pass
        
        # Filtre par interface
        if self.filters['interface'] and self.filters['interface'] != packet_info.interface:
            return False
        
        return True
    
    def set_filters(self, **filters):
        """Configure les filtres de capture."""
        self.filters.update(filters)
        logger.info(f"Filtres mis à jour: {self.filters}")
    
    def clear_filters(self):
        """Supprime tous les filtres."""
        self.filters = {
            'protocol': [],
            'src_ip': '',
            'dst_ip': '',
            'port': '',
            'interface': ''
        }
    
    def start_capture(self):
        """Démarre la capture."""
        self.capture_active = True
        logger.info("Capture de paquets démarrée")
    
    def stop_capture(self):
        """Arrête la capture."""
        self.capture_active = False
        logger.info("Capture de paquets arrêtée")
    
    def clear_packets(self):
        """Vide la liste des paquets capturés."""
        with self.lock:
            self.packets.clear()
            self.packet_count = 0
            self.statistics.clear()
        logger.info("Paquets capturés effacés")
    
    def get_packets(self, start=0, count=100):
        """Retourne une liste de paquets."""
        with self.lock:
            packets_list = list(self.packets)
        
        # Trier par timestamp décroissant (plus récents en premier)
        packets_list.sort(key=lambda p: p.timestamp, reverse=True)
        
        return packets_list[start:start+count]
    
    def get_packet_by_frame(self, frame_number):
        """Retourne un paquet spécifique par son numéro de frame."""
        with self.lock:
            for packet in self.packets:
                if packet.frame_number == frame_number:
                    return packet
        return None
    
    def get_statistics(self):
        """Retourne les statistiques de capture."""
        with self.lock:
            stats = dict(self.statistics)
            stats['capture_active'] = self.capture_active
            stats['packets_in_buffer'] = len(self.packets)
            stats['max_packets'] = self.packets.maxlen
        return stats
    
    def export_packets(self, filename, format='json'):
        """Exporte les paquets capturés."""
        packets_list = self.get_packets(0, len(self.packets))
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump([asdict(p) for p in packets_list], f, indent=2, default=str)
        elif format == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Frame', 'Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
                for p in packets_list:
                    info = f"{p.src_port}->{p.dst_port}" if p.src_port else p.flags or ""
                    writer.writerow([p.frame_number, datetime.fromtimestamp(p.timestamp), 
                                   p.src_ip, p.dst_ip, p.protocol, p.length, info])
        
        logger.info(f"Paquets exportés vers {filename} (format: {format})")

# Instance globale de capture
packet_capture = PacketCapture()

def integrate_with_nat_engine():
    """Intègre la capture avec le moteur NAT existant."""
    # Cette fonction modifie les handlers NAT pour ajouter la capture
    def enhanced_handle_outgoing(original_handler):
        def wrapper(packet, *args, **kwargs):
            # Ajouter à la capture
            packet_capture.add_packet(packet, 
                                    interface=args[0] if args else "lan", 
                                    direction="outgoing")
            # Appeler le handler original
            return original_handler(packet, *args, **kwargs)
        return wrapper
    
    def enhanced_handle_incoming(original_handler):
        def wrapper(packet, *args, **kwargs):
            # Ajouter à la capture
            packet_capture.add_packet(packet, 
                                    interface=args[1] if len(args) > 1 else "wan", 
                                    direction="incoming")
            # Appeler le handler original
            return original_handler(packet, *args, **kwargs)
        return wrapper
    
    return enhanced_handle_outgoing, enhanced_handle_incoming