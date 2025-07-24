# gateway_detector.py - Détection de passerelle cross-platform en Python pur

import socket
import struct
import platform
import psutil
import netifaces
from typing import Optional, Tuple, Dict, List
import logging

logger = logging.getLogger(__name__)

class GatewayDetector:
    """Détecteur de passerelle réseau cross-platform."""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.gateway_cache = {}
    
    def get_default_gateway(self) -> Optional[Tuple[str, str]]:
        """
        Retourne la passerelle par défaut et l'interface associée.
        Returns: (gateway_ip, interface_name) ou None
        """
        try:
            # Méthode 1: Utiliser netifaces (multiplateforme)
            gateways = netifaces.gateways()
            
            if 'default' in gateways:
                default_gw = gateways['default']
                if netifaces.AF_INET in default_gw:
                    gateway_ip, interface = default_gw[netifaces.AF_INET]
                    logger.info(f"Passerelle détectée (netifaces): {gateway_ip} via {interface}")
                    return gateway_ip, interface
            
            # Méthode 2: Analyser toutes les passerelles
            if netifaces.AF_INET in gateways:
                for gateway_ip, interface, default in gateways[netifaces.AF_INET]:
                    if default:
                        logger.info(f"Passerelle par défaut: {gateway_ip} via {interface}")
                        return gateway_ip, interface
        
        except Exception as e:
            logger.debug(f"Erreur netifaces: {e}")
        
        # Méthode 3: Utiliser psutil
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            # Trouver l'interface avec une route par défaut
            for interface_name, interface_addrs in addrs.items():
                if interface_name in stats and stats[interface_name].isup:
                    for addr in interface_addrs:
                        if addr.family == socket.AF_INET:
                            # Calculer la passerelle probable
                            gateway = self._calculate_gateway(addr.address, addr.netmask)
                            if gateway:
                                logger.info(f"Passerelle calculée: {gateway} via {interface_name}")
                                return gateway, interface_name
        
        except Exception as e:
            logger.debug(f"Erreur psutil: {e}")
        
        # Méthode 4: Socket trick pour trouver l'interface de sortie
        try:
            gateway, interface = self._socket_trick_gateway()
            if gateway and interface:
                return gateway, interface
        except Exception as e:
            logger.debug(f"Erreur socket trick: {e}")
        
        logger.warning("Impossible de détecter la passerelle par défaut")
        return None
    
    def _calculate_gateway(self, ip: str, netmask: str) -> Optional[str]:
        """Calcule la passerelle probable à partir de l'IP et du masque."""
        try:
            # Convertir IP et masque en entiers
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
            
            # Calculer l'adresse réseau
            network_int = ip_int & mask_int
            
            # La passerelle est généralement .1 ou .254 du réseau
            gateway_candidates = [
                network_int | 1,        # xxx.xxx.xxx.1
                network_int | 254,      # xxx.xxx.xxx.254
            ]
            
            for gw_int in gateway_candidates:
                gateway_ip = socket.inet_ntoa(struct.pack('!I', gw_int))
                if self._test_gateway_reachability(gateway_ip):
                    return gateway_ip
            
            return None
            
        except Exception as e:
            logger.debug(f"Erreur calcul passerelle: {e}")
            return None
    
    def _socket_trick_gateway(self) -> Tuple[Optional[str], Optional[str]]:
        """Utilise un socket pour déterminer l'interface et passerelle de sortie."""
        try:
            # Créer un socket UDP vers une adresse externe
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Se connecter à Google DNS (ne génère pas de trafic réel)
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            
            # Trouver l'interface correspondante
            addrs = psutil.net_if_addrs()
            for interface_name, interface_addrs in addrs.items():
                for addr in interface_addrs:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        # Calculer la passerelle
                        gateway = self._calculate_gateway(addr.address, addr.netmask)
                        if gateway:
                            return gateway, interface_name
            
            return None, None
            
        except Exception as e:
            logger.debug(f"Erreur socket trick: {e}")
            return None, None
    
    def _test_gateway_reachability(self, gateway_ip: str, timeout: int = 1) -> bool:
        """Teste si une passerelle est joignable (sans ping)."""
        try:
            # Essayer de se connecter au port 53 (DNS) de la passerelle
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((gateway_ip, 53))
                return result == 0 or result == 61  # 61 = Connection refused (mais joignable)
        except:
            pass
        
        try:
            # Essayer le port 80 (HTTP)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((gateway_ip, 80))
                return result == 0 or result == 61
        except:
            pass
        
        return False
    
    def get_interface_gateway(self, interface_name: str) -> Optional[str]:
        """Obtient la passerelle pour une interface spécifique."""
        try:
            # Utiliser netifaces pour obtenir les infos de l'interface
            if interface_name not in netifaces.interfaces():
                logger.error(f"Interface {interface_name} non trouvée")
                return None
            
            # Obtenir les adresses de l'interface
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET not in addrs:
                logger.error(f"Interface {interface_name} n'a pas d'adresse IPv4")
                return None
            
            inet_info = addrs[netifaces.AF_INET][0]
            ip = inet_info['addr']
            netmask = inet_info['netmask']
            
            # Vérifier s'il y a une passerelle explicite
            if 'gateway' in inet_info:
                return inet_info['gateway']
            
            # Calculer la passerelle probable
            gateway = self._calculate_gateway(ip, netmask)
            if gateway:
                logger.info(f"Passerelle calculée pour {interface_name}: {gateway}")
                return gateway
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur obtention passerelle pour {interface_name}: {e}")
            return None
    
    def get_all_gateways(self) -> Dict[str, str]:
        """Retourne toutes les passerelles par interface."""
        gateways = {}
        
        try:
            # Méthode netifaces
            all_gateways = netifaces.gateways()
            
            if netifaces.AF_INET in all_gateways:
                for gateway_ip, interface, is_default in all_gateways[netifaces.AF_INET]:
                    gateways[interface] = gateway_ip
                    if is_default:
                        gateways['default'] = gateway_ip
            
            # Compléter avec psutil
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for interface_name, interface_addrs in addrs.items():
                if interface_name not in gateways and interface_name in stats:
                    if stats[interface_name].isup:
                        for addr in interface_addrs:
                            if addr.family == socket.AF_INET:
                                gateway = self._calculate_gateway(addr.address, addr.netmask)
                                if gateway:
                                    gateways[interface_name] = gateway
                                break
        
        except Exception as e:
            logger.error(f"Erreur obtention toutes passerelles: {e}")
        
        return gateways
    
    def test_gateway_connectivity(self, gateway_ip: str) -> Dict[str, any]:
        """Teste la connectivité vers une passerelle."""
        results = {
            'gateway_ip': gateway_ip,
            'reachable': False,
            'response_time': None,
            'open_ports': [],
            'method_used': None
        }
        
        # Test des ports communs
        common_ports = [53, 80, 443, 22, 23]  # DNS, HTTP, HTTPS, SSH, Telnet
        
        for port in common_ports:
            try:
                start_time = socket.time()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((gateway_ip, port))
                    
                    if result == 0:  # Connexion réussie
                        response_time = (socket.time() - start_time) * 1000
                        results['reachable'] = True
                        results['response_time'] = response_time
                        results['open_ports'].append(port)
                        results['method_used'] = f'TCP port {port}'
                    elif result == 61:  # Connection refused (mais host joignable)
                        if not results['reachable']:
                            results['reachable'] = True
                            results['response_time'] = (socket.time() - start_time) * 1000
                            results['method_used'] = f'TCP port {port} (refused but reachable)'
            except Exception as e:
                logger.debug(f"Erreur test port {port}: {e}")
        
        return results

def test_gateway_detector():
    """Fonction de test du détecteur de passerelle."""
    print("🔍 Test du détecteur de passerelle")
    print("=" * 50)
    
    detector = GatewayDetector()
    
    # Test 1: Passerelle par défaut
    print("\n1. Détection passerelle par défaut:")
    default_gw = detector.get_default_gateway()
    if default_gw:
        gateway_ip, interface = default_gw
        print(f"   ✅ Passerelle: {gateway_ip}")
        print(f"   ✅ Interface: {interface}")
        
        # Tester la connectivité
        print(f"\n2. Test connectivité vers {gateway_ip}:")
        connectivity = detector.test_gateway_connectivity(gateway_ip)
        print(f"   Joignable: {'✅' if connectivity['reachable'] else '❌'}")
        if connectivity['response_time']:
            print(f"   Temps réponse: {connectivity['response_time']:.1f}ms")
        if connectivity['open_ports']:
            print(f"   Ports ouverts: {connectivity['open_ports']}")
        print(f"   Méthode: {connectivity['method_used']}")
    else:
        print("   ❌ Aucune passerelle détectée")
    
    # Test 2: Toutes les passerelles
    print("\n3. Toutes les passerelles:")
    all_gateways = detector.get_all_gateways()
    for interface, gateway in all_gateways.items():
        print(f"   {interface}: {gateway}")
    
    # Test 3: Informations interfaces
    print("\n4. Interfaces réseau:")
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                print(f"   {interface}: {ip}")
    except Exception as e:
        print(f"   Erreur: {e}")

if __name__ == "__main__":
    # Configuration logging pour les tests
    logging.basicConfig(level=logging.INFO, 
                       format='%(levelname)s:%(name)s:%(message)s')
    
    test_gateway_detector()
    detector = GatewayDetector()
    detector.get_default_gateway()
