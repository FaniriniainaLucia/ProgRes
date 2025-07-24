# nat_config.py - Configuration et utilitaires pour le NAT

import json
import os
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class NATConfig:
    """Configuration du NAT."""
    lan_interface: Optional[str] = None
    wan_interface: Optional[str] = None
    enabled_protocols: List[str] = None
    port_range_start: int = 1024
    port_range_end: int = 65535
    arp_timeout: int = 300  # secondes
    nat_timeout: int = 3600  # secondes
    log_level: str = "INFO"
    
    def __post_init__(self):
        if self.enabled_protocols is None:
            self.enabled_protocols = []

class NATConfigManager:
    """Gestionnaire de configuration NAT."""
    
    def __init__(self, config_file: str = "nat_config.json"):
        self.config_file = Path(config_file)
        self.config = NATConfig()
        self.load_config()
    
    def load_config(self) -> bool:
        """Charge la configuration depuis le fichier."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.config = NATConfig(**data)
                    logging.info(f"Configuration chargée depuis {self.config_file}")
                    return True
            else:
                logging.info("Fichier de configuration non trouvé, utilisation des valeurs par défaut")
                return False
        except Exception as e:
            logging.error(f"Erreur lors du chargement de la configuration: {e}")
            return False
    
    def save_config(self) -> bool:
        """Sauvegarde la configuration dans le fichier."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(asdict(self.config), f, indent=4)
            logging.info(f"Configuration sauvegardée dans {self.config_file}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde de la configuration: {e}")
            return False
    
    def update_interfaces(self, lan: str, wan: str) -> bool:
        """Met à jour les interfaces."""
        if lan == wan:
            logging.error("Les interfaces LAN et WAN ne peuvent pas être identiques")
            return False
        
        self.config.lan_interface = lan
        self.config.wan_interface = wan
        return self.save_config()
    
    def update_protocols(self, protocols: List[str]) -> bool:
        """Met à jour les protocoles activés."""
        valid_protocols = {'TCP', 'UDP', 'ICMP', 'ALL'}
        
        # Valider les protocoles
        for proto in protocols:
            if proto not in valid_protocols:
                logging.error(f"Protocole invalide: {proto}")
                return False
        
        self.config.enabled_protocols = protocols
        return self.save_config()
    
    def get_config(self) -> NATConfig:
        """Retourne la configuration actuelle."""
        return self.config

# Utilitaires de validation
def validate_interface_name(interface: str) -> bool:
    """Valide le nom d'une interface réseau."""
    if not interface or not isinstance(interface, str):
        return False
    
    # Vérifications basiques
    if len(interface) > 15:  # Limite Linux pour les noms d'interface
        return False
    
    # Caractères autorisés
    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.')
    if not all(c in allowed_chars for c in interface):
        return False
    
    return True

def validate_protocol_list(protocols: List[str]) -> tuple[bool, str]:
    """Valide une liste de protocoles."""
    if not protocols:
        return False, "Liste de protocoles vide"
    
    valid_protocols = {'TCP', 'UDP', 'ICMP', 'ALL'}
    
    for proto in protocols:
        if proto not in valid_protocols:
            return False, f"Protocole invalide: {proto}"
    
    # Si ALL est sélectionné, il ne devrait pas y avoir d'autres protocoles
    if 'ALL' in protocols and len(protocols) > 1:
        return False, "Le protocole 'ALL' ne peut pas être combiné avec d'autres protocoles"
    
    return True, "OK"

def validate_port_range(start: int, end: int) -> tuple[bool, str]:
    """Valide une plage de ports."""
    if not isinstance(start, int) or not isinstance(end, int):
        return False, "Les ports doivent être des entiers"
    
    if start < 1 or end > 65535:
        return False, "Les ports doivent être entre 1 et 65535"
    
    if start >= end:
        return False, "Le port de début doit être inférieur au port de fin"
    
    if start < 1024:
        return False, "Il est recommandé d'utiliser des ports >= 1024"
    
    return True, "OK"

# Fonctions utilitaires pour l'interface web
def get_system_info() -> Dict:
    """Retourne les informations système."""
    import psutil
    import platform
    
    return {
        "os": platform.system(),
        "os_version": platform.release(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "memory_total": psutil.virtual_memory().total,
        "memory_available": psutil.virtual_memory().available,
        "boot_time": psutil.boot_time()
    }

def check_dependencies() -> Dict[str, bool]:
    """Vérifie les dépendances nécessaires."""
    dependencies = {}
    
    try:
        import scapy
        dependencies["scapy"] = True
    except ImportError:
        dependencies["scapy"] = False
    
    try:
        import psutil
        dependencies["psutil"] = True
    except ImportError:
        dependencies["psutil"] = False
    
    try:
        import flask
        dependencies["flask"] = True
    except ImportError:
        dependencies["flask"] = False
    
    # Vérifier les permissions root
    dependencies["root_permissions"] = os.geteuid() == 0
    
    return dependencies

def get_performance_recommendations(stats: Dict) -> List[str]:
    """Génère des recommandations de performance."""
    recommendations = []
    
    if stats.get("active_connections", 0) > 1000:
        recommendations.append("⚠️ Nombre élevé de connexions actives. Considérez augmenter le timeout NAT.")
    
    if stats.get("used_ports", 0) > 50000:
        recommendations.append("⚠️ Beaucoup de ports utilisés. Risque d'épuisement des ports disponibles.")
    
    if stats.get("total_bytes", 0) > 1024**3:  # 1GB
        recommendations.append("ℹ️ Trafic important détecté. Surveillez l'utilisation CPU et mémoire.")
    
    uptime = stats.get("uptime_seconds", 0)
    if uptime > 86400:  # 24 heures
        recommendations.append("ℹ️ NAT actif depuis plus de 24h. Un redémarrage périodique peut être bénéfique.")
    
    return recommendations

def export_config(config: NATConfig, export_path: str) -> bool:
    """Exporte la configuration vers un fichier."""
    try:
        export_data = {
            "config": asdict(config),
            "export_timestamp": int(time.time()),
            "export_version": "2.0"
        }
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=4)
        
        return True
    except Exception as e:
        logging.error(f"Erreur lors de l'export: {e}")
        return False

def import_config(import_path: str) -> Optional[NATConfig]:
    """Importe une configuration depuis un fichier."""
    try:
        with open(import_path, 'r') as f:
            data = json.load(f)
        
        if "config" in data:
            return NATConfig(**data["config"])
        else:
            # Format legacy
            return NATConfig(**data)
            
    except Exception as e:
        logging.error(f"Erreur lors de l'import: {e}")
        return None

# Configuration par défaut pour différents scénarios
DEFAULT_CONFIGS = {
    "home_router": NATConfig(
        enabled_protocols=["TCP", "UDP", "ICMP"],
        port_range_start=1024,
        port_range_end=65535,
        arp_timeout=300,
        nat_timeout=1800,
        log_level="INFO"
    ),
    
    "enterprise": NATConfig(
        enabled_protocols=["TCP", "UDP"],
        port_range_start=10000,
        port_range_end=60000,
        arp_timeout=600,
        nat_timeout=3600,
        log_level="WARNING"
    ),
    
    "development": NATConfig(
        enabled_protocols=["ALL"],
        port_range_start=1024,
        port_range_end=65535,
        arp_timeout=60,
        nat_timeout=300,
        log_level="DEBUG"
    )
}

def get_preset_config(preset_name: str) -> Optional[NATConfig]:
    """Retourne une configuration prédéfinie."""
    return DEFAULT_CONFIGS.get(preset_name)

if __name__ == "__main__":
    # Test du gestionnaire de configuration
    import time
    
    config_manager = NATConfigManager("test_config.json")
    
    # Test de mise à jour
    config_manager.update_interfaces("eth0", "eth1")
    config_manager.update_protocols(["TCP", "UDP"])
    
    print("Configuration actuelle:")
    print(json.dumps(asdict(config_manager.get_config()), indent=2))
    
    # Test des validations
    print("\nTests de validation:")
    print(f"Interface 'eth0' valide: {validate_interface_name('eth0')}")
    print(f"Interface '' invalide: {validate_interface_name('')}")
    
    valid, msg = validate_protocol_list(["TCP", "UDP"])
    print(f"Protocoles TCP,UDP: {valid} - {msg}")
    
    valid, msg = validate_protocol_list(["ALL", "TCP"])
    print(f"Protocoles ALL,TCP: {valid} - {msg}")
    
    # Nettoyage
    os.unlink("test_config.json")