# app_v2.py - Version améliorée avec filtres protocoles

import sys
import os

# Ajout du chemin parent au PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, redirect, jsonify
import json
from core.packet_capture import packet_capture
from dataclasses import asdict

from network_utils import list_interfaces, get_iface_ip
from core.nat_engine import (
    start_nat, stop_nat, nat_table, get_nat_stats, lock,
    get_protocol_config, set_protocol_enabled, get_enabled_protocols,
    reset_protocol_config, get_arp_table, clear_nat_tables
)
from core.logger import get_logger
from core.nat_config import NATConfigManager, validate_interface_name, validate_protocol_list

app = Flask(__name__)
logger = get_logger("WebApp")

# Gestionnaire de configuration
config_manager = NATConfigManager("web/nat_config.json")

# Configuration globale
running_config = {
    "lan": None,
    "wan": None,
    "wan_ip": None,
    "status": False,
    "enabled_protocols": []
}

@app.route("/capture")
def capture_interface():
    """Interface de capture de paquets style Wireshark."""
    return render_template("capture.html")

@app.route("/capture/start", methods=["POST"])
def start_capture():
    """Démarre la capture de paquets."""
    try:
        if not running_config["status"]:
            return jsonify({
                "status": "error",
                "message": "NAT non démarré. Impossible de capturer des paquets."
            })
        
        packet_capture.start_capture()
        logger.info("Capture de paquets démarrée via interface web")
        
        return jsonify({
            "status": "success",
            "message": "Capture démarrée avec succès"
        })
    
    except Exception as e:
        logger.error(f"Erreur démarrage capture: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur lors du démarrage: {str(e)}"
        })

@app.route("/capture/stop", methods=["POST"])
def stop_capture():
    """Arrête la capture de paquets."""
    try:
        packet_capture.stop_capture()
        logger.info("Capture de paquets arrêtée via interface web")
        
        return jsonify({
            "status": "success",
            "message": "Capture arrêtée avec succès"
        })
    
    except Exception as e:
        logger.error(f"Erreur arrêt capture: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur lors de l'arrêt: {str(e)}"
        })

@app.route("/capture/clear", methods=["POST"])
def clear_capture():
    """Vide la liste des paquets capturés."""
    try:
        packet_capture.clear_packets()
        logger.info("Paquets capturés vidés via interface web")
        
        return jsonify({
            "status": "success",
            "message": "Paquets vidés avec succès"
        })
    
    except Exception as e:
        logger.error(f"Erreur vidage capture: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur lors du vidage: {str(e)}"
        })

@app.route("/capture/packets")
def get_packets():
    """Récupère la liste des paquets capturés."""
    try:
        start = int(request.args.get('start', 0))
        count = int(request.args.get('count', 100))
        
        packets = packet_capture.get_packets(start, count)
        statistics = packet_capture.get_statistics()
        
        # Convertir les paquets en dictionnaires pour JSON
        packets_data = []
        for packet in packets:
            packet_dict = {
                'timestamp': packet.timestamp,
                'frame_number': packet.frame_number,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'protocol': packet.protocol,
                'length': packet.length,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'flags': packet.flags,
                'ttl': packet.ttl,
                'id': packet.id,
                'checksum': packet.checksum,
                'payload_size': packet.payload_size,
                'raw_data': packet.raw_data,
                'detailed_info': packet.detailed_info,
                'interface': packet.interface,
                'direction': packet.direction
            }
            packets_data.append(packet_dict)
        
        return jsonify({
            "status": "success",
            "packets": packets_data,
            "statistics": statistics,
            "total_packets": len(packets_data)
        })
    
    except Exception as e:
        logger.error(f"Erreur récupération paquets: {e}")
        return jsonify({
            "status": "error",
            "packets": [],
            "statistics": {},
            "message": f"Erreur: {str(e)}"
        })

@app.route("/capture/packet/<int:frame_number>")
def get_packet_details(frame_number):
    """Récupère les détails d'un paquet spécifique."""
    try:
        packet = packet_capture.get_packet_by_frame(frame_number)
        
        if packet:
            packet_dict = {
                'timestamp': packet.timestamp,
                'frame_number': packet.frame_number,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'protocol': packet.protocol,
                'length': packet.length,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'flags': packet.flags,
                'ttl': packet.ttl,
                'id': packet.id,
                'checksum': packet.checksum,
                'payload_size': packet.payload_size,
                'raw_data': packet.raw_data,
                'detailed_info': packet.detailed_info,
                'interface': packet.interface,
                'direction': packet.direction
            }
            
            return jsonify({
                "status": "success",
                "packet": packet_dict
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Paquet {frame_number} non trouvé"
            })
    
    except Exception as e:
        logger.error(f"Erreur récupération paquet {frame_number}: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur: {str(e)}"
        })

@app.route("/capture/filters", methods=["POST"])
def set_capture_filters():
    """Configure les filtres de capture."""
    try:
        filters = request.get_json()
        
        # Valider les filtres
        valid_filters = {}
        if 'protocol' in filters:
            protocols = filters['protocol']
            if isinstance(protocols, str):
                protocols = [protocols] if protocols else []
            valid_filters['protocol'] = protocols
        
        if 'src_ip' in filters:
            valid_filters['src_ip'] = filters['src_ip']
        
        if 'dst_ip' in filters:
            valid_filters['dst_ip'] = filters['dst_ip']
        
        if 'port' in filters:
            valid_filters['port'] = filters['port']
        
        if 'interface' in filters:
            valid_filters['interface'] = filters['interface']
        
        packet_capture.set_filters(**valid_filters)
        
        return jsonify({
            "status": "success",
            "message": "Filtres appliqués avec succès",
            "filters": valid_filters
        })
    
    except Exception as e:
        logger.error(f"Erreur configuration filtres: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur: {str(e)}"
        })

@app.route("/capture/export")
def export_capture():
    """Exporte les paquets capturés."""
    try:
        format_type = request.args.get('format', 'json').lower()
        
        if format_type not in ['json', 'csv']:
            return jsonify({
                "status": "error",
                "message": "Format non supporté. Utilisez 'json' ou 'csv'."
            })
        
        # Créer un fichier temporaire
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{format_type}', delete=False) as temp_file:
            temp_filename = temp_file.name
            
            # Exporter vers le fichier temporaire
            packet_capture.export_packets(temp_filename, format_type)
            
            # Lire le contenu du fichier
            with open(temp_filename, 'r') as f:
                content = f.read()
            
            # Supprimer le fichier temporaire
            os.unlink(temp_filename)
            
            # Déterminer le type MIME
            mime_type = 'application/json' if format_type == 'json' else 'text/csv'
            
            # Créer la réponse avec le bon en-tête
            from flask import Response
            response = Response(
                content,
                mimetype=mime_type,
                headers={
                    "Content-Disposition": f"attachment; filename=capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
                }
            )
            
            return response
    
    except Exception as e:
        logger.error(f"Erreur export capture: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur lors de l'export: {str(e)}"
        })

@app.route("/capture/status")
def capture_status():
    """Retourne le statut de la capture."""
    try:
        statistics = packet_capture.get_statistics()
        
        return jsonify({
            "status": "success",
            "capture_active": statistics.get('capture_active', False),
            "packets_count": statistics.get('packets_in_buffer', 0),
            "statistics": statistics
        })
    
    except Exception as e:
        logger.error(f"Erreur statut capture: {e}")
        return jsonify({
            "status": "error",
            "message": f"Erreur: {str(e)}"
        })

@app.route("/", methods=["GET", "POST"])
def index():
    """Page principale avec configuration du NAT."""
    if request.method == "POST":
        return handle_nat_start()
    
    # Charger la dernière configuration sauvegardée
    saved_config = config_manager.get_config()
    
    return render_template("index.html", 
                         interfaces=list_interfaces(), 
                         config=running_config,
                         protocol_config=get_protocol_config(),
                         enabled_protocols=get_enabled_protocols(),
                         saved_config=saved_config)

def handle_nat_start():
    """Gère le démarrage du NAT depuis le formulaire."""
    if running_config["status"]:
        return redirect("/")
    
    # Récupérer les interfaces
    lan = request.form.get("lan")
    wan = request.form.get("wan")
    
    # Validation des interfaces
    if not validate_interface_name(lan) or not validate_interface_name(wan):
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error="Noms d'interfaces invalides")
    
    if lan == wan:
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error="Les interfaces LAN et WAN ne peuvent pas être identiques")
    
    wan_ip = get_iface_ip(wan)
    if not wan_ip:
        logger.error(f"Interface WAN {wan} sans adresse IP")
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error="L'interface WAN sélectionnée n'a pas d'adresse IP")

    # Récupérer les protocoles sélectionnés
    selected_protocols = request.form.getlist("protocols")
    
    # Validation des protocoles
    valid, error_msg = validate_protocol_list(selected_protocols)
    if not valid:
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error=error_msg)

    # Sauvegarder la configuration
    config_manager.update_interfaces(lan, wan)
    config_manager.update_protocols(selected_protocols)

    # Configurer les protocoles
    reset_protocol_config()  # Désactiver tous les protocoles
    
    for protocol in selected_protocols:
        set_protocol_enabled(protocol, True)
    
    logger.info(f"Démarrage NAT: LAN={lan}, WAN={wan}, WAN_IP={wan_ip}")
    logger.info(f"Protocoles activés: {', '.join(selected_protocols)}")

    # Mise à jour de la configuration
    running_config.update({
        "lan": lan,
        "wan": wan,
        "wan_ip": wan_ip,
        "enabled_protocols": selected_protocols
    })

    # Tentative de démarrage
    if start_nat(lan, wan):
        running_config["status"] = True
        logger.info("NAT démarré avec succès")
    else:
        logger.error("Échec du démarrage du NAT")
        running_config.update({
            "lan": None, 
            "wan": None, 
            "wan_ip": None,
            "enabled_protocols": []
        })
        reset_protocol_config()
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error="Échec du démarrage du NAT. Vérifiez les logs.")
    
    return redirect("/")

@app.route("/nat_table_json")
def nat_table_json():
    """API JSON pour la table NAT."""
    try:
        with lock:
            current_table = dict(nat_table)
        
        connections = []
        for (src_ip, src_port, proto), (wan_ip, public_port) in current_table.items():
            connections.append({
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "wan_ip": wan_ip,
                "public_port": public_port,
                "state": "ACTIVE",
                "duration": "N/A"
            })

        stats = get_nat_stats()
        
        return jsonify({
            "connections": connections,
            "stats": stats,
            "enabled_protocols": get_enabled_protocols(),
            "status": "success"
        })

    except Exception as e:
        logger.error(f"Erreur API table NAT: {e}")
        return jsonify({
            "connections": [],
            "stats": {"active_connections": 0, "used_ports": 0},
            "error": str(e),
            "status": "error"
        })

@app.route("/arp_table_json")
def arp_table_json():
    """API JSON pour la table ARP."""
    try:
        arp_entries = []
        arp_table = get_arp_table()
        
        for ip, mac in arp_table.items():
            arp_entries.append({
                "ip": ip,
                "mac": mac,
                "interface": "auto-detected"
            })

        return jsonify({
            "arp_entries": arp_entries,
            "total_entries": len(arp_entries),
            "status": "success"
        })

    except Exception as e:
        logger.error(f"Erreur API table ARP: {e}")
        return jsonify({
            "arp_entries": [],
            "total_entries": 0,
            "error": str(e),
            "status": "error"
        })

@app.route("/protocol_config", methods=["POST"])
def update_protocol_config():
    """Met à jour la configuration des protocoles en temps réel."""
    try:
        if not running_config["status"]:
            return jsonify({
                "status": "error",
                "message": "NAT non démarré. Impossible de modifier les protocoles."
            })

        data = request.get_json()
        protocol = data.get("protocol")
        enabled = data.get("enabled", False)

        if not protocol:
            return jsonify({
                "status": "error",
                "message": "Protocole non spécifié"
            })

        success = set_protocol_enabled(protocol, enabled)
        if success:
            # Mettre à jour la configuration locale
            if enabled and protocol not in running_config["enabled_protocols"]:
                running_config["enabled_protocols"].append(protocol)
            elif not enabled and protocol in running_config["enabled_protocols"]:
                running_config["enabled_protocols"].remove(protocol)

            return jsonify({
                "status": "success",
                "message": f"Protocole {protocol} {'activé' if enabled else 'désactivé'}",
                "enabled_protocols": get_enabled_protocols()
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Protocole {protocol} inconnu"
            })

    except Exception as e:
        logger.error(f"Erreur modification protocole: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route("/clear_nat_table", methods=["POST"])
def clear_nat_table():
    """Vide la table NAT."""
    try:
        if clear_nat_tables():
            return jsonify({
                "status": "success",
                "message": "Table NAT vidée avec succès"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Erreur lors du vidage de la table NAT"
            })
    except Exception as e:
        logger.error(f"Erreur vidage table NAT: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route("/test_capture/<interface>")
def test_interface(interface):
    """Teste la capture sur une interface."""
    logger.info(f"Test de capture demandé pour {interface}")
    # Note: Cette fonction doit être implémentée dans nat_engine_v2
    # success = test_capture(interface, duration=5)
    
    return jsonify({
        "interface": interface,
        "success": True,  # Placeholder
        "message": "Test de capture non encore implémenté"
    })

@app.route("/stop")
def stop():
    """Arrête le NAT."""
    if stop_nat():
        running_config["status"] = False
        running_config["enabled_protocols"] = []
        reset_protocol_config()
        logger.info("NAT arrêté par l'utilisateur")
    return redirect("/")

@app.route("/stats_json")
def stats_json():
    """API JSON pour les statistiques détaillées."""
    try:
        stats = get_nat_stats()
        return jsonify({
            "status": "success",
            "stats": stats
        })
    except Exception as e:
        logger.error(f"Erreur API statistiques: {e}")
        return jsonify({
            "status": "error",
            "stats": {},
            "message": str(e)
        })

@app.route("/load_preset/<preset_name>")
def load_preset(preset_name):
    """Charge une configuration prédéfinie."""
    from core.nat_config import get_preset_config
    
    preset_config = get_preset_config(preset_name)
    if preset_config:
        # Mettre à jour le gestionnaire de configuration
        config_manager.config = preset_config
        config_manager.save_config()
        
        return jsonify({
            "status": "success",
            "message": f"Configuration '{preset_name}' chargée",
            "config": asdict(preset_config)
        })
    else:
        return jsonify({
            "status": "error",
            "message": f"Configuration prédéfinie '{preset_name}' non trouvée"
        })

def check_root_permissions():
    """Vérifie et affiche les permissions root."""
    if os.geteuid() != 0:
        logger.warning("⚠️  Programme non exécuté en tant que root")
        logger.warning("   La capture de paquets peut échouer")
        logger.warning("   Utilisez: sudo python web/app_v2.py")
    else:
        logger.info("✅ Permissions root OK")

if __name__ == "__main__":
    check_root_permissions()
    app.run(debug=True, host="0.0.0.0")