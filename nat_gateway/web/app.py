# app_v2.py - Version améliorée avec filtres protocoles

import sys
import os

# Ajout du chemin parent au PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, redirect, jsonify
import json

from network_utils import list_interfaces, get_iface_ip
from core.nat_engine import (
    start_nat, stop_nat, nat_table, get_nat_stats, lock,
    get_protocol_config, set_protocol_enabled, get_enabled_protocols,
    reset_protocol_config, get_arp_table, clear_nat_tables
)
from core.logger import get_logger

app = Flask(__name__)
logger = get_logger("WebApp")

# Configuration globale
running_config = {
    "lan": None,
    "wan": None,
    "wan_ip": None,
    "status": False,
    "enabled_protocols": []
}

@app.route("/", methods=["GET", "POST"])
def index():
    """Page principale avec configuration du NAT."""
    if request.method == "POST":
        return handle_nat_start()
    
    return render_template("index.html", 
                         interfaces=list_interfaces(), 
                         config=running_config,
                         protocol_config=get_protocol_config(),
                         enabled_protocols=get_enabled_protocols())

def handle_nat_start():
    """Gère le démarrage du NAT depuis le formulaire."""
    if running_config["status"]:
        return redirect("/")
    
    # Récupérer les interfaces
    lan = request.form.get("lan")
    wan = request.form.get("wan")
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
    
    if not selected_protocols:
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             protocol_config=get_protocol_config(),
                             enabled_protocols=get_enabled_protocols(),
                             error="Veuillez sélectionner au moins un protocole à supporter")

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