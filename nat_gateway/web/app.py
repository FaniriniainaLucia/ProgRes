# app.py - Version refactorisée et nettoyée

import sys
import os

# Ajout du chemin parent au PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, redirect, jsonify

from network_utils import list_interfaces, get_iface_ip
from core.nat_engine import start_nat, stop_nat, nat_table, get_nat_stats, lock
from core.logger import get_logger

app = Flask(__name__)
logger = get_logger("WebApp")

# Configuration globale
running_config = {
    "lan": None,
    "wan": None,
    "wan_ip": None,
    "status": False
}

@app.route("/", methods=["GET", "POST"])
def index():
    """Page principale avec configuration du NAT."""
    if request.method == "POST":
        return handle_nat_start()
    
    return render_template("index.html", 
                         interfaces=list_interfaces(), 
                         config=running_config)

def handle_nat_start():
    """Gère le démarrage du NAT depuis le formulaire."""
    if running_config["status"]:
        return redirect("/")
    
    lan = request.form.get("lan")
    wan = request.form.get("wan")
    wan_ip = get_iface_ip(wan)

    if not wan_ip:
        logger.error(f"Interface WAN {wan} sans adresse IP")
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             error="L'interface WAN sélectionnée n'a pas d'adresse IP")

    logger.info(f"Démarrage NAT: LAN={lan}, WAN={wan}, WAN_IP={wan_ip}")

    # Mise à jour de la configuration
    running_config.update({
        "lan": lan,
        "wan": wan,
        "wan_ip": wan_ip
    })

    # Tentative de démarrage
    if start_nat(lan, wan):
        running_config["status"] = True
        logger.info("NAT démarré avec succès")
    else:
        logger.error("Échec du démarrage du NAT")
        running_config.update({"lan": None, "wan": None, "wan_ip": None})
        return render_template("index.html", 
                             interfaces=list_interfaces(), 
                             config=running_config,
                             error="Échec du démarrage du NAT. Vérifiez les logs.")
    
    return redirect("/")

@app.route("/nat_table_json")
def nat_table_json():
    """API JSON pour la table NAT."""
    try:
        with lock:
            current_table = dict(nat_table)
        
        connections = []
        for (src_ip, src_port, proto), (dst_ip, dst_port) in current_table.items():
            connections.append({
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "state": "ESTABLISHED",
                "duration": "N/A"
            })

        return jsonify({
            "connections": connections,
            "stats": get_nat_stats(),
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

@app.route("/test_capture/<interface>")
def test_interface(interface):
    """Teste la capture sur une interface."""
    logger.info(f"Test de capture demandé pour {interface}")
    success = test_capture(interface, duration=5)
    
    return jsonify({
        "interface": interface,
        "success": success,
        "message": "Capture réussie" if success else "Aucun paquet capturé"
    })

@app.route("/stop")
def stop():
    """Arrête le NAT."""
    if stop_nat():
        running_config["status"] = False
        logger.info("NAT arrêté par l'utilisateur")
    return redirect("/")

def check_root_permissions():
    """Vérifie et affiche les permissions root."""
    if os.geteuid() != 0:
        logger.warning("⚠️  Programme non exécuté en tant que root")
        logger.warning("   La capture de paquets peut échouer")
        logger.warning("   Utilisez: sudo python web/app.py")
    else:
        logger.info("✅ Permissions root OK")

if __name__ == "__main__":
    check_root_permissions()
    app.run(debug=True, host="0.0.0.0")