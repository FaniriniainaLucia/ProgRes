import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, render_template, request, redirect, jsonify

from network_utils import list_interfaces, get_iface_ip
from core.nat_engine import start_nat, stop_nat, nat_table, get_nat_stats, test_capture, debug_scapy_config, lock
from core.logger import get_logger

app = Flask(__name__)
logger = get_logger("app")

running_config = {
    "lan": None,
    "wan": None,
    "wan_ip": None,
    "status": False
}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if not running_config["status"]:
            lan = request.form.get("lan")
            wan = request.form.get("wan")
            wan_ip = get_iface_ip(wan)

            if not wan_ip:
                logger.error(f"Interface WAN {wan} n'a pas d'adresse IP")
                return render_template("index.html", 
                                     interfaces=list_interfaces(), 
                                     config=running_config,
                                     error="L'interface WAN sélectionnée n'a pas d'adresse IP")

            logger.info(f"Configuration sélectionnée: LAN={lan}, WAN={wan}, WAN_IP={wan_ip}")

            running_config.update({
                "lan": lan,
                "wan": wan,
                "wan_ip": wan_ip
            })

            # Tenter de démarrer le NAT
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

    interfaces = list_interfaces()
    return render_template("index.html", interfaces=interfaces, config=running_config)



@app.route("/nat_table_json")
def nat_table_json():
    """API JSON pour la table NAT - format adapté au front-end."""
    try:
        with lock:
            current_table = dict(nat_table)
        
        connections = []
        for key, val in current_table.items():
            src_ip, src_port, proto = key
            dst_ip, dst_port = val

            connections.append({
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "state": "ESTABLISHED",  # ⬅️ temporaire — à améliorer si tu as un vrai suivi d'état
                "duration": "N/A"        # ⬅️ idem, tu peux ajouter un timestamp plus tard
            })

        stats = get_nat_stats()

        return jsonify({
            "connections": connections,
            "stats": stats,
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
    if stop_nat():
        running_config["status"] = False
        logger.info("NAT arrêté par l'utilisateur")
    return redirect("/")

@app.route("/debug")
def debug_info():
    """Page de debug avec informations système."""
    import psutil
    from scapy.all import get_if_list, get_if_addr
    
    # Afficher la config Scapy dans les logs
    debug_scapy_config()
    
    debug_data = {
        "interfaces_scapy": [],
        "interfaces_psutil": list_interfaces(),
        "running_config": running_config,
        "nat_stats": get_nat_stats() if running_config["status"] else None
    }
    
    # Informations Scapy
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            debug_data["interfaces_scapy"].append({"name": iface, "ip": ip})
        except:
            debug_data["interfaces_scapy"].append({"name": iface, "ip": "Erreur"})
    
    return render_template("debug.html", debug=debug_data)

if __name__ == "__main__":
    # Vérifier les permissions root
    if os.geteuid() != 0:
        logger.warning("⚠️  Attention: Le programme ne s'exécute pas en tant que root.")
        logger.warning("   La capture de paquets peut ne pas fonctionner correctement.")
        logger.warning("   Utilisez: sudo python web/app.py")
    else:
        logger.info("✅ Exécution en tant que root - permissions OK")
    
    app.run(debug=True, host="0.0.0.0")