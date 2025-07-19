# app.py

from flask import Flask, render_template, request, redirect
from network_utils import list_interfaces, get_iface_ip
from nat_core import start_nat, stop_nat, get_nat_table, nat_table


app = Flask(__name__)

running_config = {
    "lan": None,
    "wan": None,
    "wan_ip": None,
    "status": False
}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        lan = request.form.get("lan")
        wan = request.form.get("wan")
        wan_ip = get_iface_ip(wan)

        running_config.update({
            "lan": lan,
            "wan": wan,
            "wan_ip": wan_ip
        })

        start_nat(lan, wan, wan_ip)
        running_config["status"] = True
        return redirect("/")

    interfaces = list_interfaces()
    return render_template("index.html", interfaces=interfaces, config=running_config)

@app.route("/nat_table")
def nat_table_view():
    rows = ""
    for key, val in nat_table.items():
        src_ip, src_port, proto = key
        pub_ip, pub_port = val
        rows += f"<tr><td>{src_ip}:{src_port}</td><td>{pub_ip}:{pub_port}</td><td>{proto}</td></tr>"
    table_html = f"""
    <table class="table table-bordered table-sm">
      <thead><tr><th>Client Privé</th><th>Adresse NAT</th><th>Protocole</th></tr></thead>
      <tbody>{rows or '<tr><td colspan=3>Aucune connexion</td></tr>'}</tbody>
    </table>
    """
    return table_html
    
@app.route("/stop")
def stop():
    stop_nat()
    running_config["status"] = False
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
