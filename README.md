# 🔀 NAT Gateway Python (avec Interface Web)

Ce projet est une passerelle NAT (Network Address Translation) écrite en **Python pur**, avec une **interface web** pour :

- Configurer les interfaces réseau
- Visualiser la table NAT en temps réel
- Afficher les clients connectés et leur trafic

---

## 🧰 Dépendances

Ce projet utilise :

- `Flask` : interface web
- `psutil` : détection des interfaces
- `scapy` : manipulation des paquets IP
- `NetfilterQueue` : interception des paquets via `iptables`
- `libnetfilter-queue-dev` : dépendance native obligatoire

---

## ⚙️ Installation (Linux Debian/Ubuntu)

### 1. Installer les paquets système :

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-full \
    python3-pip \
    libnfnetlink-dev libnetfilter-queue-dev
```

### 2. Créer et activer un environnement virtuel :

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installer les dépendances Python :

```bash
pip install flask psutil scapy NetfilterQueue
```

---

## 🚀 Lancement de l’application

Tu dois lancer l’application **avec les privilèges root**, mais en gardant le Python du venv :

```bash
sudo venv/bin/python app.py
```

Le serveur Flask sera accessible sur :

```
http://localhost:5000
```

---

## 🌐 Interface Web

L’interface permet de :

- Choisir les interfaces LAN / WAN
- Afficher la table NAT en temps réel
- Voir les clients connectés (IP, ports, protocoles)
- Suivre le trafic par client (à venir)

---

## 🧪 Environnement de test recommandé

- Utiliser **Hyper-V** avec :
  - une interface en **réseau interne** (LAN)
  - une interface en **bridge** ou **partage de connexion** (WAN)
- Ou bien :
  - un téléphone Android en partage USB
  - un point d’accès Wi-Fi émis par la même machine

---

## 📌 Notes

- L’application intercepte et modifie le trafic réseau en temps réel
- Elle s’appuie sur `iptables` et `NetfilterQueue`, donc nécessite les droits root
- Les règles `iptables` sont ajoutées automatiquement au lancement (à implémenter)

---

## 📎 Structure du projet

```
nat_gateway/
├── app.py               # Serveur Flask + interface web
├── nat_core.py          # Logique NAT (paquets, table NAT)
├── net_utils.py         # Utilitaires réseau
├── templates/
│   └── index.html       # Interface HTML principale
├── static/              # (à ajouter si besoin de CSS ou JS)
├── venv/                # Environnement Python virtuel (ne pas versionner)
└── README.md            # Ce fichier
```

---

## ✅ À faire / TODO

- [ ] Suivi du trafic (octets envoyés/reçus)
- [ ] Logs des connexions
- [ ] Blocage par IP/MAC
- [ ] Configuration persistante (fichier .json ou .yaml)
- [ ] Tests avec clients Python automatisés

---