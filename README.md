# NAT Router Python - Projet Routeur Logiciel Multi-Clients

Ce projet est une application Python qui implémente un routeur logiciel capable de faire du NAT (Network Address Translation) entre deux interfaces réseau (LAN/WAN), de superviser le trafic réseau, et de visualiser dynamiquement les activités du réseau local.

---

## 🌐 Objectif principal

Construire un **routeur logiciel portable** (Linux, Windows, macOS) qui :

* Traduit les adresses IP et ports (SNAT/DNAT)
* Supervise le trafic réseau (volume, protocoles, connexions par client)
* Fournit une interface web pour contrôle et visualisation
* Gère plusieurs clients simultanément (Python ou non)
* Ne dépend d'aucun outil spécifique à Linux (iptables, /proc/sys/net/...)

---

## 🚧 Fonctionnalités principales

### NAT (Network Address Translation)

* Traitement bidirectionnel (LAN <-> WAN)
* Traduction manuelle des adresses et ports
* Table NAT dynamique avec expiration possible

### Supervision et Monitoring

* Identification des clients LAN
* Suivi du trafic par IP (packets, octets, connexions)
* Visualisation temps réel via l'interface web (JS + WebSocket/AJAX)

### Interface web Flask

* Formulaire de sélection des interfaces LAN/WAN
* Affichage de la table NAT
* Vue par client : trafic, protocoles, connexions

### Support multi-plateforme

* Fonctionne sous Linux, Windows et macOS
* Installation simple avec `pip` ou via binaire `PyInstaller`

---

## 📁 Structure du projet

```
nat_gateway/
│
├── core/
│   ├── nat_engine.py
│   ├── packet_capture.py
│   ├── client_tracker.py
│   └── ...
│
├── web/
│   ├── templates/
│   │   └── index.html
│   ├── static/
│   └── dashboard.py
│
├── clients/
│   ├── test_client.py
│   └── ...
│
├── utils/
│   └── network.py
│
├── README.md
└── requirements.txt

```

---

## ⚡ Installation rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-utilisateur/nat-router-python.git
cd nat-router-python

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application web
python app.py
```

---

## 🚀 État du projet

| Composant                    | Statut          |
| ---------------------------- | --------------- |
| NAT bidirectionnel           | ⭕ à implémenter |
| Table NAT dynamique          | ⭕ à implémenter |
| Interface web de base        | ✅ Fonctionnelle |
| Monitoring par client        | ⭕ à implémenter |
| Support clients Python/non   | ⭕ en cours      |
| Installation multiplateforme | ✅ Compatible    |

---

## 🌐 Contribuer

Toute aide est la bienvenue pour :

* Ajouter des graphes temps réel
* Améliorer la reconnaissance des clients LAN
* Implémenter un timeout pour les connexions NAT inactives

---

## 🛡️ Avertissement

Ce projet accède directement aux paquets réseau et peut nécessiter les droits root/admin sur certaines plateformes.
Utiliser à des fins éducatives ou de laboratoire. Ne jamais utiliser sur un réseau public sans autorisation.

---

## 📅 Auteur

Ambinintsoa Marckel - 2025
