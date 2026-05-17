# 🔍 Linux Log Analyzer – Détection d'activités suspectes

Outil d'analyse de logs Linux orienté **cybersécurité défensive**.  
Développé dans le cadre de ma formation **Bac Pro SN RISC**, en préparation d'une alternance **BTS SIO SISR – Cybersécurité & Réseaux**.

---

## 🎯 Objectif

Simuler le travail d'un analyste **SOC junior** : analyser des fichiers de logs système Linux, détecter des comportements anormaux et générer des alertes de sécurité.

Ce type d'analyse est réalisé quotidiennement dans les centres opérationnels de sécurité (SOC) pour surveiller les systèmes et détecter les intrusions.

---

## 🚨 Ce que l'outil détecte

| Menace | Description |
|---|---|
| **Brute Force SSH** | Détecte les IPs avec trop de tentatives de connexion échouées |
| **Utilisateurs inconnus** | Connexions tentées sur des comptes inexistants |
| **Accès root / sudo** | Élévations de privilèges sur le système |
| **IPs suspectes** | Classement des IPs par nombre de tentatives |
| **Erreurs système** | Segfaults, panics, erreurs critiques kernel |
| **Score de risque** | Évaluation globale du niveau de menace (0–100) |

---

## 🛠 Technologies utilisées

| Outil | Usage |
|---|---|
| **Python 3** | Scripting et analyse |
| **Regex (re)** | Extraction de patterns dans les logs |
| **Collections** | Comptage et tri des événements |
| **Linux auth.log** | Fichier de logs analysé |

---

## 🚀 Installation & utilisation

```bash
# Cloner le dépôt
git clone https://github.com/gasmisandes/log-analyzer-linux.git
cd log-analyzer-linux

# Lancer avec les logs de démonstration
python log_analyzer.py

# Lancer avec un vrai fichier de logs Linux
python log_analyzer.py /var/log/auth.log
```

> Requiert **Python 3.7+** — aucune dépendance externe

---

## 📊 Exemple de résultat

```
══════════════════════════════════════════════════════════════
  RAPPORT D'ANALYSE DE LOGS  ·  15/09/2025 14:32:10
══════════════════════════════════════════════════════════════

  📊 RÉSUMÉ GÉNÉRAL
  ────────────────────────────────────────
  Lignes analysées       : 26
  Tentatives échouées    : 18
  Connexions réussies    : 2
  Accès root/sudo        : 3
  Utilisateurs inconnus  : 2
  Erreurs système        : 1

  🌐 IPs LES PLUS ACTIVES
  ────────────────────────────────────────
  🔴 CRITIQUE  203.0.113.42      11 tentatives  ███████████
  🟡 ALERTE    192.168.1.105      6 tentatives  ██████
  🟢 Normal    198.51.100.7       3 tentatives  ███

  🚨 ALERTE BRUTE FORCE SSH DÉTECTÉE
  → IP 203.0.113.42 : 11 tentatives échouées
  → IP 192.168.1.105 : 6 tentatives échouées

  💡 Recommandation : bloquer ces IPs avec fail2ban ou iptables

  🛡  SCORE DE RISQUE
  65/100 — ÉLEVÉ
  [█████████████░░░░░░░]
```

---

## 🧠 Concepts de cybersécurité abordés

| Concept | Description |
|---|---|
| **Brute Force** | Attaque par essai massif de mots de passe |
| **Logs d'authentification** | Traces des connexions SSH sous Linux |
| **Élévation de privilèges** | Accès non autorisé aux droits root |
| **Analyse SIEM** | Corrélation d'événements de sécurité |
| **Fail2ban / iptables** | Contre-mesures recommandées |
| **Score de risque** | Évaluation quantitative de la menace |

---

## 📁 Structure du projet

```
log-analyzer-linux/
│
├── log_analyzer.py     # Script principal d'analyse
└── README.md           # Documentation
```

---

## 🔗 Projets liés

- [lab-reseau-virtuel](https://github.com/gasmisandes/lab-reseau-virtuel) — Laboratoire réseau sous VirtualBox/Linux

---

## 👩‍💻 Auteure

**Gasmi Sandes**  
Étudiante en BTS SIO SISR – Cybersécurité & Réseaux (alternance)  
Bac Pro SN RISC – Mention Bien  
📧 gasmi.sandes.gf@gmail.com

---

## 📄 Licence

MIT — libre d'utilisation et de modification.
