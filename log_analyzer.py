"""
================================================================
  Linux Log Analyzer – Détection d'activités suspectes
  Auteur  : Gasmi Sandes
  Projet  : Analyse de logs système Linux orientée cybersécurité
  Description : Analyse les fichiers de logs Linux (/var/log/auth.log,
                syslog...) pour détecter des comportements suspects :
                tentatives de connexion échouées, brute force SSH,
                accès root non autorisés, IPs suspectes.
================================================================
"""

import re
import sys
import os
from collections import defaultdict
from datetime import datetime

# ── Couleurs terminal ─────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Seuils d'alerte ───────────────────────────────────────────
SEUIL_BRUTE_FORCE   = 5   # nb tentatives échouées avant alerte
SEUIL_IP_SUSPECTE   = 10  # nb d'échecs par IP avant alerte critique

# ── Patterns de détection ─────────────────────────────────────
PATTERNS = {
    "echec_connexion": re.compile(
        r"(?:Failed password|authentication failure|Invalid user)\s+(?:for\s+)?(\S+)?\s*(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?",
        re.IGNORECASE
    ),
    "succes_connexion": re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE
    ),
    "acces_root": re.compile(
        r"(?:su|sudo).*(?:root|COMMAND=)",
        re.IGNORECASE
    ),
    "connexion_ssh": re.compile(
        r"sshd.*(?:session opened|Accepted)",
        re.IGNORECASE
    ),
    "utilisateur_inconnu": re.compile(
        r"Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE
    ),
    "erreur_systeme": re.compile(
        r"(?:error|critical|panic|segfault|kernel)",
        re.IGNORECASE
    ),
}

# ── Logs de démonstration (si pas de vrai fichier) ───────────
LOGS_DEMO = """Jan 15 10:23:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 52341 ssh2
Jan 15 10:23:03 server sshd[1234]: Failed password for root from 192.168.1.105 port 52342 ssh2
Jan 15 10:23:05 server sshd[1234]: Failed password for admin from 192.168.1.105 port 52343 ssh2
Jan 15 10:23:07 server sshd[1234]: Failed password for root from 192.168.1.105 port 52344 ssh2
Jan 15 10:23:09 server sshd[1234]: Failed password for ubuntu from 192.168.1.105 port 52345 ssh2
Jan 15 10:23:11 server sshd[1234]: Failed password for root from 192.168.1.105 port 52346 ssh2
Jan 15 10:25:00 server sshd[1235]: Accepted password for alice from 10.0.0.15 port 54321 ssh2
Jan 15 10:25:01 server sshd[1235]: pam_unix(sshd:session): session opened for user alice
Jan 15 10:30:00 server sudo[1236]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
Jan 15 10:31:00 server sshd[1237]: Failed password for invalid user hacker from 203.0.113.42 port 12345 ssh2
Jan 15 10:31:02 server sshd[1237]: Invalid user hacker from 203.0.113.42 port 12346
Jan 15 10:31:04 server sshd[1237]: Failed password for invalid user admin from 203.0.113.42 port 12347 ssh2
Jan 15 10:31:06 server sshd[1237]: Failed password for invalid user test from 203.0.113.42 port 12348 ssh2
Jan 15 10:31:08 server sshd[1237]: Failed password for root from 203.0.113.42 port 12349 ssh2
Jan 15 10:31:10 server sshd[1237]: Failed password for admin from 203.0.113.42 port 12350 ssh2
Jan 15 10:31:12 server sshd[1237]: Failed password for user from 203.0.113.42 port 12351 ssh2
Jan 15 10:31:14 server sshd[1237]: Failed password for root from 203.0.113.42 port 12352 ssh2
Jan 15 10:31:16 server sshd[1237]: Failed password for oracle from 203.0.113.42 port 12353 ssh2
Jan 15 10:31:18 server sshd[1237]: Failed password for postgres from 203.0.113.42 port 12354 ssh2
Jan 15 10:31:20 server sshd[1237]: Failed password for mysql from 203.0.113.42 port 12355 ssh2
Jan 15 10:45:00 server kernel: segfault at 0 ip 00007f error 4 in libc.so
Jan 15 11:00:00 server sshd[1238]: Accepted publickey for bob from 10.0.0.20 port 44444 ssh2
Jan 15 11:05:00 server su[1239]: Successful su for root by bob
Jan 15 11:30:00 server sshd[1240]: Failed password for root from 198.51.100.7 port 22222 ssh2
Jan 15 11:30:02 server sshd[1240]: Failed password for root from 198.51.100.7 port 22223 ssh2
Jan 15 11:30:04 server sshd[1240]: Failed password for root from 198.51.100.7 port 22224 ssh2"""


# ── Fonctions d'analyse ───────────────────────────────────────

def banner():
    print(f"""
{CYAN}{BOLD}
 ██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
 ██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{DIM}  Détection d'activités suspectes dans les logs Linux  |  by Gasmi Sandes{RESET}
""")


def charger_logs(chemin=None):
    """
    Charge les logs depuis un fichier ou utilise les logs de démonstration.
    Sur Linux, les logs sont dans /var/log/auth.log ou /var/log/syslog.
    """
    if chemin and os.path.exists(chemin):
        print(f"  {GREEN}✔{RESET} Chargement du fichier : {BOLD}{chemin}{RESET}")
        with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    else:
        if chemin:
            print(f"  {YELLOW}⚠{RESET}  Fichier '{chemin}' introuvable.")
        print(f"  {CYAN}→{RESET}  Utilisation des logs de démonstration.\n")
        return LOGS_DEMO.strip().split("\n")


def analyser(lignes):
    """
    Parcourt chaque ligne de log et extrait les événements.
    Retourne un dictionnaire de résultats structurés.
    """
    resultats = {
        "total_lignes"      : len(lignes),
        "echecs"            : [],        # (utilisateur, ip, ligne)
        "succes"            : [],        # (utilisateur, ip)
        "acces_root"        : [],        # lignes brutes
        "utilisateurs_inc"  : [],        # (utilisateur, ip)
        "erreurs_systeme"   : [],        # lignes brutes
        "echecs_par_ip"     : defaultdict(int),
        "echecs_par_user"   : defaultdict(int),
    }

    for i, ligne in enumerate(lignes, 1):
        ligne = ligne.strip()

        # Tentatives de connexion échouées
        m = PATTERNS["echec_connexion"].search(ligne)
        if m:
            user = m.group(1) or "inconnu"
            ip   = m.group(2) or "IP inconnue"
            resultats["echecs"].append((user, ip, ligne))
            resultats["echecs_par_ip"][ip] += 1
            resultats["echecs_par_user"][user] += 1

        # Connexions réussies
        m = PATTERNS["succes_connexion"].search(ligne)
        if m:
            resultats["succes"].append((m.group(1), m.group(2)))

        # Accès root / sudo
        if PATTERNS["acces_root"].search(ligne):
            resultats["acces_root"].append(ligne)

        # Utilisateurs inconnus
        m = PATTERNS["utilisateur_inconnu"].search(ligne)
        if m:
            resultats["utilisateurs_inc"].append((m.group(1), m.group(2)))

        # Erreurs système
        if PATTERNS["erreur_systeme"].search(ligne):
            resultats["erreurs_systeme"].append(ligne)

    return resultats


def afficher_rapport(r):
    """
    Affiche le rapport d'analyse complet avec alertes colorées.
    """
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    print(f"\n{BOLD}{CYAN}{'═'*62}{RESET}")
    print(f"{BOLD}  RAPPORT D'ANALYSE DE LOGS{RESET}  {DIM}· {now}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*62}{RESET}\n")

    # ── Résumé général ──
    print(f"{BOLD}  📊 RÉSUMÉ GÉNÉRAL{RESET}")
    print(f"  {'─'*40}")
    print(f"  Lignes analysées       : {BOLD}{r['total_lignes']}{RESET}")
    print(f"  Tentatives échouées    : {RED}{BOLD}{len(r['echecs'])}{RESET}")
    print(f"  Connexions réussies    : {GREEN}{len(r['succes'])}{RESET}")
    print(f"  Accès root/sudo        : {YELLOW}{len(r['acces_root'])}{RESET}")
    print(f"  Utilisateurs inconnus  : {YELLOW}{len(r['utilisateurs_inc'])}{RESET}")
    print(f"  Erreurs système        : {RED}{len(r['erreurs_systeme'])}{RESET}")

    # ── IPs suspectes ──
    print(f"\n{BOLD}  🌐 IPs LES PLUS ACTIVES (tentatives échouées){RESET}")
    print(f"  {'─'*40}")
    ips_triees = sorted(r["echecs_par_ip"].items(), key=lambda x: x[1], reverse=True)

    if not ips_triees:
        print(f"  {GREEN}Aucune IP suspecte détectée.{RESET}")
    else:
        for ip, nb in ips_triees[:10]:
            if nb >= SEUIL_IP_SUSPECTE:
                niveau = f"{RED}{BOLD}🔴 CRITIQUE{RESET}"
            elif nb >= SEUIL_BRUTE_FORCE:
                niveau = f"{YELLOW}{BOLD}🟡 ALERTE  {RESET}"
            else:
                niveau = f"{GREEN}🟢 Normal  {RESET}"
            barre = "█" * min(nb, 30)
            print(f"  {niveau}  {ip:<18} {nb:>3} tentatives  {CYAN}{barre}{RESET}")

    # ── Brute force SSH ──
    ips_bf = [(ip, nb) for ip, nb in ips_triees if nb >= SEUIL_BRUTE_FORCE]
    if ips_bf:
        print(f"\n{RED}{BOLD}  🚨 ALERTE BRUTE FORCE SSH DÉTECTÉE{RESET}")
        print(f"  {'─'*40}")
        for ip, nb in ips_bf:
            print(f"  {RED}→ IP {ip} : {nb} tentatives échouées{RESET}")
        print(f"\n  {YELLOW}💡 Recommandation : bloquer ces IPs avec fail2ban ou iptables{RESET}")

    # ── Connexions réussies ──
    if r["succes"]:
        print(f"\n{BOLD}  ✅ CONNEXIONS RÉUSSIES{RESET}")
        print(f"  {'─'*40}")
        for user, ip in r["succes"]:
            print(f"  {GREEN}✔{RESET}  Utilisateur {BOLD}{user}{RESET} depuis {ip}")

    # ── Accès root ──
    if r["acces_root"]:
        print(f"\n{YELLOW}{BOLD}  ⚠  ACCÈS ROOT / SUDO DÉTECTÉS{RESET}")
        print(f"  {'─'*40}")
        for ligne in r["acces_root"][:5]:
            print(f"  {YELLOW}→{RESET} {DIM}{ligne[:80]}...{RESET}" if len(ligne) > 80 else f"  {YELLOW}→{RESET} {DIM}{ligne}{RESET}")

    # ── Utilisateurs inconnus ──
    if r["utilisateurs_inc"]:
        print(f"\n{RED}{BOLD}  🔍 UTILISATEURS INCONNUS TENTÉS{RESET}")
        print(f"  {'─'*40}")
        users_uniques = list(set(r["utilisateurs_inc"]))
        for user, ip in users_uniques[:8]:
            print(f"  {RED}→{RESET} Utilisateur '{BOLD}{user}{RESET}' depuis {ip}")

    # ── Erreurs système ──
    if r["erreurs_systeme"]:
        print(f"\n{RED}{BOLD}  💥 ERREURS SYSTÈME{RESET}")
        print(f"  {'─'*40}")
        for ligne in r["erreurs_systeme"][:3]:
            print(f"  {RED}→{RESET} {DIM}{ligne[:80]}{RESET}")

    # ── Score de risque ──
    score = 0
    score += min(len(ips_bf) * 20, 40)
    score += min(len(r["utilisateurs_inc"]) * 5, 20)
    score += min(len(r["acces_root"]) * 10, 20)
    score += min(len(r["erreurs_systeme"]) * 5, 20)
    score = min(score, 100)

    if score < 20:   niveau_r, couleur_r = "FAIBLE",   GREEN
    elif score < 50: niveau_r, couleur_r = "MODÉRÉ",   YELLOW
    elif score < 75: niveau_r, couleur_r = "ÉLEVÉ",    RED
    else:            niveau_r, couleur_r = "CRITIQUE",  RED

    barre_s = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    print(f"\n{BOLD}  🛡  SCORE DE RISQUE{RESET}")
    print(f"  {'─'*40}")
    print(f"  {couleur_r}{BOLD}{score}/100 — {niveau_r}{RESET}")
    print(f"  {couleur_r}[{barre_s}]{RESET}\n")

    print(f"{BOLD}{CYAN}{'═'*62}{RESET}\n")


def exporter_rapport(r, chemin_sortie="rapport_logs.txt"):
    """Exporte le rapport dans un fichier texte."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with open(chemin_sortie, "w", encoding="utf-8") as f:
        f.write(f"=== RAPPORT D'ANALYSE DE LOGS ===\n")
        f.write(f"Date    : {now}\n")
        f.write(f"Lignes  : {r['total_lignes']}\n\n")
        f.write(f"ÉCHECS DE CONNEXION : {len(r['echecs'])}\n")
        f.write(f"CONNEXIONS RÉUSSIES : {len(r['succes'])}\n")
        f.write(f"ACCÈS ROOT/SUDO     : {len(r['acces_root'])}\n\n")
        f.write("IPs SUSPECTES :\n")
        for ip, nb in sorted(r["echecs_par_ip"].items(), key=lambda x: x[1], reverse=True):
            f.write(f"  {ip} — {nb} tentatives\n")
    print(f"  {GREEN}✔ Rapport exporté : {chemin_sortie}{RESET}\n")


# ── Point d'entrée ────────────────────────────────────────────
def main():
    banner()

    print(f"  {DIM}Fichiers Linux courants : /var/log/auth.log | /var/log/syslog{RESET}\n")

    chemin = None
    if len(sys.argv) > 1:
        chemin = sys.argv[1]
    else:
        rep = input(f"  {BOLD}Chemin vers un fichier de log (Entrée = démo) :{RESET} ").strip()
        chemin = rep if rep else None

    lignes   = charger_logs(chemin)
    resultats = analyser(lignes)
    afficher_rapport(resultats)

    choix = input(f"  Exporter le rapport en fichier texte ? (o/n) : ").strip().lower()
    if choix == "o":
        exporter_rapport(resultats)


if __name__ == "__main__":
    main()
