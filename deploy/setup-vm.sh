#!/usr/bin/env bash
#
# Pregătirea o singură dată a VM-ului pe care rulează serverul EDR.
#
# Rulare, din rădăcina repo-ului, pe VM:
#   sudo bash deploy/setup-vm.sh
#   sudo bash deploy/setup-vm.sh --allow-service-control   # vezi pasul 5
#
# Fiecare pas poate fi rulat din nou fără efecte în plus. Scriptul se oprește
# la prima eroare, deci un pas eșuat nu lasă în urmă jumătate de configurare
# peste care să se aplice următorul.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Rulează cu sudo: sudo bash deploy/setup-vm.sh" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="gabi"
LAN="192.168.16.0/24"
EDR_PORT=8000

step() { printf '\n=== %s\n' "$1"; }

# --- 1. Actualizări ---------------------------------------------------------
# Restul de pachete pe care unattended-upgrades nu le ia (nu sunt de
# securitate). autoremove scoate doar dependențele rămase fără utilizare:
# kernelul care rulează și cel dinaintea lui sunt protejate de apt însuși
# (verificat cu apt-get -s autoremove), deci plasa de siguranță rămâne.
step "1/5 Actualizări de pachete"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
apt-get -y autoremove --purge

# --- 2. SSH doar cu cheie ---------------------------------------------------
# sshd ia, pentru fiecare opțiune, PRIMA valoare găsită, iar fișierele din
# sshd_config.d se citesc alfabetic. 10-* trece deci înaintea lui
# 50-cloud-init.conf, care e cel care pornește parola pe Ubuntu.
step "2/5 SSH: autentificare doar cu cheie"
AUTH_KEYS="/home/${SERVICE_USER}/.ssh/authorized_keys"
if [[ ! -s "$AUTH_KEYS" ]]; then
    echo "Nu există chei în $AUTH_KEYS — opresc, altfel te-ai bloca afară." >&2
    exit 1
fi
echo "Chei autorizate pentru ${SERVICE_USER}:"
awk '{print "  " $1, $NF}' "$AUTH_KEYS"
echo "Conținutul actual al 50-cloud-init.conf:"
sed 's/^/  /' /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null || echo "  (lipsește)"

cat > /etc/ssh/sshd_config.d/10-edr-hardening.conf <<'EOF'
# Pus de edr-server/deploy/setup-vm.sh. Accesul se face doar cu cheie.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sshd -t
systemctl reload ssh
echo "Valori efective:"
sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) ' | sed 's/^/  /'

# --- 3. Firewall ------------------------------------------------------------
# Regulile se adaugă ÎNAINTE de enable, ca sesiunea SSH curentă să nu cadă.
# Doar rețeaua laboratorului ajunge la SSH și la API; restul e refuzat.
step "3/5 Firewall (ufw)"
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$LAN" to any port 22 proto tcp comment 'SSH din laborator'
ufw allow from "$LAN" to any port "$EDR_PORT" proto tcp comment 'API EDR din laborator'
ufw --force enable
ufw status verbose

# --- 4. Serviciul EDR -------------------------------------------------------
step "4/5 Serviciul systemd edr-server"
if ss -ltn "sport = :${EDR_PORT}" | grep -q LISTEN && ! systemctl is-active --quiet edr-server; then
    echo "Portul ${EDR_PORT} e deja ocupat (un uvicorn pornit de mână?). Oprește-l și rulează din nou." >&2
    exit 1
fi
install -m 644 "$REPO_DIR/deploy/edr-server.service" /etc/systemd/system/edr-server.service
systemctl daemon-reload
systemctl enable edr-server
systemctl restart edr-server

# Pornirea amprentează reputation.db: ~10 s cu fișierul în cache, ~30 s la rece.
echo "Aștept /health (până la 90 s)..."
healthy=0
for _ in $(seq 1 90); do
    if curl -fs -o /dev/null "http://127.0.0.1:${EDR_PORT}/health"; then
        healthy=1
        break
    fi
    sleep 1
done
systemctl --no-pager status edr-server | head -12
if [[ $healthy -ne 1 ]]; then
    echo "edr-server nu răspunde pe /health după 90 s. Ultimele linii din journal:" >&2
    journalctl -u edr-server -n 30 --no-pager >&2
    exit 1
fi
echo "/health răspunde."

# --- 5. Control al serviciului fără parolă (opțional) -----------------------
# Doar cu --allow-service-control. Permite lui gabi start/stop/restart/status
# pe ACEST serviciu fără parolă — nimic altceva. Util ca repornirea după o
# modificare de cod să nu ceară parola de fiecare dată.
step "5/5 Control al serviciului fără parolă"
SUDOERS_FILE=/etc/sudoers.d/edr-server
if [[ "${1:-}" == "--allow-service-control" ]]; then
    cat > "${SUDOERS_FILE}.tmp" <<EOF
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start edr-server, /usr/bin/systemctl stop edr-server, /usr/bin/systemctl restart edr-server, /usr/bin/systemctl status edr-server
EOF
    visudo -cf "${SUDOERS_FILE}.tmp"
    install -m 440 "${SUDOERS_FILE}.tmp" "$SUDOERS_FILE"
    rm -f "${SUDOERS_FILE}.tmp"
    echo "Activat: $SUDOERS_FILE"
else
    echo "Sărit (rulează cu --allow-service-control dacă îl vrei)."
fi

step "Gata"
echo "Lasă deschisă sesiunea curentă și verifică dintr-un terminal NOU că SSH-ul cu cheie merge."
