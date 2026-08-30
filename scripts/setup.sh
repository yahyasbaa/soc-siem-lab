#!/usr/bin/env bash
# SOC & SIEM Security Monitoring Lab - one-time (idempotent) setup.
#
#  1. Verifies prerequisites (docker, compose, python3, vm.max_map_count)
#  2. Creates .env with random lab-only secrets (never overwrites an existing one)
#  3. Creates the Python virtualenv used by tests and tooling
#  4. Renders generated configs (indexer internal users, dashboard API config)
#  5. Generates the TLS certificates for the SIEM components
#  6. Creates the runtime log directories tailed by the lab agents
#  7. Pulls container images
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

info() { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. prerequisites --------------------------------------------------------
command -v docker >/dev/null || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 plugin is required"
docker info >/dev/null 2>&1 || fail "cannot talk to the docker daemon (permissions?)"
command -v python3 >/dev/null || fail "python3 is required"
python3 -c 'import venv' 2>/dev/null || fail "python3-venv is required"
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required"

MAP_COUNT="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"
if [ "$MAP_COUNT" -lt 262144 ]; then
  fail "vm.max_map_count=$MAP_COUNT is too low for OpenSearch. Run: sudo sysctl -w vm.max_map_count=262144"
fi

MEM_KB="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
if [ "${MEM_KB:-0}" -lt 3500000 ]; then
  info "WARNING: less than ~3.5 GB RAM available; the stack may be slow or OOM."
fi

# --- 2. .env -----------------------------------------------------------------
if [ ! -f .env ]; then
  info "Creating .env with generated lab-only secrets"
  python3 - <<'PY'
import secrets, string, re, pathlib
src = pathlib.Path(".env.example").read_text()
def gen():
    # Wazuh API policy: upper, lower, digit and symbol; avoid shell/YAML-special chars
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Lab" + core + "9." + secrets.choice("-.")
out = re.sub(r"__GENERATE__", lambda _m: gen(), src)
p = pathlib.Path(".env"); p.write_text(out); p.chmod(0o600)
PY
else
  info ".env already exists - keeping it"
fi
# shellcheck disable=SC1091
set -a; . ./.env; set +a

# --- 3. python virtualenv ----------------------------------------------------
if [ ! -x .venv/bin/python ]; then
  info "Creating Python virtualenv (.venv)"
  python3 -m venv .venv
fi
.venv/bin/pip install -q --upgrade pip >/dev/null
.venv/bin/pip install -q -r requirements.txt

# --- 4. generated configuration ---------------------------------------------
info "Rendering generated configuration (wazuh/generated/)"
mkdir -p wazuh/generated
.venv/bin/python scripts/render_config.py

# --- 5. certificates ---------------------------------------------------------
if [ ! -f wazuh/certs/root-ca.pem ]; then
  info "Generating TLS certificates"
  mkdir -p wazuh/certs
  docker compose --profile setup run --rm certs >/dev/null 2>&1 || fail "certificate generation failed"
  [ -f wazuh/certs/root-ca.pem ] || fail "certificate generation produced no root CA"
  # The generator writes as root; make the files readable by the containers
  docker run --rm --entrypoint sh -v "$ROOT/wazuh/certs:/c" wazuh/wazuh-certs-generator:0.0.4 -c "chown -R $(id -u):$(id -g) /c && chmod 755 /c && chmod 644 /c/*.pem" \
    || fail "could not fix certificate permissions"
else
  info "Certificates already present - keeping them"
fi

# --- 6. runtime log directories ---------------------------------------------
info "Preparing runtime log directories (runtime/hosts/)"
for h in lab-linux-01 lab-win-01 lab-web-01 lab-nids-01; do
  mkdir -p "runtime/hosts/$h"
  touch "runtime/hosts/$h/heartbeat.log"
done
touch runtime/hosts/lab-linux-01/auth.log runtime/hosts/lab-linux-01/audit.log
touch runtime/hosts/lab-win-01/eventchannel.jsonl
mkdir -p runtime/hosts/lab-web-01/nginx runtime/hosts/lab-nids-01/suricata
touch runtime/hosts/lab-web-01/nginx/access.log runtime/hosts/lab-web-01/nginx/error.log
touch runtime/hosts/lab-nids-01/suricata/eve.json
# nginx (root master inside its container) appends to these host-owned files
chmod 0777 runtime/hosts/lab-web-01/nginx
chmod 0666 runtime/hosts/lab-web-01/nginx/*.log
mkdir -p runtime/evidence reports

# --- 7. images ---------------------------------------------------------------
info "Pulling container images (first run downloads ~3 GB)"
docker compose pull -q

info "Setup complete. Next: make up"
