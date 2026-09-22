#!/usr/bin/env bash
# SOC & SIEM Security Monitoring Lab - health check.
#
# Verifies the whole pipeline, not just that containers are up:
#   containers  -> SIEM APIs -> agents -> rules/decoders -> indices
#   -> live ingestion (heartbeat on every lab host + a real Nginx request
#      must come back as alerts in the indexer) -> dashboards
#
# Exit code: 0 if every check passes, 1 otherwise.
# Options:  --wait N   wait up to N seconds for services/agents first (default 0)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f .env ] || { echo "ERROR: .env missing - run 'make setup'"; exit 1; }
set -a; . ./.env; set +a

WAIT=0
[ "${1:-}" = "--wait" ] && WAIT="${2:-180}"

PASS=0; FAIL=0
ok()   { printf '  \033[32m[PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
section() { printf '\n\033[1m%s\033[0m\n' "$*"; }

IDX="https://127.0.0.1:${INDEXER_PORT}"
API="https://127.0.0.1:${API_PORT}"
DSH="https://127.0.0.1:${DASHBOARD_PORT}"
icurl() { curl -sk --max-time 15 -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" "$@"; }
EXPECTED_AGENTS="lab-linux-01 lab-win-01 lab-web-01 lab-nids-01"
SERVICES="wazuh.indexer wazuh.manager wazuh.dashboard lab-linux-01 lab-win-01 lab-web-01 lab-nids-01 web-nginx"
EXPECTED_RULES=$(grep -c '<rule id="100' wazuh/manager/etc/rules/soc_lab_rules.xml)

api_token() {
  curl -sk --max-time 15 -u "${API_USERNAME}:${API_PASSWORD}" -X POST "${API}/security/user/authenticate?raw=true"
}

# ---------------------------------------------------------------- wait (optional)
if [ "$WAIT" -gt 0 ]; then
  echo "Waiting up to ${WAIT}s for the SIEM and agents..."
  end=$(( $(date +%s) + WAIT ))
  while [ "$(date +%s)" -lt "$end" ]; do
    T=$(api_token 2>/dev/null)
    n=$(curl -sk --max-time 10 -H "Authorization: Bearer $T" "${API}/agents?status=active&select=name" 2>/dev/null \
        | jq -r '.data.affected_items[].name' 2>/dev/null | grep -c '^lab-')
    st=$(icurl "${DSH}/api/status" 2>/dev/null | jq -r '.status.overall.state' 2>/dev/null)
    [ "${n:-0}" -ge 4 ] && [ "$st" = "green" ] && break
    sleep 5
  done
fi

# ---------------------------------------------------------------- containers
section "1. Containers"
for s in $SERVICES; do
  cid=$(docker compose ps -aq "$s" 2>/dev/null)
  if [ -z "$cid" ]; then bad "$s: not created"; continue; fi
  state=$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
  case "$state" in
    running/healthy|running/none) ok "$s: $state" ;;
    *) bad "$s: $state" ;;
  esac
done

# ---------------------------------------------------------------- SIEM services
section "2. SIEM services"
H=$(icurl "${IDX}/_cluster/health" | jq -r '.status' 2>/dev/null)
case "$H" in green|yellow) ok "Wazuh indexer (OpenSearch) cluster health: $H" ;; *) bad "Wazuh indexer cluster health: ${H:-unreachable}" ;; esac
TOKEN=$(api_token)
if [ "${#TOKEN}" -gt 50 ]; then ok "Wazuh manager API authentication"; else bad "Wazuh manager API authentication"; fi
AUTH=(-H "Authorization: Bearer ${TOKEN}")
MS=$(curl -sk --max-time 15 "${AUTH[@]}" "${API}/manager/status" | jq -r '.data.affected_items[0] | to_entries[] | select(.key=="wazuh-analysisd" or .key=="wazuh-remoted" or .key=="wazuh-db" or .key=="wazuh-authd") | "\(.key)=\(.value)"' 2>/dev/null)
for d in wazuh-analysisd wazuh-remoted wazuh-db wazuh-authd; do
  if echo "$MS" | grep -q "^$d=running$"; then ok "manager daemon $d running"; else bad "manager daemon $d not running"; fi
done
FB=$(docker compose exec -T wazuh.manager sh -c 'filebeat test output 2>&1 | grep -c "talk to server... OK"' 2>/dev/null | tr -d '\r')
if [ "${FB:-0}" -ge 1 ]; then ok "Filebeat -> indexer output"; else bad "Filebeat cannot reach the indexer"; fi

# ---------------------------------------------------------------- agents
section "3. Agents"
AG=$(curl -sk --max-time 15 "${AUTH[@]}" "${API}/agents?select=name,status&limit=500" | jq -r '.data.affected_items[] | "\(.name)=\(.status)"')
for a in $EXPECTED_AGENTS; do
  st=$(echo "$AG" | grep "^$a=" | cut -d= -f2)
  if [ "$st" = "active" ]; then ok "agent $a active"; else bad "agent $a ${st:-not registered}"; fi
done

# ---------------------------------------------------------------- rules
section "4. Detection rules and decoders"
LOADED=$(curl -sk --max-time 15 "${AUTH[@]}" "${API}/rules?filename=soc_lab_rules.xml&limit=500" | jq -r '.data.total_affected_items')
if [ "${LOADED:-0}" -eq "$EXPECTED_RULES" ]; then ok "SOC lab rules loaded: $LOADED/$EXPECTED_RULES"; else bad "SOC lab rules loaded: ${LOADED:-0}/$EXPECTED_RULES"; fi
DEC=$(curl -sk --max-time 15 "${AUTH[@]}" "${API}/decoders?filename=soc_lab_decoders.xml&limit=100" | jq -r '.data.total_affected_items')
if [ "${DEC:-0}" -ge 4 ]; then ok "SOC lab decoders loaded: $DEC"; else bad "SOC lab decoders loaded: ${DEC:-0}"; fi
LT=$(curl -sk --max-time 15 "${AUTH[@]}" -X PUT "${API}/logtest" -H 'Content-Type: application/json' \
  -d '{"event":"Oct  3 10:00:00 lab-linux-01 sudo:  hc-user : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash","location":"/var/log/lab/auth.log","log_format":"syslog"}' \
  | jq -r '.data.output.rule.id')
if [ "$LT" = "100120" ]; then ok "rule engine evaluates SOC rules (logtest -> 100120)"; else bad "logtest returned rule ${LT:-none}, expected 100120"; fi

# ---------------------------------------------------------------- indices
section "5. Indices"
for p in "wazuh-alerts-4.x-*" "wazuh-archives-4.x-*" "soc-incidents"; do
  c=$(icurl "${IDX}/${p}/_count?allow_no_indices=false" | jq -r '.count' 2>/dev/null)
  if [ -n "$c" ] && [ "$c" != "null" ]; then ok "index $p exists ($c docs)"; else bad "index $p missing"; fi
done

# ---------------------------------------------------------------- live ingestion
section "6. Live log ingestion (end-to-end)"
NONCE="hc$(date +%s)$RANDOM"
SINCE=$(date -u -d '-10 seconds' +%Y-%m-%dT%H:%M:%S.000Z)
"$ROOT/.venv/bin/python" scripts/generate-test-events/generate.py heartbeat --nonce "$NONCE" >/dev/null \
  || bad "could not write heartbeat events"
docker compose exec -T lab-web-01 curl -s -o /dev/null "http://web-nginx/soc-lab-heartbeat?nonce=${NONCE}" \
  || bad "lab-web-01 could not reach web-nginx"
deadline=$(( $(date +%s) + 90 ))
HB=0; WEB=0; EV=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  HB=$(icurl -H 'Content-Type: application/json' "${IDX}/wazuh-alerts-4.x-*/_search" -d "{\"size\":10,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"rule.id\":\"100090\"}},{\"match_phrase\":{\"data.nonce\":\"${NONCE}\"}}]}}}" | jq -r '[.hits.hits[]._source.agent.name] | unique | length')
  WEB=$(icurl -H 'Content-Type: application/json' "${IDX}/wazuh-alerts-4.x-*/_search" -d "{\"size\":1,\"query\":{\"bool\":{\"filter\":[{\"term\":{\"rule.id\":\"100091\"}},{\"range\":{\"timestamp\":{\"gte\":\"${SINCE}\"}}},{\"wildcard\":{\"data.url\":\"*${NONCE}*\"}}]}}}" | jq -r '.hits.total.value')
  EV=$(icurl -H 'Content-Type: application/json' "${IDX}/wazuh-archives-4.x-*/_count" -d "{\"query\":{\"match_phrase\":{\"full_log\":\"${NONCE}\"}}}" | jq -r '.count')
  [ "${HB:-0}" -ge 4 ] && [ "${WEB:-0}" -ge 1 ] && [ "${EV:-0}" -ge 4 ] && break
  sleep 3
done
if [ "${HB:-0}" -ge 4 ]; then ok "heartbeat from all 4 lab hosts searchable in the indexer"; else bad "heartbeat searchable from ${HB:-0}/4 hosts"; fi
if [ "${WEB:-0}" -ge 1 ]; then ok "real Nginx access log ingested and alerted (rule 100091)"; else bad "Nginx request not found in the indexer"; fi
if [ "${EV:-0}" -ge 4 ]; then ok "raw events searchable in archives ($EV events)"; else bad "raw events not found in archives (${EV:-0})"; fi

# ---------------------------------------------------------------- dashboards
section "7. Dashboards"
ST=$(icurl "${DSH}/api/status" | jq -r '.status.overall.state' 2>/dev/null)
if [ "$ST" = "green" ]; then ok "Wazuh dashboard status: green"; else bad "Wazuh dashboard status: ${ST:-unreachable}"; fi
DB=$(icurl -H 'osd-xsrf: true' "${DSH}/api/saved_objects/dashboard/soc-lab-overview" | jq -r '.attributes.title' 2>/dev/null)
if [ "$DB" = "SOC Lab - Security Overview" ]; then ok "SOC dashboard imported"; else bad "SOC dashboard missing (run 'make dashboards')"; fi

# ---------------------------------------------------------------- summary
echo
TOTAL=$((PASS+FAIL))
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mHEALTHY\033[0m - %d/%d checks passed\n' "$PASS" "$TOTAL"; exit 0
else
  printf '\033[31mUNHEALTHY\033[0m - %d/%d checks failed\n' "$FAIL" "$TOTAL"; exit 1
fi
