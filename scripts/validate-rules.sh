#!/usr/bin/env bash
# Validate the SOC lab decoders/rules with the manager's own parser
# (wazuh-analysisd -t) without restarting the running manager.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C="$(docker compose -f "$ROOT/docker-compose.yml" ps -q wazuh.manager)"
[ -n "$C" ] || { echo "wazuh.manager is not running" >&2; exit 1; }
docker cp "$ROOT/wazuh/manager/etc/rules/soc_lab_rules.xml" "$C:/var/ossec/etc/rules/soc_lab_rules.xml"
docker cp "$ROOT/wazuh/manager/etc/decoders/soc_lab_decoders.xml" "$C:/var/ossec/etc/decoders/soc_lab_decoders.xml"
OUT="$(docker exec "$C" /var/ossec/bin/wazuh-analysisd -t 2>&1 || true)"
if echo "$OUT" | grep -qE "ERROR|CRITICAL"; then
  echo "$OUT" | grep -E "ERROR|CRITICAL|WARNING" >&2
  echo "rule validation FAILED" >&2
  exit 1
fi
echo "$OUT" | grep -E "WARNING" || true
echo "rules and decoders OK"
