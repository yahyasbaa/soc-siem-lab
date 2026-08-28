#!/usr/bin/env bash
# SOC lab: ship *all* decoded events (archives.json) to the indexer, not only
# alerts, so the "Total events" dashboard panel and event searches work.
# Runs from the manager image entrypoint after filebeat.yml is regenerated.
set -euo pipefail
FB=/etc/filebeat/filebeat.yml
if grep -q 'archives:' "$FB"; then
  sed -i '/archives:/{n;s/enabled: false/enabled: true/}' "$FB"
  echo "[soc-lab] Filebeat archives shipping enabled"
fi
