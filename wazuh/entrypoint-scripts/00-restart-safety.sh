#!/usr/bin/env bash
# SOC lab: make in-place container restarts (docker restart, host reboot with
# restart policy) safe for the wazuh-manager 4.14 image.
#
# 1. Stale PID files survive in the container layer; after a restart the PIDs
#    belong to other processes and wazuh-apid refuses to start, which aborts
#    `wazuh-control start`. Remove them before the daemons are started.
# 2. The image's first-boot data (data_tmp) is consumed on first start. On a
#    restart, an *empty* var/multigroups volume (Wazuh keeps it empty) makes
#    0-wazuh-init copy from that missing source and exit before copying
#    /wazuh-config-mount (our rules!). Re-creating the empty source directory
#    turns that copy into a harmless no-op on every later restart.
set -uo pipefail
rm -f /var/ossec/var/run/*.pid /var/ossec/var/run/*.failed 2>/dev/null || true
mkdir -p /var/ossec/data_tmp/permanent/var/ossec/var/multigroups
echo "[soc-lab] restart-safety: stale PID files cleared, first-boot data path ensured"
