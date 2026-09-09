#!/usr/bin/env bash
# SOC lab: deterministic correlation.
# By default remoted and analysisd use one worker thread per CPU, so a
# burst of events written in the same millisecond can be correlated out of
# order and frequency/if_matched_sid rules may miss by one event. The lab's
# event rate is tiny, so single-threaded decoding and rule matching cost
# nothing and make every correlation rule reproducible under test.
# (The image restores local_internal_options.conf on start, so it is set here.)
set -euo pipefail
F=/var/ossec/etc/local_internal_options.conf
for opt in remoted.worker_pool=1 analysisd.event_threads=1 analysisd.winevt_threads=1 analysisd.rule_matching_threads=1; do
  key="${opt%%=*}"
  grep -q "^${key}=" "$F" && sed -i "s/^${key}=.*/${opt}/" "$F" || echo "$opt" >> "$F"
done
echo "[soc-lab] remoted/analysisd pinned to single-threaded, in-order processing"
