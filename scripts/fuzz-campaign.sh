#!/usr/bin/env bash
# Runs every fuzz target for HOURS each, LANES at a time, for the hardening pass's
# campaign. Logs and a summary go under fuzz/campaign/; a crash stops its
# target, and its input is in fuzz/artifacts/<target>/.
#
#   scripts/fuzz-campaign.sh [HOURS] [LANES]
set -euo pipefail
hours=${1:-24}
lanes=${2:-4}
cd "$(dirname "$0")/../fuzz"
mkdir -p campaign
cargo +nightly fuzz build --release >/dev/null
seconds=$((hours * 3600))
export seconds
cargo +nightly fuzz list | xargs -P "$lanes" -I{} bash -c '
  mkdir -p "corpus/{}" "seeds/{}"
  start=$(date +%s)
  status=0
  cargo +nightly fuzz run --release "{}" "corpus/{}" "seeds/{}" -- \
    -max_total_time="$seconds" -print_final_stats=1 > "campaign/{}.log" 2>&1 || status=$?
  echo "{} exit=$status seconds=$(( $(date +%s) - start ))" >> campaign/summary.txt
'
