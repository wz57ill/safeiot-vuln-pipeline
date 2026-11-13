#!/usr/bin/env bash
#
# attribute-oracle — end-to-end run.
#
# Drives stage 2 (Zigbee2MQTT controller bring-up) and stage 3 (enumeration) in a
# single invocation, because Zigbee2MQTT must stay up for the analysis to attach to
# it. Console output is written to stage 4 (last_run.log, gitignored).
#
# Prerequisites (see pipeline_harness/attribute-oracle/README.md):
#   - Docker (for the Mosquitto + Zigbee2MQTT bring-up), or a broker + Z2M already up
#   - SONOFF ZBDongle-P flashed with Z-Stack coordinator firmware, port set in .env
#   - The Hue motion sensor paired to this coordinator (open a pairing window first)
#
# Usage:
#   ./pipeline_harness/attribute-oracle/run.sh [subcommand] [args...]
# Default subcommand is 'enumerate'. Examples:
#   ./run.sh env-check
#   ./run.sh enumerate --device hue_motion
#   ./run.sh diff --supported <f> --visible <f>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREPROCESS_DIR="$REPO_ROOT/2_preprocess/attribute-oracle"
ANALYSIS_DIR="$REPO_ROOT/3_security_analysis/attribute-oracle"
OUTPUT_DIR="$REPO_ROOT/4_analysis_output/attribute-oracle"

mkdir -p "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/last_run.log"

# Default to the enumerate step if no subcommand is given.
if [[ $# -eq 0 ]]; then
  set -- enumerate
fi

{
  echo "==> attribute-oracle run @ $(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # ── Stage 2: controller bring-up ────────────────────────────────────────────
  if command -v docker >/dev/null 2>&1 && [[ -f "$PREPROCESS_DIR/.env" ]]; then
    echo "==> Stage 2: bringing up Mosquitto + Zigbee2MQTT (docker compose)"
    ( cd "$PREPROCESS_DIR" && docker compose up -d )
    echo "    waiting for the bridge to come online..."
    sleep 15
  else
    echo "==> Stage 2: skipping docker bring-up"
    echo "    (docker not found, or 2_preprocess/attribute-oracle/.env missing)."
    echo "    Assuming a broker + Zigbee2MQTT are already reachable on localhost:1883."
  fi

  # ── Stage 3: analysis ───────────────────────────────────────────────────────
  echo "==> Stage 3: installing Python dependencies"
  python3 -m pip install --quiet -r "$ANALYSIS_DIR/requirements.txt"

  echo "==> Stage 3: running attribute-oracle ($*)"
  cd "$ANALYSIS_DIR"
  python3 attribute_oracle.py "$@"
} 2>&1 | tee "$LOG"

echo "==> Console output written to 4_analysis_output/attribute-oracle/last_run.log"
