#!/bin/bash
# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

# ----------------------------------------
# ObscuraJ CLI Wrapper
# ----------------------------------------

API_URL="${OBSCURAJ_API_URL:-http://localhost:19191}"
REPORT_DIR="${OBSCURAJ_REPORT_DIR:-.}"
POLL_INTERVAL="2"
MAX_WAIT="120"

show_help() {
    echo "ObscuraJ - OSINT Intelligence Framework"
    echo ""
    echo "Usage:"
    echo "  ./obscuraj.sh -T <target> [-m mode]"
    echo ""
    echo "Options:"
    echo "  -T, --target      Target domain or IP"
    echo "  -m, --mode        Scan mode (passive)"
    echo "  -h, --help        Show this help message"
    echo ""
}

# ----------------------------------------
# Parse Arguments
# ----------------------------------------
TARGET=""
MODE="passive"

while [[ $# -gt 0 ]]; do
    case $1 in
        -T|--target)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            TARGET="$2"
            shift 2
            ;;
        -m|--mode)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            MODE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            show_help >&2
            exit 2
            ;;
    esac
done

# ----------------------------------------
# Validate Input
# ----------------------------------------
if [[ -z "$TARGET" ]]; then
    echo "[!] Target is required"
    show_help >&2
    exit 2
fi
if [[ "$MODE" != "passive" ]]; then
    echo "[!] Only passive mode is currently supported" >&2
    exit 2
fi
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

auth_args=()
if [[ -n "${OBSCURAJ_API_TOKEN:-}" ]]; then auth_args=(-H "Authorization: Bearer $OBSCURAJ_API_TOKEN"); fi

echo "[*] Starting scan..."
echo "[*] Target: $TARGET"
echo "[*] Mode: $MODE"

# ----------------------------------------
# Trigger Scan
# ----------------------------------------
RESPONSE=$(curl -fsS --max-time 20 -X POST "$API_URL/scan" \
    -H "Content-Type: application/json" \
    "${auth_args[@]}" \
    -d "$(jq -cn --arg target "$TARGET" --arg mode "$MODE" '{target:$target,mode:$mode}')") || {
      echo "[!] Could not submit scan. Is the API reachable?" >&2; exit 1;
    }

SCAN_ID=$(echo "$RESPONSE" | jq -r '.scan_id')

if [[ -z "$SCAN_ID" || "$SCAN_ID" == "null" ]]; then
    echo "[!] Scan failed"
    echo "$RESPONSE"
    exit 1
fi

echo "[+] Scan ID: $SCAN_ID"

echo "[*] Waiting for scan to finish..."
elapsed=0
while (( elapsed < MAX_WAIT )); do
    JOB=$(curl -fsS --max-time 10 "${auth_args[@]}" "$API_URL/scan/$SCAN_ID") || {
      echo "[!] Could not read scan status" >&2; exit 1;
    }
    STATUS=$(jq -r '.status // "unknown"' <<<"$JOB")
    case "$STATUS" in
      completed) break ;;
      failed) echo "[!] Scan failed: $(jq -r '.error // .result.error // "unknown error"' <<<"$JOB")" >&2; exit 1 ;;
      queued|running) sleep "$POLL_INTERVAL"; elapsed=$((elapsed + POLL_INTERVAL)) ;;
      *) echo "[!] Unexpected scan status: $STATUS" >&2; exit 1 ;;
    esac
done
if [[ "$STATUS" != "completed" ]]; then echo "[!] Timed out waiting for scan" >&2; exit 1; fi
echo "[+] Scan completed"

# ----------------------------------------
# Generate Report
# ----------------------------------------
REPORT_RESPONSE=$(curl -fsS --max-time 10 "${auth_args[@]}" "$API_URL/report/$SCAN_ID") || {
  echo "[!] Report metadata request failed" >&2; exit 1;
}

echo "[+] Report generated"
mkdir -p "$REPORT_DIR" || { echo "[!] Cannot create report directory: $REPORT_DIR" >&2; exit 1; }
REPORT_FILE="$REPORT_DIR/obscuraj-${SCAN_ID}.html"
curl -fsS --max-time 20 "${auth_args[@]}" "$API_URL/report/$SCAN_ID/download" -o "$REPORT_FILE" || {
  echo "[!] Report download failed" >&2; exit 1;
}
echo "[+] Report saved: $REPORT_FILE"

# ----------------------------------------
# Open Report (if possible)
# ----------------------------------------
if command -v xdg-open > /dev/null; then
    xdg-open "$REPORT_FILE" >/dev/null 2>&1 &
elif command -v open > /dev/null; then
    open "$REPORT_FILE"
else
    echo "[i] Open the report manually in browser"
fi
