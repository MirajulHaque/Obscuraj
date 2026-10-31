#!/usr/bin/env bash
# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

set -euo pipefail

target="${1:?domain required}"
# The API validates this too; repeat the check at the process boundary.
if [[ ! "$target" =~ ^[A-Za-z0-9.-]+$ || "$target" == -* ]]; then
  if [[ ! "$target" =~ ^[0-9A-Fa-f:.]+$ ]]; then
    echo "invalid DNS target" >&2
    exit 2
  fi
fi

if [[ "$target" =~ ^[0-9]+(\.[0-9]+){3}$ || "$target" == *:* ]]; then
  printf '=== PTR RECORDS ===\n'
  dig +time=4 +tries=1 +noall +answer -x "$target" | awk '{$1=$2=$3=""; sub(/^ +/, ""); print}'
  exit 0
fi

for record in A AAAA MX NS CNAME TXT SOA CAA; do
  printf '=== %s RECORDS ===\n' "$record"
  # dig's short form avoids machine-specific formatting and returns no shell code.
  dig +time=4 +tries=1 +noall +answer "$target" "$record" | awk '{$1=$2=$3=$4=""; sub(/^ +/, ""); print}'
done
