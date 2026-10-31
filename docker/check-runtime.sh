#!/bin/sh
# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

set -eu

for tool in python sh bash dig awk curl jq sleep mkdir chown gosu; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required runtime executable is missing from the image: $tool" >&2
        exit 1
    fi
done

for asset in /app/api/main.py /app/api/routes/scan_routes.py /app/api/routes/report_routes.py \
             /app/api/services/scan_service.py /app/cli/obscuraj.sh /app/config/settings.yaml \
             /app/core/executor.py /app/core/recon.py /app/core/db.py /app/modules/passive/dns.sh \
             /app/reporting/reporting.py /app/requirements-lock.txt \
             /etc/ssl/certs/ca-certificates.crt; do
    if [ ! -r "$asset" ]; then
        echo "Required runtime asset is missing or unreadable: $asset" >&2
        exit 1
    fi
done

if [ ! -w /app/data/raw ] || [ ! -w /app/data/reports ]; then
    echo "Runtime data and report directories must be writable by the application user" >&2
    exit 1
fi

python -c 'import fastapi, pydantic, starlette, uvicorn, yaml; import api.routes.report_routes, api.routes.scan_routes; from core.config_loader import load_config; required = {"dns", "subdomain", "wayback", "google_dorks"}; configured = set(load_config().get("modules", {})); missing = sorted(required - configured); assert not missing, f"Missing module configuration: {missing}"'
echo "ObscuraJ runtime dependencies and assets are available."
