# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from core.executor import run_dns_scan
from core.parser import parse_dns_output
from core.normalizer import normalize
from core.validation import validate_target
from core.recon import find_subdomains, lookup_wayback, google_dorks
from core.config_loader import is_module_enabled

import datetime
import ipaddress


def run_scan(scan_id: str, target: str, mode: str = "passive") -> dict:
    """
    Full scan pipeline:
    Execute → Parse → Normalize → Return Intelligence
    """

    target = validate_target(target)
    start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    final_result = {
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "start_time": start_time,
        "modules": [],
        "summary": {
            "total_modules": 0,
            "total_findings": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0
        },
        "status": "running"
    }

    try:
        # -----------------------------
        # DNS MODULE EXECUTION
        # -----------------------------
        final_result["summary"]["total_modules"] += 1
        dns_exec = run_dns_scan(scan_id, target)

        if dns_exec.get("status") != "completed":
            final_result["modules"].append({
                "name": "dns",
                "status": "failed",
                "error": dns_exec.get("error", "Unknown error")
            })
        else:
            raw_output = dns_exec.get("data", "")

            # -----------------------------
            # PARSE
            # -----------------------------
            parsed = parse_dns_output(raw_output)

            # -----------------------------
            # NORMALIZE
            # -----------------------------
            normalized = normalize("dns", parsed)

            # -----------------------------
            # STORE MODULE RESULT
            # -----------------------------
            final_result["modules"].append({
                "name": "dns",
                "status": "completed",
                "output_file": dns_exec.get("output_file"),
                "data": normalized
            })

            # -----------------------------
            # UPDATE GLOBAL SUMMARY
            # -----------------------------
            findings = normalized.get("findings", [])

            final_result["summary"]["total_findings"] += len(findings)

            for f in findings:
                if f["severity"] == "high":
                    final_result["summary"]["high_risk"] += 1
                elif f["severity"] == "medium":
                    final_result["summary"]["medium_risk"] += 1
                elif f["severity"] == "low":
                    final_result["summary"]["low_risk"] += 1

        try:
            ipaddress.ip_address(target)
            domain_target = False
        except ValueError:
            domain_target = True

        for module_name, runner in (("subdomain", find_subdomains), ("wayback", lookup_wayback),
                                    ("google_dorks", google_dorks)):
            if not domain_target or not is_module_enabled(module_name):
                continue
            final_result["summary"]["total_modules"] += 1
            try:
                data = runner(target)
                final_result["modules"].append({"name": module_name, "status": "completed", "data": data})
                findings = data.get("findings", [])
                final_result["summary"]["total_findings"] += len(findings)
                for finding in findings:
                    severity = finding.get("severity")
                    if severity in ("high", "medium", "low"):
                        final_result["summary"][f"{severity}_risk"] += 1
            except Exception as exc:
                final_result["modules"].append({"name": module_name, "status": "failed", "error": str(exc)})

        # A result with any failed module remains failed rather than being reported as complete.
        failed = any(module.get("status") == "failed" for module in final_result["modules"])
        final_result["status"] = "failed" if failed else "completed"
        if failed:
            failed_names = [module["name"] for module in final_result["modules"] if module.get("status") == "failed"]
            final_result["error"] = "Module failure: " + ", ".join(failed_names)
        final_result["end_time"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return final_result

    except Exception as e:
        final_result["status"] = "failed"
        final_result["error"] = str(e)
        final_result["end_time"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return final_result
