# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

def normalize_dns(parsed_data: dict) -> dict:
    """
    Normalize DNS parsed data into a unified schema
    """

    normalized = {
        "module": "dns",
        "summary": {},
        "records": {},
        "findings": []
    }

    # -----------------------------
    # Records
    # -----------------------------
    normalized["records"] = {
        "a": parsed_data.get("a_records", []),
        "aaaa": parsed_data.get("aaaa_records", []),
        "mx": parsed_data.get("mx_records", []),
        "ns": parsed_data.get("ns_records", []),
        "cname": parsed_data.get("cname_records", []),
        "txt": parsed_data.get("txt_records", []),
        "soa": parsed_data.get("soa_records", []),
        "ptr": parsed_data.get("ptr_records", []),
        "caa": parsed_data.get("caa_records", []),
    }

    # -----------------------------
    # Summary Metrics
    # -----------------------------
    normalized["summary"] = {
        "total_a": len(normalized["records"]["a"]),
        "total_aaaa": len(normalized["records"]["aaaa"]),
        "total_mx": len(normalized["records"]["mx"]),
        "total_ns": len(normalized["records"]["ns"]),
        "total_txt": len(normalized["records"]["txt"]),
    }

    # -----------------------------
    # Findings (Basic Intelligence)
    # -----------------------------
    findings = []

    # Zone Transfer
    if parsed_data.get("zone_transfer"):
        findings.append({
            "type": "zone_transfer",
            "severity": "high",
            "description": "DNS Zone Transfer may be enabled"
        })

    # Missing CAA (Potential risk)
    if not normalized["records"]["caa"]:
        findings.append({
            "type": "missing_caa",
            "severity": "medium",
            "description": "CAA records not configured"
        })

    # No MX record
    if not normalized["records"]["mx"]:
        findings.append({
            "type": "missing_mx",
            "severity": "low",
            "description": "No MX records found"
        })

    normalized["findings"] = findings

    return normalized


# -----------------------------
# Generic Normalizer Dispatcher
# -----------------------------
def normalize(module_name: str, parsed_data: dict) -> dict:
    """
    Dispatch normalization based on module
    """

    if module_name == "dns":
        return normalize_dns(parsed_data)

    # Future modules
    # elif module_name == "subdomain":
    #     return normalize_subdomain(parsed_data)

    return {
        "module": module_name,
        "data": parsed_data
    }
