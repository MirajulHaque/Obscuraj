# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import re


def parse_dns_output(raw_text: str) -> dict:
    """
    Parse DNS module output into structured JSON
    Expected format:
    === A RECORDS ===
    1.1.1.1
    === MX RECORDS ===
    mail.example.com
    """

    parsed_data = {}
    current_section = None

    lines = raw_text.splitlines()

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # Detect section headers
        section_match = re.match(r"^===\s*(.*?)\s*===$", line)
        if section_match:
            current_section = section_match.group(1).lower().replace(" ", "_")
            parsed_data[current_section] = []
            continue

        # Add data under current section
        if current_section:
            parsed_data[current_section].append(line)

    return parsed_data


# -----------------------------
# Normalize DNS Data (Basic)
# -----------------------------
def normalize_dns_data(parsed_data: dict) -> dict:
    """
    Normalize parsed DNS data for reporting layer
    """

    normalized = {
        "a_records": parsed_data.get("a_records", []),
        "aaaa_records": parsed_data.get("aaaa_records", []),
        "mx_records": parsed_data.get("mx_records", []),
        "ns_records": parsed_data.get("ns_records", []),
        "cname_records": parsed_data.get("cname_records", []),
        "txt_records": parsed_data.get("txt_records", []),
        "soa_records": parsed_data.get("soa_records", []),
        "ptr_records": parsed_data.get("ptr_records", []),
        "caa_records": parsed_data.get("caa_records", []),
        "zone_transfer": parsed_data.get("zone_transfer", []),
        "whois": parsed_data.get("whois", [])
    }

    return normalized
