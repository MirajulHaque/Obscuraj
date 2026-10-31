# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import ipaddress
import re

from core.config_loader import get_security_config

_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z")


def validate_target(target: str) -> str:
    if not isinstance(target, str):
        raise ValueError("Target must be a domain name or public IP address")
    target = target.strip().rstrip(".")
    if len(target) > 253 or not target or any(c in target for c in " /\\\x00"):
        raise ValueError("Target must be a domain name or public IP address")
    try:
        address = ipaddress.ip_address(target)
        if not address.is_global:
            raise ValueError("Only public IP addresses can be scanned")
        normalized = str(address)
    except ValueError as exc:
        if "Only public" in str(exc):
            raise
        try:
            normalized = target.encode("idna").decode("ascii").lower()
        except UnicodeError as idna_error:
            raise ValueError("Invalid domain name") from idna_error
        if not _DOMAIN.fullmatch(normalized):
            raise ValueError("Target must be a fully qualified domain name")
    allowlist = get_security_config().get("allowed_targets", [])
    allowed = [str(entry).strip().lower().rstrip(".") for entry in allowlist]
    if allowed and not any(normalized == entry or normalized.endswith("." + entry.lstrip(".")) for entry in allowed):
        raise ValueError("Target is outside the configured allowed_targets list")
    return normalized
