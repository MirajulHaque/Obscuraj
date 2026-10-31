# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import yaml
from pathlib import Path


# -----------------------------
# Base Path
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "settings.yaml"


# -----------------------------
# Global Config Cache
# -----------------------------
_config_cache = None


# -----------------------------
# Load Config
# -----------------------------
def load_config() -> dict:
    global _config_cache

    if _config_cache is not None:
        return _config_cache

    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f)
        if not isinstance(loaded, dict):
            raise ValueError(f"Config must be a YAML mapping: {CONFIG_PATH}")
        _config_cache = loaded

    return _config_cache


# -----------------------------
# Get Specific Config Section
# -----------------------------
def get_config(section: str = None):
    config = load_config()

    if section:
        return config.get(section, {})

    return config


# -----------------------------
# Helper: Get Module Config
# -----------------------------
def is_module_enabled(module_name: str) -> bool:
    config = load_config()
    modules = config.get("modules", {})

    module = modules.get(module_name, {})
    return module.get("enabled", False)


# -----------------------------
# Helper: Get Server Config
# -----------------------------
def get_server_config():
    return get_config("server")


# -----------------------------
# Helper: Get Scan Config
# -----------------------------
def get_scan_config():
    return get_config("scan")


# -----------------------------
# Helper: Get Reporting Config
# -----------------------------
def get_reporting_config():
    return get_config("reporting")


def get_security_config():
    return get_config("security")
