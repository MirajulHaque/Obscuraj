# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import subprocess
import os
import datetime
import re
import shutil
from pathlib import Path
from core.config_loader import get_security_config


# -----------------------------
# Base Paths
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
MODULES_DIR = BASE_DIR / "modules"
DATA_RAW_DIR = BASE_DIR / "data" / "raw"

# Ensure directories exist
DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------
# Utility: Clean ANSI Escape Codes
# -----------------------------
def strip_ansi(text: str) -> str:
    import re
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


# -----------------------------
# Execute Shell Module
# -----------------------------
def run_shell_module(module_path: str, target: str) -> dict:
    """
    Executes a bash module and captures output
    """

    if not os.path.isfile(module_path):
        return {
            "status": "error",
            "error": f"Module not found: {module_path}"
        }

    try:
        process = subprocess.run(
            ["bash", module_path, target],
            capture_output=True,
            text=True,
            timeout=max(5, min(45, int(get_security_config().get("scan_timeout", 90)))),
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )

        stdout = strip_ansi(process.stdout)[:2_000_000]
        stderr = strip_ansi(process.stderr)[:200_000]

        return {
            "status": "success" if process.returncode == 0 else "failed",
            "stdout": stdout,
            "stderr": stderr,
            "returncode": process.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Execution timed out"
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# -----------------------------
# Save Raw Output
# -----------------------------
def save_raw_output(scan_id: str, module_name: str, content: str):
    """
    Saves raw output to file
    """

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", scan_id)
    filename = f"{safe_id}_{module_name}_{timestamp}.log"
    filepath = DATA_RAW_DIR / filename

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    return str(filepath)


# -----------------------------
# Execute DNS Module (Phase 1)
# -----------------------------
def run_dns_scan(scan_id: str, target: str) -> dict:
    """
    Executes dns.sh module and stores output
    """

    required_tools = {
        "bash": "bash",
        "dig": "install bind9-dnsutils (dnsutils on Kali)",
        "awk": "mawk or another awk implementation",
    }
    missing_tools = [f"{tool} ({package})" for tool, package in required_tools.items()
                     if shutil.which(tool) is None]
    if missing_tools:
        return {
            "status": "error",
            "error": "Missing required DNS runtime executable(s): " + ", ".join(missing_tools),
        }

    module_path = MODULES_DIR / "passive" / "dns.sh"

    result = run_shell_module(str(module_path), target)

    if result["status"] != "success":
        return result

    # Save raw output
    file_path = save_raw_output(
        scan_id,
        "dns",
        result["stdout"]
    )

    return {
        "status": "completed",
        "module": "dns",
        "output_file": file_path,
        "data": result["stdout"]
    }
