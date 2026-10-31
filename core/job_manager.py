# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import threading

from api.services.scan_service import run_scan
from core.db import create_scan, update_scan, get_scan
from core.config_loader import get_security_config

_capacity = max(1, int(get_security_config().get("max_concurrent_scans", 2)))
_slots = threading.BoundedSemaphore(_capacity)


# -----------------------------
# Worker
# -----------------------------
def _scan_worker(scan_id: str, target: str, mode: str):
    try:
        update_scan(scan_id, status="running")

        result = run_scan(scan_id, target, mode)

        status = result.get("status", "failed")
        update_scan(scan_id, status=status, result=result,
                    error=result.get("error") if status == "failed" else None)

    except Exception as e:
        update_scan(scan_id, status="failed", error=str(e))
    finally:
        _slots.release()


# -----------------------------
# Start Job
# -----------------------------
def start_scan_job(scan_id: str, target: str, mode: str):
    if not _slots.acquire(blocking=False):
        return False
    try:
        create_scan(scan_id, target, mode)
        thread = threading.Thread(target=_scan_worker, args=(scan_id, target, mode), daemon=True)
        thread.start()
        return True
    except Exception:
        _slots.release()
        raise


# -----------------------------
# Get Job
# -----------------------------
def get_job(scan_id: str):
    return get_scan(scan_id)
