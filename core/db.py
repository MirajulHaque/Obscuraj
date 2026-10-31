# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import sqlite3
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "obscuraj.db"


# -----------------------------
# Initialize DB
# -----------------------------
def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Jobs are process-local threads; they cannot resume after a restart.
        conn.execute("""UPDATE scans SET status = 'failed', error = 'Service restarted before scan finished',
                      updated_at = CURRENT_TIMESTAMP WHERE status IN ('queued', 'running')""")


# -----------------------------
# Create Scan
# -----------------------------
def create_scan(scan_id, target, mode):
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("INSERT INTO scans (scan_id, target, mode, status) VALUES (?, ?, ?, ?)",
                     (scan_id, target, mode, "queued"))


# -----------------------------
# Update Scan
# -----------------------------
def update_scan(scan_id, status=None, result=None, error=None):
    fields, values = [], []
    if status is not None:
        fields.append("status = ?"); values.append(status)
    if result is not None:
        fields.append("result = ?"); values.append(json.dumps(result))
    if error is not None:
        fields.append("error = ?"); values.append(error)
    if not fields:
        return
    fields.append("updated_at = CURRENT_TIMESTAMP")
    values.append(scan_id)
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = ?", values)


# -----------------------------
# Get Scan
# -----------------------------
def get_scan(scan_id):
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        cursor = conn.execute("SELECT scan_id, target, mode, status, result, error FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()

    if not row:
        return None

    result = json.loads(row[4]) if row[4] else None

    return {
        "scan_id": row[0],
        "target": row[1],
        "mode": row[2],
        "status": row[3],
        "result": result,
        "error": row[5]
    }
