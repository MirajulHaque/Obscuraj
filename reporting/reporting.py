# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from pathlib import Path
import json
import html as html_lib
import os
import tempfile


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "data" / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------
# Generate Report
# -----------------------------
def generate_html_report(scan_result: dict) -> str:

    scan_id = scan_result["scan_id"]
    safe_scan_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(scan_id))
    filename = f"{safe_scan_id}.html"
    filepath = REPORT_DIR / filename

    html_content = build_html(scan_result)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=REPORT_DIR,
                                         prefix=f".{safe_scan_id}_", suffix=".tmp", delete=False) as f:
            temp_path = Path(f.name)
            f.write(html_content)
        os.replace(temp_path, filepath)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

    return str(filepath)


# -----------------------------
# Build HTML
# -----------------------------
def build_html(data: dict) -> str:

    summary = data.get("summary", {})
    modules = data.get("modules", [])

    high = _safe_count(summary.get("high_risk", 0))
    medium = _safe_count(summary.get("medium_risk", 0))
    low = _safe_count(summary.get("low_risk", 0))
    total_modules = _safe_count(summary.get("total_modules", 0))
    total_findings = _safe_count(summary.get("total_findings", 0))
    risk_total = high + medium + low
    high_pct = round(high * 100 / risk_total) if risk_total else 0
    medium_pct = round(medium * 100 / risk_total) if risk_total else 0
    low_pct = round(low * 100 / risk_total) if risk_total else 0

    html = f"""
    <html>
    <head>
        <title>ObscuraJ Report</title>

        <style>
            body {{
                font-family: Arial;
                background: #0f172a;
                color: #e2e8f0;
                margin: 0;
            }}

            .container {{
                padding: 30px;
            }}

            h1 {{
                color: #38bdf8;
            }}

            .summary-box {{
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
            }}

            .cards {{
                display: flex;
                gap: 20px;
                margin-top: 20px;
            }}

            .card {{
                flex: 1;
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }}

            .section {{
                margin-top: 30px;
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
            }}

            .high {{ color: #ef4444; }}
            .medium {{ color: #facc15; }}
            .low {{ color: #22c55e; }}

            .risk-row {{ display: grid; grid-template-columns: 90px 1fr 50px; gap: 12px; align-items: center; margin: 12px 0; }}
            .bar {{ background: #0f172a; border-radius: 6px; overflow: hidden; height: 16px; }}
            .bar i {{ display: block; height: 100%; }}
            .high-bar {{ background: #ef4444; }} .medium-bar {{ background: #facc15; }} .low-bar {{ background: #22c55e; }}

            pre {{
                background: #020617;
                padding: 10px;
                overflow-x: auto;
            }}
        </style>
    </head>

    <body>
    <div class="container">

        <h1>ObscuraJ Intelligence Report</h1>

        <!-- Executive Summary -->
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <p><b>Target:</b> {html_lib.escape(str(data.get("target", "")))}</p>
            <p><b>Status:</b> {html_lib.escape(str(data.get("status", "unknown")))}</p>
            <p><b>Total Findings:</b> {total_findings}</p>
            <p>
                High Risk: <span class="high">{high}</span> |
                Medium Risk: <span class="medium">{medium}</span> |
                Low Risk: <span class="low">{low}</span>
            </p>
        </div>

        <!-- Dashboard Cards -->
        <div class="cards">
            <div class="card">
                <h2>{total_modules}</h2>
                <p>Modules</p>
            </div>

            <div class="card">
                <h2>{total_findings}</h2>
                <p>Findings</p>
            </div>

            <div class="card">
                <h2 class="high">{high}</h2>
                <p>High</p>
            </div>

            <div class="card">
                <h2 class="medium">{medium}</h2>
                <p>Medium</p>
            </div>

            <div class="card">
                <h2 class="low">{low}</h2>
                <p>Low</p>
            </div>
        </div>

        <!-- Chart -->
        <div class="section">
            <h2>Risk Distribution</h2>
            <div class="risk-row"><span>High</span><div class="bar"><i class="high-bar" style="width:{high_pct}%"></i></div><b>{high}</b></div>
            <div class="risk-row"><span>Medium</span><div class="bar"><i class="medium-bar" style="width:{medium_pct}%"></i></div><b>{medium}</b></div>
            <div class="risk-row"><span>Low</span><div class="bar"><i class="low-bar" style="width:{low_pct}%"></i></div><b>{low}</b></div>
        </div>
    """

    # -----------------------------
    # Modules
    # -----------------------------
    for module in modules:
        html += f"""
        <div class="section">
            <h2>Module: {html_lib.escape(str(module.get("name", "unknown")))}</h2>
            <p>Status: {html_lib.escape(str(module.get("status", "unknown")))}</p>
        """

        if module.get("status") != "completed" and module.get("error"):
            html += f"<p class='high'>Error: {html_lib.escape(str(module['error']))}</p>"

        if module.get("status") == "completed":
            data_block = module.get("data", {})

            # Records
            html += "<h3>Records</h3><pre>"
            html += html_escape_json(data_block.get("records", {}))
            html += "</pre>"

            # Findings
            html += "<h3>Findings</h3>"
            findings = data_block.get("findings", [])

            if findings:
                for f in findings:
                    severity = str(f.get("severity", "info")).lower()
                    css_severity = severity if severity in {"high", "medium", "low"} else ""
                    html += f"<p class='{css_severity}'><b>{html_lib.escape(severity.upper())}</b>: {html_lib.escape(str(f.get('description', '')))}</p>"
            else:
                html += "<p>No findings</p>"

        html += "</div>"

    html += "</div></body></html>"

    return html


def html_escape_json(value) -> str:
    # Escape markup delimiters as well as quotes to prevent a value closing <pre>.
    return html_lib.escape(json.dumps(value, indent=2, ensure_ascii=False))


def _safe_count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0
