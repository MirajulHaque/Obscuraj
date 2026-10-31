# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import sqlite3

from core import db, normalizer, parser, validation
from reporting.reporting import build_html


def test_dns_parser_and_normalizer_contract():
    parsed = parser.parse_dns_output("=== A RECORDS ===\n203.0.113.9\n=== MX RECORDS ===\nmail.example.com")
    normalized = normalizer.normalize("dns", parsed)
    assert normalized["records"]["a"] == ["203.0.113.9"]
    assert normalized["records"]["mx"] == ["mail.example.com"]
    assert normalized["findings"]


def test_dns_scan_reports_missing_container_tool_actionably(monkeypatch):
    from core import executor

    monkeypatch.setattr(
        executor.shutil, "which",
        lambda tool: None if tool == "dig" else f"/usr/bin/{tool}",
    )

    result = executor.run_dns_scan("missing-dig-test", "example.com")

    assert result["status"] == "error"
    assert result["error"] == (
        "Missing required DNS runtime executable(s): dig (install bind9-dnsutils (dnsutils on Kali))"
    )


def test_validate_target_rejects_local_and_command_input():
    for value in ("localhost", "127.0.0.1", "-bad.example", "example.com;id", "example.com/path"):
        try:
            validation.validate_target(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted unsafe target {value!r}")
    assert validation.validate_target("ExAmPlE.com.") == "example.com"


def test_db_status_updates_preserve_result_and_error(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "data" / "scan.db")
    db.init_db()
    db.create_scan("id", "example.com", "passive")
    result = {"status": "completed"}
    db.update_scan("id", status="completed", result=result)
    db.update_scan("id", status="running")
    assert db.get_scan("id")["result"] == result
    assert db.get_scan("id")["status"] == "running"


def test_db_uses_portable_rollback_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scan.db")
    db.init_db()
    with sqlite3.connect(db.DB_PATH) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"


def test_report_escapes_untrusted_values():
    report = build_html({
        "target": "<script>alert(1)</script>", "status": "completed",
        "summary": {}, "modules": [{"name": "dns", "status": "completed", "data": {
            "records": {"txt": ["</pre><script>alert(2)</script>"]},
            "findings": [{"severity": "low", "description": "<img src=x onerror=alert(3)>"}]
        }}]
    })
    assert "<script>alert(1)</script>" not in report
    assert "</pre><script>alert(2)</script>" not in report
    assert "<img src=x onerror=alert(3)>" not in report


def test_failed_scan_keeps_error_visible_in_report():
    report = build_html({
        "target": "example.com", "status": "failed", "summary": {},
        "modules": [{"name": "subdomain", "status": "failed", "error": "<timeout>"}]
    })
    assert "Status:</b> failed" in report
    assert "&lt;timeout&gt;" in report
    assert "<timeout>" not in report


def test_failed_scan_json_export_preserves_failed_status(monkeypatch):
    from api.routes import report_routes

    payload = {"status": "failed", "modules": [{"name": "subdomain", "status": "failed"}]}
    monkeypatch.setattr(report_routes, "get_job", lambda _scan_id: {"status": "failed", "result": payload})
    assert report_routes.download_json_report("id") == payload


def test_scan_service_does_not_mark_module_failure_success(monkeypatch):
    from api.services import scan_service

    monkeypatch.setattr(scan_service, "run_dns_scan", lambda *_: {"status": "error", "error": "missing tool"})
    monkeypatch.setattr(scan_service, "is_module_enabled", lambda _name: True)
    monkeypatch.setattr(scan_service, "find_subdomains", lambda _target: {"records": {}, "findings": []})
    monkeypatch.setattr(scan_service, "lookup_wayback", lambda _target: {"records": {}, "findings": []})
    monkeypatch.setattr(scan_service, "google_dorks", lambda _target: {"records": {}, "findings": []})
    result = scan_service.run_scan("id", "example.com")
    assert result["status"] == "failed"
    assert next(m for m in result["modules"] if m["name"] == "dns")["status"] == "failed"


def test_job_worker_persists_failed_terminal_state(monkeypatch):
    from core import job_manager

    writes = []

    class Slot:
        def release(self):
            pass

    monkeypatch.setattr(job_manager, "_slots", Slot())
    monkeypatch.setattr(job_manager, "run_scan", lambda *_: {"status": "failed", "error": "DNS unavailable"})
    monkeypatch.setattr(job_manager, "update_scan", lambda *args, **kwargs: writes.append((args, kwargs)))
    job_manager._scan_worker("id", "example.com", "passive")
    assert writes[-1][1]["status"] == "failed"
    assert writes[-1][1]["error"] == "DNS unavailable"


def test_dork_generation_is_encoded_and_offline():
    from core.recon import google_dorks

    data = google_dorks("example.com")
    assert len(data["records"]["queries"]) >= 5
    assert all(query["url"].startswith("https://www.google.com/search?") for query in data["records"]["queries"])


def test_public_recon_modules_normalize_provider_shapes(monkeypatch):
    from core import recon

    monkeypatch.setattr(recon, "_get_json", lambda _url: [
        {"name_value": "www.example.com\n*.example.com\nattacker-example.com"}
    ])
    subs = recon.find_subdomains("example.com")["records"]["subdomains"]
    assert subs == ["example.com", "www.example.com"]

    monkeypatch.setattr(recon, "_get_json", lambda _url: [
        ["original", "timestamp", "statuscode"],
        ["https://example.com/", "20260101000000", "200"],
    ])
    wayback = recon.lookup_wayback("example.com")["records"]["snapshots"]
    assert wayback[0]["statuscode"] == "200"


def test_json_provider_timeout_identifies_provider_and_configured_timeout(monkeypatch):
    from core import recon

    monkeypatch.setattr(recon, "get_security_config", lambda: {"request_timeout": 7})
    observed = {}

    class TimeoutResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            raise TimeoutError("The read operation timed out")

    def timeout(_request, timeout):
        observed["timeout"] = timeout
        return TimeoutResponse()

    monkeypatch.setattr(recon.urllib.request, "urlopen", timeout)
    try:
        recon.find_subdomains("example.com")
    except TimeoutError as exc:
        assert str(exc) == "crt.sh request timed out after 7 seconds"
    else:
        raise AssertionError("provider timeout was not reported")
    assert observed["timeout"] == 7


def test_json_provider_timeout_unwraps_urlerror_reason(monkeypatch):
    from urllib.error import URLError
    from core import recon

    monkeypatch.setattr(recon, "get_security_config", lambda: {"request_timeout": 9})
    monkeypatch.setattr(
        recon.urllib.request, "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError(TimeoutError("socket timed out"))),
    )
    try:
        recon._get_json("https://crt.sh/?q=example.com&output=json")
    except TimeoutError as exc:
        assert str(exc) == "crt.sh request timed out after 9 seconds"
    else:
        raise AssertionError("wrapped provider timeout was not reported")


def test_subdomain_timeout_fails_scan_and_keeps_successful_modules_in_report(monkeypatch):
    from api.services import scan_service
    from core import recon

    monkeypatch.setattr(recon, "get_security_config", lambda: {"request_timeout": 30})
    monkeypatch.setattr(
        recon.urllib.request, "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("The read operation timed out")),
    )
    monkeypatch.setattr(scan_service, "run_dns_scan", lambda *_: {
        "status": "completed", "data": "=== A RECORDS ===\n203.0.113.10"
    })
    monkeypatch.setattr(scan_service, "is_module_enabled", lambda _name: True)
    monkeypatch.setattr(scan_service, "lookup_wayback", lambda _target: {
        "records": {"snapshots": [{"original": "https://example.com/"}]}, "findings": []
    })
    monkeypatch.setattr(scan_service, "google_dorks", lambda _target: {
        "records": {"queries": [{"query": "site:example.com"}]}, "findings": []
    })

    result = scan_service.run_scan("timeout-test", "example.com")

    assert result["status"] == "failed"
    subdomain = next(module for module in result["modules"] if module["name"] == "subdomain")
    assert subdomain["status"] == "failed"
    assert subdomain["error"] == "crt.sh request timed out after 30 seconds"
    assert next(module for module in result["modules"] if module["name"] == "dns")["status"] == "completed"
    assert next(module for module in result["modules"] if module["name"] == "wayback")["status"] == "completed"
    assert next(module for module in result["modules"] if module["name"] == "google_dorks")["status"] == "completed"

    report = build_html(result)
    assert "Status:</b> failed" in report
    assert "crt.sh request timed out after 30 seconds" in report
    assert "https://example.com/" in report
    assert "203.0.113.10" in report

