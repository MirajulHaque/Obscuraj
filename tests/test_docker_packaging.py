# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_clean_checkout_docker_workflow_has_runtime_assets_and_browser_steps():
    compose_path = PROJECT_ROOT / "docker" / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    service = compose["services"]["obscuraj"]
    build = service["build"]
    context = (compose_path.parent / build["context"]).resolve()
    dockerfile = (context / build["dockerfile"]).resolve()

    assert context == PROJECT_ROOT
    assert dockerfile.is_file()
    for runtime_asset in (
        "api/main.py",
        "cli/obscuraj.sh",
        "config/settings.yaml",
        "modules/passive/dns.sh",
        "requirements-lock.txt",
        "docker/check-runtime.sh",
    ):
        assert (context / runtime_asset).is_file()

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docker compose -f docker/docker-compose.yml up --build -d" in readme
    assert "http://127.0.0.1:19191/docs" in readme
    assert "/report/{scan_id}/download" in readme
    assert "--user 10001:10001" in readme
    assert "bash /app/cli/obscuraj.sh" in readme


def test_compose_api_token_is_optional_and_cli_runs_with_container_tools():
    compose = (PROJECT_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    cli = (PROJECT_ROOT / "cli" / "obscuraj.sh").read_text(encoding="utf-8")
    runtime_check = (PROJECT_ROOT / "docker" / "check-runtime.sh").read_text(encoding="utf-8")

    assert "${OBSCURAJ_API_TOKEN:-}" in compose
    assert "${OBSCURAJ_API_URL:-http://localhost:19191}" in cli
    assert "${OBSCURAJ_REPORT_DIR:-.}" in cli
    for tool in ("python", "sh", "bash", "dig", "awk", "curl", "jq", "sleep", "mkdir", "chown", "gosu"):
        assert tool in runtime_check
    for asset in ("/app/core/recon.py", "/app/reporting/reporting.py", "/etc/ssl/certs/ca-certificates.crt"):
        assert asset in runtime_check


def test_api_allows_optional_authentication_when_token_is_not_configured(tmp_path, monkeypatch):
    from core import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "obscuraj.db")
    monkeypatch.delenv("OBSCURAJ_API_TOKEN", raising=False)

    # Importing the app initializes its database; point it to this isolated test path.
    from api.main import APIKeyMiddleware

    downstream_calls = []

    async def downstream(scope, _receive, _send):
        downstream_calls.append(scope["path"])

    middleware = APIKeyMiddleware(downstream)
    call = middleware(
        {"type": "http", "path": "/report/no-such-scan", "headers": []},
        None,
        None,
    )
    try:
        call.send(None)
    except StopIteration:
        pass

    assert downstream_calls == ["/report/no-such-scan"]
