# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
import os
import hmac

from api.routes.scan_routes import router as scan_router
from api.routes.report_routes import router as report_router

from core.db import init_db

init_db()

from core.config_loader import get_server_config, get_security_config

import uvicorn


# -----------------------------
# App Initialization
# -----------------------------
app = FastAPI(
    title="ObscuraJ API",
    description="Modular OSINT Intelligence Framework",
    version="1.0.0"
)


class APIKeyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        expected = os.getenv("OBSCURAJ_API_TOKEN")
        if scope["type"] == "http" and expected and scope.get("path") not in ("/", "/health"):
            headers = {key.lower(): value.decode("latin1") for key, value in scope.get("headers", [])}
            supplied = headers.get(b"authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {expected}"):
                response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


app.add_middleware(APIKeyMiddleware)


# -----------------------------
# Middleware
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_security_config().get("cors_origins", ["http://localhost:19191"]),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Include Routers
# -----------------------------
app.include_router(scan_router)
app.include_router(report_router)


# -----------------------------
# Root
# -----------------------------
@app.get("/")
def root():
    return {
        "message": "ObscuraJ API is running"
    }


# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    config = get_server_config()

    uvicorn.run(
        "api.main:app",
        host=os.getenv("OBSCURAJ_HOST", config.get("host", "127.0.0.1")),
        port=config.get("port", 19191),
        reload=False
    )
