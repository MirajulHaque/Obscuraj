# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Literal
import uuid

from core.job_manager import start_scan_job, get_job
from core.validation import validate_target

router = APIRouter()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    mode: Literal["passive"] = "passive"

    model_config = {"extra": "forbid"}


# -----------------------------
# Start Scan (ASYNC)
# -----------------------------
@router.post("/scan")
def start_scan(request: ScanRequest):
    try:
        target = validate_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    scan_id = str(uuid.uuid4())

    if not start_scan_job(scan_id, target, request.mode):
        raise HTTPException(status_code=429, detail="Scan capacity reached; retry later")

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan started in background"
    }


# -----------------------------
# Get Scan Status
# -----------------------------
@router.get("/scan/{scan_id}")
def get_scan(scan_id: str):

    job = get_job(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    return job
