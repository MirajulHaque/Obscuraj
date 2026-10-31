# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from core.job_manager import get_job
from reporting.reporting import generate_html_report

router = APIRouter()


@router.get("/report/{scan_id}")
def get_report(scan_id: str):

    job = get_job(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not job.get("result"):
        raise HTTPException(status_code=409, detail={
            "status": job["status"],
            "message": "Scan results are not available yet"
        })

    report_path = generate_html_report(job["result"])

    return {
        "scan_id": scan_id,
        "status": job["status"],
        "download_url": f"/report/{scan_id}/download",
        "json_url": f"/report/{scan_id}/json"
    }


@router.get("/report/{scan_id}/download")
def download_report(scan_id: str):

    job = get_job(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not job.get("result"):
        raise HTTPException(status_code=409, detail=f"Report not ready: {job['status']}")

    report_path = generate_html_report(job["result"])

    return FileResponse(report_path, media_type="text/html", filename=f"obscuraj-{scan_id}.html")


@router.get("/report/{scan_id}/json")
def download_json_report(scan_id: str):
    job = get_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not job.get("result"):
        raise HTTPException(status_code=409, detail="Report not ready")
    return job["result"]
