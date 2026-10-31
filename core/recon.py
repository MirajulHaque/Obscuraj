"""Passive, read-only OSINT lookups. No module sends probes to the target."""
# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

import json
import urllib.error
import urllib.parse
import urllib.request

from core.config_loader import get_security_config

_USER_AGENT = "ObscuraJ/1.0 (passive reconnaissance)"


def _get_json(url: str):
    timeout = max(2, min(30, int(get_security_config().get("request_timeout", 20))))
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    provider = urllib.parse.urlsplit(url).hostname or "OSINT provider"
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"Remote service returned HTTP {response.status}")
            return json.loads(response.read(5_000_000).decode("utf-8"))
    except TimeoutError as exc:
        raise TimeoutError(f"{provider} request timed out after {timeout} seconds") from exc
    except urllib.error.URLError as exc:
        # urllib can wrap connection timeouts in URLError; keep other network
        # failures distinct so callers can see whether the provider timed out.
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError(f"{provider} request timed out after {timeout} seconds") from exc
        raise


def find_subdomains(domain: str) -> dict:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    rows = _get_json("https://crt.sh/?" + query)
    names = set()
    for row in rows:
        for value in str(row.get("name_value", "")).splitlines():
            name = value.strip().lower().lstrip("*.").rstrip(".")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return {"module": "subdomain", "records": {"subdomains": sorted(names)}, "findings": []}


def lookup_wayback(domain: str) -> dict:
    params = urllib.parse.urlencode({
        "url": f"*.{domain}/*", "output": "json", "fl": "original,timestamp,statuscode,mimetype",
        "filter": "statuscode:200", "collapse": "urlkey", "limit": "1000",
    })
    rows = _get_json("https://web.archive.org/cdx/search/cdx?" + params)
    if not isinstance(rows, list) or not rows:
        rows = []
    headers, *items = rows
    if not isinstance(headers, list):
        return {"module": "wayback", "records": {"snapshots": []}, "findings": []}
    records = [dict(zip(headers, item)) for item in items if isinstance(item, list)]
    return {"module": "wayback", "records": {"snapshots": records}, "findings": []}


def google_dorks(domain: str) -> dict:
    # Generate Google query links only; do not scrape Google or crawl the target.
    templates = [
        ("Indexed subdomains", f"site:*.{domain}"),
        ("Login pages", f"site:{domain} (inurl:login OR inurl:signin OR inurl:admin)"),
        ("Exposed documents", f"site:{domain} (filetype:pdf OR filetype:doc OR filetype:xls)"),
        ("Configuration references", f"site:{domain} (filetype:env OR filetype:conf OR filetype:config)"),
        ("Directory listings", f"site:{domain} intitle:index.of"),
        ("Public code references", f"site:github.com \"{domain}\""),
    ]
    queries = [{"name": name, "query": query,
                "url": "https://www.google.com/search?" + urllib.parse.urlencode({"q": query})}
               for name, query in templates]
    return {"module": "google_dorks", "records": {"queries": queries}, "findings": []}
