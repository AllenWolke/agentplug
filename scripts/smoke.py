"""Probe authenticated platform health without requiring business-specific seeds."""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--username", default="system.admin")
    args = parser.parse_args()
    password = os.environ.get("SMOKE_PASSWORD")
    if not password:
        parser.error("SMOKE_PASSWORD must contain the chosen administrator's password")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base = args.base_url.rstrip("/")

    def request(path: str, body: dict | None = None) -> object:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(base + path, data=payload,
                                     headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=10) as response:
            if response.status != 200:
                raise ValueError("unexpected HTTP status")
            raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError("response exceeded limit")
            return json.loads(raw) if path != "/healthz" else None

    logged_in = False
    try:
        request("/healthz")
        request("/auth/login", {"username": args.username, "password": password})
        logged_in = True
        status = request("/ops/status")
        if (not isinstance(status, dict)
                or any(not isinstance(status.get(name), dict)
                       or status[name].get("status") != "healthy"
                       for name in ("gateway", "platform"))):
            raise ValueError("gateway or platform is not healthy")
        print("PLATFORM SMOKE PASS | frontend, administrator login, gateway and platform")
        return 0
    except (urllib.error.URLError, ValueError):
        print("PLATFORM SMOKE FAILED | check service availability and administrator credentials")
        return 1
    finally:
        if logged_in:
            try:
                request("/auth/logout", {})
            except (urllib.error.URLError, ValueError):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
