"""Authenticated DLQ metadata/commands; no raw broker payload or credentials in output."""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request


class ClientError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def gateway_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ClientError("INVALID_GATEWAY_ORIGIN")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ClientError("REMOTE_GATEWAY_REQUIRES_HTTPS")
    try:
        parsed.port
    except ValueError:
        raise ClientError("INVALID_GATEWAY_PORT") from None
    return value.rstrip("/")


def read_credentials(path: Path) -> dict[str, str]:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ClientError("INVALID_CREDENTIAL_FILE")
        if os.name != "nt" and info.st_mode & 0o077:
            raise ClientError("CREDENTIAL_FILE_REQUIRES_MODE_600")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        raise ClientError("CREDENTIAL_FILE_UNREADABLE") from None
    if (not isinstance(value, dict) or set(value) != {"username", "password"}
            or any(not isinstance(value[k], str) or not value[k] for k in value)):
        raise ClientError("INVALID_CREDENTIAL_FILE")
    return value


class Client:
    def __init__(self, origin: str, timeout: int = 15):
        self.origin = gateway_origin(origin)
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, path: str, payload=None, refresh=True):
        request = urllib.request.Request(self.origin + path,
            data=None if payload is None else json.dumps(payload).encode("utf-8"),
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            method="GET" if payload is None else "POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise ClientError("RESPONSE_TOO_LARGE")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            # 401 means the gateway rejected authentication. Retry with the
            # same command/key after refresh, never after a timeout or 5xx.
            if status == 401 and refresh and path.startswith("/api/modules/"):
                self.request("/auth/refresh", {}, refresh=False)
                return self.request(path, payload, refresh=False)
            raise ClientError("HTTP_" + str(status)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ClientError("TRANSPORT_UNCONFIRMED_QUERY_OR_RETRY_SAME_KEY") from None
        except ValueError:
            raise ClientError("INVALID_JSON_RESPONSE") from None

    def close(self):
        self.jar.clear()


META_FIELDS = {"version", "id", "source", "attempts", "error_code", "payload_bytes",
               "payload_digest", "event_id", "tenant_id", "department_id", "application_id",
               "status", "revision", "created_at"}
SOURCE_FIELDS = {"consumer_group", "source_topic", "source_partition", "source_offset", "source_digest"}


def metadata(value):
    if not isinstance(value, dict) or value.get("version") != "kafka-dead-letter/v1":
        raise ClientError("INVALID_DEAD_LETTER_RESPONSE")
    result = {k: v for k, v in value.items() if k in META_FIELDS}
    source = result.get("source")
    if not isinstance(source, dict):
        raise ClientError("INVALID_DEAD_LETTER_RESPONSE")
    result["source"] = {k: v for k, v in source.items() if k in SOURCE_FIELDS}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", required=True, help="public browser gateway origin")
    parser.add_argument("--credentials-file", required=True, type=Path)
    parser.add_argument("--timeout", type=int, choices=range(1, 31), default=15)
    parser.add_argument("--tenant")
    parser.add_argument("--department")
    parser.add_argument("--application")
    subs = parser.add_subparsers(dest="command", required=True)
    listing = subs.add_parser("list")
    listing.add_argument("--limit", type=int, choices=range(1, 101), default=25)
    listing.add_argument("--after", default="")
    listing.add_argument("--unscoped", action="store_true")
    for name in ("close", "redrive"):
        action = subs.add_parser(name)
        action.add_argument("--id", required=True)
        action.add_argument("--revision", required=True, type=int)
        action.add_argument("--idempotency-key", required=True)
        action.add_argument("--reason-code", required=True)
        if name == "close":
            action.add_argument("--unscoped", action="store_true")
    args = parser.parse_args(argv)
    client = None
    try:
        if any((args.tenant, args.department, args.application)) and not all((args.tenant, args.department, args.application)):
            raise ClientError("WORKSPACE_REQUIRES_ALL_THREE_IDS")
        if args.command == "list":
            if args.after and not re.fullmatch(r"[a-f0-9]{64}", args.after):
                raise ClientError("INVALID_CURSOR")
        elif (not re.fullmatch(r"[a-f0-9]{64}", args.id) or args.revision < 1
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.idempotency_key)
                or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", args.reason_code)):
            raise ClientError("INVALID_ACTION_BINDING")
        client = Client(args.gateway, args.timeout)
        credential = read_credentials(args.credentials_file)
        client.request("/auth/login", credential, refresh=False)
        credential.clear()
        if args.tenant:
            client.request("/auth/workspace", {"tenant_id": args.tenant,
                "department_id": args.department, "application_id": args.application})
        base = "/api/modules/notification/dead-letters"
        if args.command == "list":
            query = urllib.parse.urlencode({"limit": args.limit, "after": args.after,
                                          "unscoped": str(args.unscoped).lower()})
            result = client.request(base + "?" + query)
            if not isinstance(result, dict) or not isinstance(result.get("items"), list):
                raise ClientError("INVALID_DEAD_LETTER_RESPONSE")
            output = {"version": "kafka-dead-letter/v1", "items": [metadata(v) for v in result["items"]],
                      "next": result.get("next", "")}
        else:
            result = client.request(base + "/" + args.id + "/actions", {
                "expected_revision": args.revision, "idempotency_key": args.idempotency_key,
                "action": args.command, "reason_code": args.reason_code,
                "unscoped": getattr(args, "unscoped", False)})
            output = metadata(result)
        print(json.dumps(output, ensure_ascii=True, indent=2))
        return 0
    except ClientError as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=True), file=sys.stderr)
        return 1
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
