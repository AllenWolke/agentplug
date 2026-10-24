"""Bounded optional schema requests; platform remains the authoritative validator."""
import json


def schema_request(schema, mode, require_json):
    if schema is None:
        if mode:
            raise ValueError("response_schema_mode requires response_schema")
        return None, ""
    if not require_json or not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("response_schema requires JSON output and an object schema")
    mode = mode or "required"
    if mode not in {"required", "prefer_supported"}:
        raise ValueError("unsupported response_schema_mode")
    raw = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(raw.encode("utf8")) > 16384:
        raise ValueError("response_schema exceeds 16 KiB")
    return json.loads(raw), mode
