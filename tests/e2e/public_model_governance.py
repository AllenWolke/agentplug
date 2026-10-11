"""Normal Model Governance API publication for an isolated public replay.

Caller owns login, Compose endpoint checks, private durable journal and mounted
credentials. No secret values, internal headers, provider inference, fake health
observations or automatic mutation retries. Rates are configured budget units,
not a vendor invoice. Provider /test validates endpoint safety only.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlencode, urlsplit

PREFIX = "/api/modules/model-governance"
PROJECT = re.compile(r"agentplug-test-public-[a-f0-9]{12}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def build_plan(project, scope, metadata, prices, dimensions, context_limits, effective_from, semantic_version="0.1.0"):
    """Build offline from key-free mount metadata and explicit operator rates.

    The HTTPS URL stays in deployment-owned metadata. Only its API descriptor
    digest and symbolic endpoint reach the model publication plan.
    """
    if not isinstance(metadata, dict) or set(metadata) != {"llm", "embedding"}:
        raise ValueError("key-free metadata must contain exactly llm and embedding")
    if not isinstance(prices, dict) or set(prices) != {"chat", "embedding"} or not isinstance(context_limits, dict) or set(context_limits) != {"chat", "embedding"}:
        raise ValueError("explicit rates and context limits required for both models")
    models = []
    for kind, source in (("chat", "llm"), ("embedding", "embedding")):
        configuration = metadata[source]
        filename = "deepseek.key" if kind == "chat" else "embedding.key"
        if not isinstance(configuration, dict) or set(configuration) != {"model", "base_url", "key_file"} or configuration["key_file"] != filename:
            raise ValueError("metadata must contain only model, clean URL and approved key filename")
        endpoint = urlsplit(configuration["base_url"])
        if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise ValueError("provider metadata requires clean HTTPS URL without embedded credentials")
        capabilities = {"dimensions": dimensions} if kind == "embedding" else {"reasoning": "disabled"}
        rate = prices[kind]
        if not isinstance(rate, dict) or set(rate) != {"currency", "input_micros_per_1k_tokens", "output_micros_per_1k_tokens"}:
            raise ValueError("rates must be explicit accounting fields without credentials")
        descriptor = {"model": configuration["model"], "endpoint": configuration["base_url"], "capabilities": capabilities}
        models.append({"kind": kind, "provider_key": "public-example-" + kind, "model_key": configuration["model"],
                       "endpoint_ref": "service://example-" + kind, "secret_ref": "secret://" + filename,
                       "capabilities": capabilities, "context_limit": context_limits[kind],
                       "semantic_version": semantic_version, "descriptor_sha256": digest(descriptor),
                       "price": dict(rate, effective_from=effective_from)})
    return validate_plan({"schema": "public-model-governance/v1", "owner_project": project, "scope": deepcopy(scope), "models": models}, project, scope)


def rows(api, path):
    reply = api.call("GET", path + ("&" if "?" in path else "?") + "limit=200")
    items = reply.get("items") if isinstance(reply, dict) else None
    if not isinstance(items, list) or len(items) >= 200 or any(not isinstance(row, dict) for row in items):
        raise RuntimeError("catalog list is malformed or truncated; cannot establish uniqueness")
    return items


def exact(row, fields):
    if not isinstance(row, dict) or any(row.get(key) != value for key, value in fields.items()):
        raise RuntimeError("live Model Governance resource differs from reviewed request")
    if not isinstance(row.get("id"), str) or not IDENTIFIER.fullmatch(row["id"]):
        raise RuntimeError("Model Governance returned an invalid resource ID")
    if type(row.get("revision")) is not int or row["revision"] < 1:
        raise RuntimeError("Model Governance returned an invalid revision")
    return row


def exact_global_catalog_scope(row, resource):
    """Model Providers and Definitions are global catalog DTOs, not app assets."""
    if not isinstance(row, dict) or any(row.get(key) != "" for key in (
        "tenant_id", "department_id", "application_id",
    )):
        raise RuntimeError(resource + " must remain in the platform's global Model Governance catalog")
    return row


def validate_plan(plan, project, scope):
    if not PROJECT.fullmatch(project) or set(scope) != {"tenant_id", "department_id", "application_id"}:
        raise ValueError("exact isolated project and application scope required")
    if any(not isinstance(value, str) or not IDENTIFIER.fullmatch(value) for value in scope.values()):
        raise ValueError("invalid scope")
    if not isinstance(plan, dict) or set(plan) != {"schema", "owner_project", "scope", "models"}:
        raise ValueError("unexpected model publication plan fields")
    if plan["schema"] != "public-model-governance/v1" or plan["owner_project"] != project or plan["scope"] != scope:
        raise ValueError("model publication plan is outside replay ownership")
    if not isinstance(plan["models"], list) or len(plan["models"]) != 2:
        raise ValueError("exactly one chat and one embedding model required")
    kinds, keys = set(), set()
    for item in plan["models"]:
        required = {"kind", "provider_key", "model_key", "endpoint_ref", "secret_ref", "capabilities", "context_limit",
                    "semantic_version", "descriptor_sha256", "price"}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("unexpected model or credential fields")
        kind = item["kind"]
        if kind not in {"chat", "embedding"} or kind in kinds:
            raise ValueError("duplicate or unsupported model kind")
        kinds.add(kind)
        for key in ("provider_key", "model_key"):
            if not isinstance(item[key], str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", item[key]):
                raise ValueError("invalid model identity")
        if item["provider_key"] in keys:
            raise ValueError("duplicate provider key")
        keys.add(item["provider_key"])
        if item["endpoint_ref"] != "service://example-" + kind or item["secret_ref"] != "secret://" + ("deepseek.key" if kind == "chat" else "embedding.key"):
            raise ValueError("only explicitly mounted example endpoint and credential references allowed")
        if not isinstance(item["capabilities"], dict) or len(json.dumps(item["capabilities"])) > 4096:
            raise ValueError("bounded explicit capabilities required")
        if kind == "embedding" and (type(item["capabilities"].get("dimensions")) is not int or not 1 <= item["capabilities"]["dimensions"] <= 16000):
            raise ValueError("explicit embedding dimensions required")
        if type(item["context_limit"]) is not int or not 1 <= item["context_limit"] <= 2_000_000:
            raise ValueError("invalid context limit")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", item["semantic_version"]) or not re.fullmatch(r"[a-f0-9]{64}", item["descriptor_sha256"]):
            raise ValueError("reviewed semantic version and API descriptor digest required")
        price = item["price"]
        if not isinstance(price, dict) or set(price) != {"currency", "input_micros_per_1k_tokens", "output_micros_per_1k_tokens", "effective_from"} or price["currency"] != "USD":
            raise ValueError("explicit USD accounting rates required")
        if any(type(price[key]) is not int or not 0 < price[key] <= 10**9 for key in ("input_micros_per_1k_tokens", "output_micros_per_1k_tokens")):
            raise ValueError("finite positive external model rates required")
        when = datetime.fromisoformat(price["effective_from"].replace("Z", "+00:00"))
        if when.tzinfo is None or when > datetime.now(timezone.utc):
            raise ValueError("price must already be effective with explicit timezone")
    return deepcopy(plan)


def publish_models(api, plan, project, scope, journal, confirm, record):
    """Publish two reviewed models; return real IDs and unobserved deployments.

    `journal` is caller-owned private state. `record` must durably persist it
    before a POST. An intent without receipt is ambiguous and blocks replay;
    reconcile the live API externally rather than blindly re-sending a POST.
    `confirm(project, provider_key, stage, request_digest)` binds each mutation.
    Caller MUST first prove its API origin belongs to the isolated Compose owner.
    """
    checked = validate_plan(plan, project, scope)
    identity = api.call("GET", "/auth/me")
    if not isinstance(identity, dict) or identity.get("username") != "system.admin" or any(identity.get(k) != v for k, v in scope.items()):
        raise RuntimeError("normal administrator login and exact workspace must be verified")
    fingerprint = digest(checked)
    if journal and (journal.get("owner_project") != project or journal.get("plan_sha256") != fingerprint):
        raise RuntimeError("publication journal belongs to a different project or plan")
    journal.setdefault("owner_project", project)
    journal.setdefault("plan_sha256", fingerprint)
    steps = journal.setdefault("steps", {})
    if any(entry.get("intent") and not entry.get("receipt") for entry in steps.values()):
        raise RuntimeError("unreconciled model mutation intent; automatic retry forbidden")
    result = {}

    def post(key, stage, path, payload):
        name = key + ":" + stage
        fingerprint = digest({"path": path, "payload": payload})
        entry = steps.get(name)
        if entry:
            if entry.get("request_sha256") != fingerprint or not entry.get("receipt"):
                raise RuntimeError("mutation journal does not match exact request")
            return deepcopy(entry["receipt"])
        if not confirm(project, key, stage, fingerprint):
            raise RuntimeError("exact model mutation confirmation missing")
        steps[name] = {"request_sha256": fingerprint, "intent": True}
        record(deepcopy(journal))
        reply = api.call("POST", path, payload)
        if not isinstance(reply, dict):
            raise RuntimeError("invalid model mutation receipt")
        steps[name]["receipt"] = deepcopy(reply)
        record(deepcopy(journal))
        return reply

    def approve(key, stage, path, row, readback):
        if row["status"] == "approved":
            return row
        if row["status"] != "draft":
            raise RuntimeError("only a matching draft may be approved")
        receipt = post(key, stage, path + "/approve", {"revision": row["revision"]})
        if receipt.get("status") != "approved" or receipt.get("revision") != row["revision"] + 1:
            raise RuntimeError("approval receipt is not exact CAS transition")
        updated = readback()
        exact(updated, {"id": row["id"], "status": "approved", "revision": row["revision"] + 1})
        return updated

    for item in checked["models"]:
        key = item["provider_key"]
        # Scope is sent only as a consistency hint accepted by the browser DTO.
        # Provider rows are intentionally global catalog assets; the server
        # binds owner_id to the authenticated manager and persists no app scope.
        provider_request = dict(scope, provider_key=key, display_name="Public teaching " + item["kind"],
                                type="external_managed", trust_zone="external", endpoint_ref=item["endpoint_ref"],
                                secret_ref=item["secret_ref"], capabilities=item["capabilities"],
                                retention_mode="provider_defined", training_usage="unknown", compliance_status="pending")
        provider_fields = {field: value for field, value in provider_request.items()
                           if field not in {"tenant_id", "department_id", "application_id"}}
        existing = [row for row in rows(api, PREFIX + "/providers") if row.get("provider_key") == key]
        if len(existing) > 1:
            raise RuntimeError("provider key is not unique")
        provider = existing[0] if existing else post(key, "provider-create", PREFIX + "/providers", provider_request)
        exact(provider, provider_fields)
        exact_global_catalog_scope(provider, "Provider")
        if provider.get("owner_id") != "system.admin":
            raise RuntimeError("global Provider owner must be the independently authenticated system.admin")
        provider_path = PREFIX + "/providers/" + provider["id"]
        safety = post(key, "provider-safety-test", provider_path + "/test", {})
        if safety.get("provider_id") != provider["id"] or safety.get("validated") is not True:
            raise RuntimeError("provider endpoint safety validation failed; not proof of connectivity")
        provider = approve(key, "provider-approve", provider_path, provider, lambda: api.call("GET", provider_path))
        exact(provider, provider_fields)
        exact_global_catalog_scope(provider, "Provider")
        if provider.get("owner_id") != "system.admin":
            raise RuntimeError("approved global Provider owner changed from system.admin")
        definition_fields = {field: item[field] for field in ("model_key", "kind", "capabilities", "context_limit")}
        definition_fields.update(provider_id=provider["id"], display_name=item["model_key"])
        existing = [row for row in rows(api, PREFIX + "/models?" + urlencode({"provider_id": provider["id"]})) if row.get("model_key") == item["model_key"] and row.get("provider_id") == provider["id"]]
        if len(existing) > 1:
            raise RuntimeError("model definition is not unique")
        definition = existing[0] if existing else post(key, "definition-create", PREFIX + "/models", definition_fields)
        exact(definition, definition_fields)
        exact_global_catalog_scope(definition, "Model Definition")
        version_fields = {"semantic_version": item["semantic_version"], "provider_fingerprint": "api-descriptor:" + item["descriptor_sha256"],
                          "artifact_digest": "sha256:" + item["descriptor_sha256"], "capability_hash": digest(item["capabilities"])}
        version_path = PREFIX + "/models/" + definition["id"] + "/versions"
        def version_read():
            found = [row for row in rows(api, version_path) if row.get("semantic_version") == item["semantic_version"]]
            if len(found) != 1:
                raise RuntimeError("model version readback is not unique")
            return found[0]
        existing = [row for row in rows(api, version_path) if row.get("semantic_version") == item["semantic_version"]]
        if len(existing) > 1:
            raise RuntimeError("model version is not unique")
        version = existing[0] if existing else post(key, "version-create", version_path, version_fields)
        exact(version, dict(definition_id=definition["id"], **version_fields))
        version = approve(key, "version-approve", version_path + "/" + version["id"], version, version_read)
        exact(version, dict(definition_id=definition["id"], **version_fields))
        price_fields = dict(item["price"], model_version_id=version["id"])
        existing = rows(api, PREFIX + "/prices?" + urlencode({"model_version_id": version["id"]}))
        if len(existing) > 1:
            raise RuntimeError("fresh replay requires one explicit price interval")
        price = existing[0] if existing else post(key, "price-create", PREFIX + "/prices", price_fields)
        # Go normalizes RFC3339 timezone spelling; compare the actual instant.
        exact(price, {field: value for field, value in price_fields.items() if field != "effective_from"})
        if datetime.fromisoformat(price["effective_from"].replace("Z", "+00:00")) != datetime.fromisoformat(price_fields["effective_from"].replace("Z", "+00:00")) or price.get("effective_until"):
            raise RuntimeError("price interval differs from reviewed request")
        price_path = PREFIX + "/prices/" + price["id"]
        price = approve(key, "price-approve", price_path, price, lambda: api.call("GET", price_path))
        exact(price, {field: value for field, value in price_fields.items() if field != "effective_from"})
        deployment_fields = dict(scope, model_version_id=version["id"], environment="development", endpoint_ref=item["endpoint_ref"],
                                 runtime_kind="http", resource_profile={}, min_replicas=1, max_replicas=1, capacity={"max_concurrent_requests": 2})
        existing = rows(api, PREFIX + "/deployments?" + urlencode({"model_version_id": version["id"]}))
        if len(existing) > 1:
            raise RuntimeError("fresh replay deployment is not unique")
        deployment = existing[0] if existing else post(key, "deployment-create", PREFIX + "/deployments", deployment_fields)
        exact(deployment, deployment_fields)
        deployment = api.call("GET", PREFIX + "/deployments/" + deployment["id"])
        exact(deployment, deployment_fields)
        result[item["kind"]] = {"provider": provider, "definition": definition, "version": version, "price": price, "deployment": deployment}
    return {"models": result, "model_deployment_readiness_proven": False, "business_execution_proven": False,
            "artifact_digest_kind": "API deployment descriptor; not model weights", "price_kind": "configured budget units; not vendor invoice"}
