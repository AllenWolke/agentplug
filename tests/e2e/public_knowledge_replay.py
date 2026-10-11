"""Repository teaching sources and managed full indexes via normal public APIs.

Separate source, submission and observation phases preserve real in-flight
handles. Caller proves isolated Compose ownership, mounted index workloads and
published model/Knowledge policies. No SQL writes, fabricated vectors, inferred
ACL, permission changes, task retries or sleeps are performed here.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "/api/modules/knowledge"
EXAMPLES = {"go": ("go-operations", "runbook.md"), "python": ("python-documents", "handbook.md"), "java": ("java-tickets", "handbook.md")}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def teaching_body(language):
    directory, filename = EXAMPLES[language]
    path = ROOT / "examples" / directory / "knowledge" / filename
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise ValueError("teaching source may not traverse a file link")
        if part == ROOT:
            break
    raw = path.read_bytes()
    if not 1 <= len(raw) <= 1024 * 1024:
        raise ValueError("teaching source must be nonempty and bounded")
    return raw.decode("utf-8-sig"), hashlib.sha256(raw).hexdigest()


def build_plan(project, scope, dimensions):
    if not re.fullmatch(r"agentplug-test-public-[a-f0-9]{12}", project):
        raise ValueError("isolated replay project required")
    if set(scope) != {"tenant_id", "department_id", "application_id"} or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) for value in scope.values()):
        raise ValueError("exact organization scope required")
    if type(dimensions) is not int or not 1 <= dimensions <= 16000:
        raise ValueError("real approved embedding dimensions required")
    items = []
    for language, (knowledge, _) in EXAMPLES.items():
        body, fingerprint = teaching_body(language)
        items.append({"language": language, "owner": "demo." + language + ".user", "machine": "example-" + language + "-machine",
                      "knowledge_id": knowledge, "installation_id": "example-" + knowledge + "-installation",
                      "document_id": "repository-handbook", "body": body, "source_file_sha256": fingerprint,
                      "metadata": {"source": "repository-teaching"},
                      "acl": {"owner_principal_id": "demo." + language + ".user", "application_visible": False,
                              "readers": ["example-" + language + "-machine"]},
                      "config": {"dimensions": dimensions, "window_runes": 400, "overlap_runes": 80,
                                 "maximum_documents": 16, "maximum_chunks": 128}})
    return {"schema": "public-knowledge-replay/v1", "owner_project": project, "scope": deepcopy(scope), "items": items}


def validate_plan(plan, project, scope):
    if not isinstance(plan, dict) or not isinstance(plan.get("items"), list) or len(plan["items"]) != 3:
        raise ValueError("exactly three repository-owned teaching sources required")
    dimension = plan["items"][0].get("config", {}).get("dimensions")
    if plan != build_plan(project, scope, dimension):
        raise ValueError("teaching source, ACL, installation or file hash differs from frozen repository plan")
    return deepcopy(plan)


def authenticate(api, username, scope):
    value = api.call("GET", "/auth/me")
    if not isinstance(value, dict) or value.get("username") != username or any(value.get(key) != item for key, item in scope.items()):
        raise RuntimeError("normal identity and exact workspace verification failed")


def source_snapshot(api, item):
    value = api.call("GET", PREFIX + "/sources/" + item["knowledge_id"] + "?limit=16")
    if not isinstance(value, dict) or value.get("schema_version") != "knowledge-source-snapshot/v1" or type(value.get("revision")) is not int or value["revision"] < 0 or not isinstance(value.get("documents"), list) or len(value["documents"]) > 16:
        raise RuntimeError("source snapshot is malformed or exceeds bounded teaching corpus")
    return value


def verify_document(snapshot, item, receipt):
    documents = snapshot["documents"]
    if len(documents) != 1:
        raise RuntimeError("replay teaching knowledge must contain exactly its owned document")
    document = documents[0]
    expected = {"id": item["document_id"], "body": item["body"], "metadata": item["metadata"], "acl": item["acl"], "deleted": False,
                "version": receipt["document_version"], "source_revision": receipt["source_revision"], "acl_revision": receipt["acl_revision"], "content_digest": receipt["content_digest"]}
    if any(document.get(key) != value for key, value in expected.items()) or snapshot["revision"] != receipt["source_revision"]:
        raise RuntimeError("source body, owner ACL or revision readback differs from exact receipt")


def private_state(journal, plan):
    fingerprint = digest(plan)
    if journal and (journal.get("owner_project") != plan["owner_project"] or journal.get("plan_sha256") != fingerprint):
        raise RuntimeError("knowledge journal belongs to another replay plan")
    journal.setdefault("owner_project", plan["owner_project"])
    journal.setdefault("plan_sha256", fingerprint)
    return journal.setdefault("languages", {})


def publish_source(api, plan, project, scope, language, journal, confirm, record):
    checked = validate_plan(plan, project, scope)
    authenticate(api, "system.admin", scope)
    item = next(row for row in checked["items"] if row["language"] == language)
    entry = private_state(journal, checked).setdefault(language, {})
    current = source_snapshot(api, item)
    if entry.get("source_receipt"):
        verify_document(current, item, entry["source_receipt"])
        return deepcopy(entry["source_receipt"])
    if entry.get("source_intent"):
        raise RuntimeError("source response is ambiguous; reconcile receipt before retry")
    if current["revision"] != 0 or current["documents"]:
        raise RuntimeError("fresh teaching source is not empty; existing data will not be overwritten")
    request = {"expected_source_revision": 0, "expected_document_version": 0,
               "idempotency_key": project + "-source-" + language,
               "body": item["body"], "metadata": item["metadata"], "acl": item["acl"], "deleted": False}
    if not confirm(project, language, "source-create", digest(request)):
        raise RuntimeError("exact source mutation confirmation missing")
    entry["source_intent"] = {"request_sha256": digest(request)}
    record(deepcopy(journal))
    receipt = api.call("PUT", PREFIX + "/sources/" + item["knowledge_id"] + "/documents/" + item["document_id"], request)
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in {"actor_principal_id": "system.admin", "document_id": item["document_id"], "document_version": 1, "source_revision": 1, "acl_revision": 1, "deleted": False}.items()) or not re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("content_digest", ""))):
        raise RuntimeError("source receipt is not the exact fresh-source CAS transition")
    entry["source_receipt"] = deepcopy(receipt)
    record(deepcopy(journal))
    verify_document(source_snapshot(api, item), item, receipt)
    return receipt


def submit_index(owner, source_reader, plan, project, scope, language, journal, confirm, record):
    checked = validate_plan(plan, project, scope)
    item = next(row for row in checked["items"] if row["language"] == language)
    authenticate(owner, item["owner"], scope)
    authenticate(source_reader, "system.admin", scope)
    entry = private_state(journal, checked).get(language, {})
    if not entry.get("source_receipt"):
        raise RuntimeError("exact source publication receipt required before managed indexing")
    verify_document(source_snapshot(source_reader, item), item, entry["source_receipt"])
    if entry.get("index_receipt"):
        return deepcopy(entry["index_receipt"])
    if entry.get("index_intent"):
        raise RuntimeError("index submission response ambiguous; never create a replacement task")
    installation = source_reader.call("GET", "/api/modules/catalog/installations/" + item["installation_id"])
    expected = dict(scope, id=item["installation_id"], agent_id="example-" + item["knowledge_id"], status="active")
    if not isinstance(installation, dict) or any(installation.get(key) != value for key, value in expected.items()) or not installation.get("version_id"):
        raise RuntimeError("managed index requires the exact active installation")
    request = {"installation_id": item["installation_id"], "idempotency_key": project + "-full-index-" + language,
               "mode": "full", "config": item["config"]}
    if not confirm(project, language, "index-submit", digest(request)):
        raise RuntimeError("exact managed index confirmation missing")
    entry["index_intent"] = {"request_sha256": digest(request), "agent_version_id": installation["version_id"]}
    record(deepcopy(journal))
    receipt = owner.call("POST", PREFIX + "/indexes/" + item["knowledge_id"] + "/tasks", request)
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "knowledge-index-task/v1" or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", str(receipt.get("run_id", ""))) or receipt.get("replayed") is not False:
        raise RuntimeError("fresh managed index receipt is invalid or unexpectedly replayed")
    entry["index_receipt"] = deepcopy(receipt)
    record(deepcopy(journal))
    return receipt


def observe_index(owner, source_reader, plan, project, scope, language, journal, record):
    checked = validate_plan(plan, project, scope)
    item = next(row for row in checked["items"] if row["language"] == language)
    authenticate(owner, item["owner"], scope)
    authenticate(source_reader, "system.admin", scope)
    entry = private_state(journal, checked).get(language, {})
    if not entry.get("index_receipt"):
        raise RuntimeError("no existing index task handle; observation cannot submit one")
    run_id = entry["index_receipt"]["run_id"]
    detail = owner.call("GET", PREFIX + "/indexes/" + item["knowledge_id"] + "/tasks/" + run_id)
    if not isinstance(detail, dict) or detail.get("schema_version") != "knowledge-index-task-detail/v1" or detail.get("run_id") != run_id or detail.get("knowledge_id") != item["knowledge_id"] or detail.get("mode") != "full" or type(detail.get("revision")) is not int or detail["revision"] < 1:
        raise RuntimeError("managed task handle readback differs from saved exact task")
    status = detail.get("status")
    if status not in {"accepted", "running", "waiting", "cancelling", "recovering", "succeeded", "failed", "cancelled"}:
        raise RuntimeError("unknown managed task status")
    entry["index_detail"] = deepcopy(detail)
    entry["index_publication_verified"] = False
    record(deepcopy(journal))
    if status != "succeeded":
        return {"run_id": run_id, "status": status, "index_publication_verified": False, "resubmit_performed": False}
    result = detail.get("result")
    if not isinstance(result, dict) or result.get("schema_version") != "knowledge-index-result/v1" or result.get("knowledge_id") != item["knowledge_id"] or result.get("source_revision") != entry["source_receipt"]["source_revision"] or not result.get("generation_id") or any(type(result.get(key)) is not int or result[key] < 1 for key in ("index_revision", "checkpoint_revision", "embedded_chunks")):
        raise RuntimeError("full index publication does not match frozen source and complete generation")
    verify_document(source_snapshot(source_reader, item), item, entry["source_receipt"])
    entry["index_publication_verified"] = True
    record(deepcopy(journal))
    return {"run_id": run_id, "status": status, "index_publication_verified": True, "result": deepcopy(result), "business_retrieval_proven": False}
