"""Normal public API business replay in a caller-proven isolated Compose owner.

Submission, observation, replay and cancellation are distinct journaled phases.
No credential, SQL, provider, hidden permission or replacement-Run operations.
This covers basic output/usage/isolation; it does not certify RAG quality,
checkpoint recovery, sandbox containment or provider stop/billing settlement.
"""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlencode

PREFIX = "/api/modules/conversation/sessions"
RUNS = "/api/modules/execution/platform/runs"
DIRECTORIES = {"go": "go-operations", "python": "python-documents", "java": "java-tickets"}
STATUSES = {"accepted", "running", "waiting", "recovering", "cancelling", "succeeded", "failed", "cancelled"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def build_plan(project, scope, versions, scenario_batch=None):
    if not re.fullmatch(r"agentplug-test-public-[a-f0-9]{12}", project) or set(scope) != {"tenant_id", "department_id", "application_id"} or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", v) for v in scope.values()):
        raise ValueError("isolated owner and exact scope required")
    if not isinstance(versions, dict) or set(versions) != set(DIRECTORIES) or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", v) for v in versions.values()):
        raise ValueError("three exact published version IDs required")
    inputs = {"go": {"service": "teaching-api", "symptom": "Explain read-only diagnosis of increased latency", "observations": "No external system changes are requested"},
              "python": {"question": "How does the platform isolate user history and knowledge access?", "top_k": 3, "cache_mode": "bypass", "workflow_mode": "tool_loop"},
              "java": {"ticket_id": "TEACHING-001", "summary": "Explain user data isolation", "details": "Draft advice from the repository teaching handbook; do not modify external systems"}}
    if scenario_batch is not None:
        if not isinstance(scenario_batch, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,31}", scenario_batch):
            raise ValueError("fresh bounded teaching scenario batch required")
        # Topic and bounded output requests match the repository teaching corpus.
        # These inputs preserve policy budgets and incomplete-output rejection.
        inputs = {
            "go": {"service": "teaching-api", "symptom": "延迟上升，应先核对哪些只读指标？请给三项检查，中文总计150字以内并引用资料。", "observations": "仅有用户观察；没有实际监控证据，不做系统变更。"},
            "python": {"question": "知识索引更新应如何核对源版本与索引版本？请用中文三句话回答，总计150字以内，保留知识引用。", "top_k": 3, "cache_mode": "bypass", "workflow_mode": "tool_loop"},
            "java": {"ticket_id": "TEACHING-002", "summary": "用户登录失败，需要收集哪些脱敏信息？", "details": "仅生成中文回复草稿，三项建议，总计150字以内并引用资料。不索取密码或Token，不修改外部系统。"},
        }
    cases = []
    for language, directory in DIRECTORIES.items():
        for case in ("baseline", "cancel"):
            identifier = project + "-" + language + "-" + case
            if scenario_batch is not None:
                identifier += "-" + scenario_batch
            cases.append({"language": language, "case": case, "owner": "demo." + language + ".user",
                          "agent_id": "example-" + directory, "agent_version_id": versions[language],
                          "installation_id": "example-" + directory + "-installation",
                          "output_schema": "schema://example-" + directory + "/output/v2",
                          "session_id": identifier + "-session", "run_id": identifier + "-run", "request": deepcopy(inputs[language])})
    plan = {"schema": "public-business-replay/v1", "owner_project": project, "scope": deepcopy(scope), "cases": cases}
    if scenario_batch is not None:
        plan["scenario_batch"] = scenario_batch
    return plan


def validate_plan(plan, project, scope):
    if not isinstance(plan, dict) or not isinstance(plan.get("cases"), list) or len(plan["cases"]) != 6:
        raise ValueError("six independently owned baseline/cancel cases required")
    versions = {row.get("language"): row.get("agent_version_id") for row in plan["cases"] if isinstance(row, dict) and row.get("case") == "baseline"}
    if plan != build_plan(project, scope, versions, plan.get("scenario_batch")):
        raise ValueError("business identity, input, schema or version differs from frozen plan")
    return deepcopy(plan)


def authenticated(api, username, scope):
    identity = api.call("GET", "/auth/me")
    if not isinstance(identity, dict) or identity.get("username") != username or any(identity.get(k) != v for k, v in scope.items()):
        raise RuntimeError("normal login and exact workspace required")


def state_for(journal, plan, item):
    if journal and (journal.get("owner_project") != plan["owner_project"] or journal.get("plan_sha256") != digest(plan)):
        raise RuntimeError("business journal belongs to another frozen plan")
    journal.setdefault("owner_project", plan["owner_project"])
    journal.setdefault("plan_sha256", digest(plan))
    return journal.setdefault("cases", {}).setdefault(item["run_id"], {})


def selected(plan, language, case):
    items = [row for row in plan["cases"] if row["language"] == language and row["case"] == case]
    if len(items) != 1:
        raise ValueError("exact language and case required")
    return items[0]


def verify_run(run, item, scope):
    if not isinstance(run, dict) or run.get("run_id") != item["run_id"] or run.get("agent_version_id") != item["agent_version_id"] or run.get("status") not in STATUSES or type(run.get("revision")) is not int or run["revision"] < 1:
        raise RuntimeError("Run handle, version or status differs from frozen case")
    expected = dict(scope, principal_type="user", principal_id=item["owner"], agent_id=item["agent_id"], agent_version_id=item["agent_version_id"],
                    agent_instance_id=item["installation_id"], installation_id=item["installation_id"],
                    session_id=item["session_id"], run_id=item["run_id"])
    if not isinstance(run.get("scope"), dict) or any(run["scope"].get(k) != v for k, v in expected.items()):
        raise RuntimeError("Run trusted scope differs from exact owner and installation")
    return run


def missing(api, path):
    try:
        api.call("GET", path)
    except Exception as error:
        if getattr(error, "status", None) == 404:
            return
        raise
    raise RuntimeError("fresh isolated case ID already exists; historical data cannot be reused")


def submit(owner, inventory, plan, project, scope, language, case, journal, confirm, record):
    checked = validate_plan(plan, project, scope)
    item = selected(checked, language, case)
    authenticated(owner, item["owner"], scope)
    authenticated(inventory, "system.admin", scope)
    entry = state_for(journal, checked, item)
    if entry.get("session_intent") or entry.get("run_intent"):
        raise RuntimeError("case already submitted or ambiguous; use observation, never resubmit")
    installation = inventory.call("GET", "/api/modules/catalog/installations/" + item["installation_id"])
    if not isinstance(installation, dict) or any(installation.get(k) != v for k, v in dict(scope, id=item["installation_id"], agent_id=item["agent_id"], version_id=item["agent_version_id"], status="active").items()):
        raise RuntimeError("exact current installation must be active before business submission")
    missing(owner, PREFIX + "/" + item["session_id"])
    missing(owner, RUNS + "/" + item["run_id"])
    if not confirm(project, language, case, digest(item)):
        raise RuntimeError("exact case execution confirmation missing")
    entry["session_intent"] = True
    record(deepcopy(journal))
    session = owner.call("POST", PREFIX, {"id": item["session_id"], "kind": "qa", "agent_id": item["agent_id"], "agent_version_id": item["agent_version_id"], "title": "Owned teaching " + language + " " + case})
    expected = dict(scope, id=item["session_id"], owner_id=item["owner"], installation_id=item["installation_id"], agent_id=item["agent_id"], agent_version_id=item["agent_version_id"])
    if not isinstance(session, dict) or any(session.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Session creation receipt differs from exact business owner")
    entry["session_receipt"] = {k: session[k] for k in expected}
    entry["usage_from"] = now()
    entry["run_intent"] = True
    record(deepcopy(journal))
    receipt = owner.call("POST", PREFIX + "/" + item["session_id"] + "/runs", {"run_id": item["run_id"], "idempotency_key": item["run_id"], "request": item["request"]})
    if not isinstance(receipt, dict) or receipt.get("run_id") != item["run_id"]:
        raise RuntimeError("Run submission acknowledgement differs from exact handle")
    entry["run_receipt"] = deepcopy(receipt)
    record(deepcopy(journal))
    return {"run_id": item["run_id"], "submitted": True, "execution_complete": False}


def observe(owner, plan, project, scope, language, case, journal, record):
    checked = validate_plan(plan, project, scope)
    item = selected(checked, language, case)
    authenticated(owner, item["owner"], scope)
    entry = state_for(journal, checked, item)
    if not entry.get("run_intent"):
        raise RuntimeError("no submitted Run handle to observe")
    run = verify_run(owner.call("GET", RUNS + "/" + item["run_id"]), item, scope)
    entry["run_observation"] = deepcopy(run)
    record(deepcopy(journal))
    return {"run_id": run["run_id"], "status": run["status"], "revision": run["revision"], "replacement_run_created": False}


def request_cancel(owner, plan, project, scope, language, journal, confirm, record):
    checked = validate_plan(plan, project, scope)
    item = selected(checked, language, "cancel")
    authenticated(owner, item["owner"], scope)
    entry = state_for(journal, checked, item)
    if not entry.get("run_receipt") or entry.get("cancel_intent"):
        raise RuntimeError("single cancellation needs its exact accepted fresh case handle")
    run = verify_run(owner.call("GET", RUNS + "/" + item["run_id"]), item, scope)
    if run["status"] in {"succeeded", "failed", "cancelled"}:
        raise RuntimeError("Run already terminal; it cannot prove in-flight cancellation")
    if not confirm(project, language, "cancel", digest({"run_id": item["run_id"], "revision": run["revision"]})):
        raise RuntimeError("exact cancellation confirmation missing")
    entry["cancel_intent"] = True
    record(deepcopy(journal))
    receipt = owner.call("POST", RUNS + "/" + item["run_id"] + "/cancel", {})
    receipt = verify_run(receipt, item, scope)
    if receipt["status"] not in {"cancelling", "cancelled"}:
        raise RuntimeError("cancel response does not confirm a cancellation state for the exact Run")
    entry["cancel_receipt"] = deepcopy(receipt)
    record(deepcopy(journal))
    return {"run_id": item["run_id"], "cancellation_requested": True, "provider_stop_proven": False, "billing_settlement_proven": False}


def messages(owner, item):
    reply = owner.call("GET", PREFIX + "/" + item["session_id"] + "/messages?page_size=100")
    if (not isinstance(reply, dict) or not isinstance(reply.get("items"), list)
            or type(reply.get("total")) is not int or reply["total"] < 0
            or type(reply.get("page")) is not int or reply["page"] != 1
            or type(reply.get("page_size")) is not int or reply["page_size"] != 100
            or len(reply["items"]) != reply["total"] or len(reply["items"]) > 100):
        raise RuntimeError("message history page is malformed or incomplete")
    return reply["items"]


def _usage_time(value):
    if not isinstance(value, str) or not value:
        raise RuntimeError("Usage timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError("Usage timestamp is malformed") from error
    if parsed.tzinfo is None:
        raise RuntimeError("Usage timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def usage(auditor, item, start, scope):
    items, total, page, end = [], None, 1, now()
    start_time, end_time = _usage_time(start), _usage_time(end)
    expected_scope = dict(scope, agent_id=item["agent_id"], agent_version_id=item["agent_version_id"], run_id=item["run_id"])
    while page <= 100:
        query = urlencode({"from": start, "to": end, "agent_id": item["agent_id"], "agent_version_id": item["agent_version_id"], "page": page, "page_size": 100})
        reply = auditor.call("GET", "/api/modules/usage/usage/runs/" + item["run_id"] + "/steps?" + query)
        if (not isinstance(reply, dict) or not isinstance(reply.get("items"), list)
                or type(reply.get("total")) is not int or reply["total"] < 0
                or type(reply.get("page")) is not int or reply["page"] != page
                or type(reply.get("page_size")) is not int or reply["page_size"] != 100
                or not isinstance(reply.get("scope"), dict)
                or any(reply["scope"].get(key) != value for key, value in expected_scope.items())
                or _usage_time(reply.get("from")) != start_time or _usage_time(reply.get("to")) != end_time):
            raise RuntimeError("Usage page does not match exact Run or pagination")
        if total is not None and total != reply["total"]:
            raise RuntimeError("Usage changed while paging a terminal Run")
        total = reply["total"]
        for item_row in reply["items"]:
            if not isinstance(item_row, dict):
                raise RuntimeError("Usage step is malformed")
            index, event_id = item_row.get("index"), item_row.get("event_id")
            occurred_at = _usage_time(item_row.get("occurred_at"))
            provider, model = item_row.get("provider"), item_row.get("model")
            step_id = item_row.get("step_id")
            counts = [item_row.get(field) for field in ("input_tokens", "output_tokens", "cost_micros")]
            if (type(index) is not int or index < 1 or not isinstance(event_id, str) or not event_id
                    or not isinstance(provider, str) or not provider.strip()
                    or not isinstance(model, str) or not model.strip()
                    or step_id is not None and (not isinstance(step_id, str) or not step_id)
                    or any(type(value) is not int or value < 0 for value in counts)
                    or not start_time <= occurred_at < end_time):
                raise RuntimeError("Usage step does not match the complete Usage DTO")
        items.extend(reply["items"])
        if len(items) == total:
            identifiers = [row.get("event_id") for row in items]
            if any(not isinstance(value, str) or not value for value in identifiers) or len(set(identifiers)) != len(identifiers):
                raise RuntimeError("Usage events are missing IDs or repeated across pages")
            indexes = sorted(row["index"] for row in items)
            if indexes != list(range(1, total + 1)):
                raise RuntimeError("Usage page indexes are incomplete or duplicated")
            return sorted(items, key=lambda row: row["event_id"])
        if len(items) > total or not reply["items"]:
            raise RuntimeError("Usage pagination is incomplete")
        page += 1
    raise RuntimeError("Usage exceeds bounded complete-page observation")


def verify_success_and_replay(owner, auditor, plan, project, scope, language, journal, confirm, record):
    checked = validate_plan(plan, project, scope)
    item = selected(checked, language, "baseline")
    authenticated(owner, item["owner"], scope)
    authenticated(auditor, "system.admin", scope)
    entry = state_for(journal, checked, item)
    if not entry.get("run_receipt") or not entry.get("usage_from") or entry.get("replay_intent"):
        raise RuntimeError("exact accepted baseline required; replay mutation is single-shot")
    before_run = verify_run(owner.call("GET", RUNS + "/" + item["run_id"]), item, scope)
    if before_run["status"] != "succeeded":
        raise RuntimeError("baseline has not succeeded; observe its original handle")
    before_messages = messages(owner, item)
    answers = [row for row in before_messages if row.get("role") == "assistant"]
    if len(answers) != 1 or not isinstance(answers[0].get("content"), str) or not answers[0]["content"].strip():
        raise RuntimeError("baseline lacks unique actual assistant output")
    metadata = answers[0].get("metadata", {})
    if metadata.get("schema") != item["output_schema"] or not metadata.get("context_checks") or not (metadata.get("knowledge") or metadata.get("references")):
        raise RuntimeError("business output does not prove its v2 schema and basic public tool/knowledge use")
    before_usage = usage(auditor, item, entry["usage_from"], scope)
    if not before_usage:
        raise RuntimeError("fresh cache-bypassed baseline has no model Usage evidence")
    if not confirm(project, language, "same-run-replay", digest(item)):
        raise RuntimeError("exact original Run replay confirmation missing")
    entry["replay_intent"] = {"run_revision": before_run["revision"], "messages_sha256": digest(before_messages), "usage_sha256": digest(before_usage)}
    record(deepcopy(journal))
    replay = owner.call("POST", PREFIX + "/" + item["session_id"] + "/runs", {"run_id": item["run_id"], "idempotency_key": item["run_id"], "request": item["request"]})
    if not isinstance(replay, dict) or replay.get("run_id") != item["run_id"]:
        raise RuntimeError("replay returned a replacement Run")
    after_run = verify_run(owner.call("GET", RUNS + "/" + item["run_id"]), item, scope)
    # Fresh end time intentionally includes any incorrectly billed replay.
    after_usage = usage(auditor, item, entry["usage_from"], scope)
    if after_run["revision"] != before_run["revision"] or after_run["status"] != "succeeded" or messages(owner, item) != before_messages or after_usage != before_usage:
        raise RuntimeError("exact replay changed Run, messages or actual cumulative Usage")
    entry["replay_receipt"] = {"run_id": item["run_id"], "revision": after_run["revision"], "usage_events": len(after_usage), "output_schema": item["output_schema"], "replay_verified": True}
    record(deepcopy(journal))
    return deepcopy(entry["replay_receipt"])


def verify_denials(foreign, administrator, plan, project, scope, language, journal, record):
    checked = validate_plan(plan, project, scope)
    item = selected(checked, language, "baseline")
    other = {"go": "python", "python": "java", "java": "go"}[language]
    authenticated(foreign, "demo." + other + ".user", scope)
    authenticated(administrator, "system.admin", scope)
    entry = state_for(journal, checked, item)
    if not entry.get("replay_receipt", {}).get("replay_verified"):
        raise RuntimeError("denial checks require completed isolated baseline and exact replay")
    results = []
    for actor, api in (("foreign_user", foreign), ("system.admin", administrator)):
        for method, path, body in (("GET", RUNS + "/" + item["run_id"], None),
                                   ("GET", PREFIX + "/" + item["session_id"] + "/messages", None),
                                   ("POST", RUNS + "/" + item["run_id"] + "/cancel", {}),
                                   ("POST", PREFIX, {"id": project + "-deny-" + actor.replace(".", "-") + "-" + language,
                                                     "kind": "qa", "agent_id": item["agent_id"], "agent_version_id": item["agent_version_id"], "title": "Isolation denial"})):
            try:
                api.call(method, path, body)
            except Exception as error:
                if getattr(error, "status", None) not in {403, 404}:
                    raise RuntimeError("denial was not a verified authorization boundary: "
                                       + actor + " " + method + " " + path + " HTTP "
                                       + str(getattr(error, "status", None))) from None
                results.append({"actor": actor, "method": method, "path": path, "http_status": error.status})
            else:
                raise RuntimeError("foreign user or administrator obtained ungranted business access")
    entry["denials"] = results
    record(deepcopy(journal))
    return {"verified_denials": len(results), "full_runtime_harness_acceptance": False}
