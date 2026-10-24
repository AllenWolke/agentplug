"""Current document authorization for cached business results, without models."""
from __future__ import annotations
import copy
import json
from .capability_client import GatewayError

FIELDS = ("source", "provider_knowledge_base_id", "provider_document_id", "document_version")


async def authorize_references(client, references, knowledge_scope, *, timeout=10):
    if not isinstance(references, list):
        raise GatewayError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED", "reference identities required")
    identities, seen = [], set()
    for reference in references:
        if not isinstance(reference, dict) or any(not isinstance(reference.get(field), str) or not reference[field] for field in FIELDS):
            raise GatewayError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED", "published reference identity missing")
        item = {field: reference[field] for field in FIELDS}
        digest = json.dumps(item, sort_keys=True)
        if digest not in seen:
            seen.add(digest); identities.append(item)
    for offset in range(0, len(identities), 128):
        page = identities[offset:offset + 128]
        result = await client._post("/internal/knowledge/references/authorize", {
            "version": "knowledge-reference-authorization/v1", "knowledge_scope": knowledge_scope,
            "references": page}, timeout)
        if (not isinstance(result, dict) or result.get("version") != "knowledge-reference-authorization/v1"
                or result.get("authorized") is not True or type(result.get("reference_count")) is not int
                or result["reference_count"] != len(page) or type(result.get("model_requests_sent")) is not int or result.get("model_requests_sent") != 0):
            raise GatewayError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED", "current reference authority unavailable")
    return True


async def authorize_cached_result(client, result, knowledge_scope):
    """Traverse documented reference containers; no regulatory schema rules."""
    references = []
    def visit(value):
        if isinstance(value, dict):
            if "doc_id" in value and "content" in value:
                # Missing identities must deny cached disclosure, not make a
                # text-bearing reference disappear from the authority check.
                references.append(copy.deepcopy(value))
                if "parent_context" in value:
                    parent = value["parent_context"]
                    documents = parent.get("source_documents") if isinstance(parent, dict) else None
                    if (not isinstance(parent, dict)
                            or parent.get("schema_version") != "authorized-parent-context/v1"
                            or not isinstance(documents, list) or not 1 <= len(documents) <= 1000
                            or any(not isinstance(document, dict) for document in documents)
                            or not any(all(document.get(field) == value.get(field) for field in FIELDS)
                                for document in documents)):
                        raise GatewayError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED", "parent reference proof unavailable")
                    # Every sibling whose text occurs in the assembled parent
                    # needs current authority, even when the child remains allowed.
                    references.extend(copy.deepcopy(documents))
                return
            if "references" in value:
                items=value["references"]
                if not isinstance(items,list) or len(items)>4096 or any(not isinstance(item,dict) for item in items):
                    raise GatewayError("KNOWLEDGE_REFERENCE_AUTHORITY_DENIED","reference identities required")
                references.extend(copy.deepcopy(items))
            for key, item in value.items():
                if key not in {"context", "prompt_program", "messages"}:
                    visit(item)
        elif isinstance(value, (list, tuple)):
            for item in value: visit(item)
    visit(result)
    return await authorize_references(client, references, knowledge_scope)
