"""Optional public State capacity learned only from trusted gateway replies."""
from collections import OrderedDict
from .graph_context import resolve_graph_context

DEFAULT_REVISIONS = 64
MAXIMUM_REVISIONS = 4096


def reply_limit(result):
    """Validate optional protocol metadata, without granting any authority."""
    from .capability_client import GatewayError
    if not isinstance(result, dict):
        raise GatewayError("STATE_CAPACITY_INVALID", "checkpoint reply is not an object")
    if "checkpoint_history" not in result:
        return DEFAULT_REVISIONS
    history = result["checkpoint_history"]
    if (not isinstance(history, dict) or set(history) != {"version", "max_revisions"}
            or history.get("version") != "checkpoint-history/v1"
            or type(history.get("max_revisions")) is not int
            or not 1 <= history["max_revisions"] <= MAXIMUM_REVISIONS):
        raise GatewayError("STATE_CAPACITY_INVALID", "invalid published checkpoint capacity")
    return history["max_revisions"]


def context_key(client):
    context = getattr(client, "_context", None)
    if context is None:
        return None
    context = resolve_graph_context(context)
    fields = ("tenant_id", "department_id", "application_id", "installation_id",
              "agent_instance_id", "agent_id", "agent_version_id", "principal_type",
              "actor_id", "session_id", "task_id", "memory_policy_id")
    values = tuple(getattr(context, name, None) for name in fields)
    epoch = getattr(context, "authorization_epoch", None)
    if any(not isinstance(value,str) or not value for value in values) or type(epoch) is not int or epoch < 1:
        return None
    return (*values, epoch)


def revision_limit(client):
    cache = getattr(client, "_checkpoint_history_limits", None)
    key = context_key(client)
    return cache.get(key, DEFAULT_REVISIONS) if isinstance(cache, OrderedDict) and key is not None else DEFAULT_REVISIONS


def remember(client, result):
    from .capability_client import GatewayError
    limit = reply_limit(result)
    key = context_key(client)
    cache = getattr(client, "_checkpoint_history_limits", None)
    if "checkpoint_history" not in result:
        if key is not None and isinstance(cache,OrderedDict):
            cache.pop(key,None)
        return result
    if key is None:
        raise GatewayError("STATE_CAPACITY_INVALID", "exact bounded history and trusted execution scope required")
    if not isinstance(cache,OrderedDict):
        cache = client._checkpoint_history_limits = OrderedDict()
    cache[key] = limit
    cache.move_to_end(key)
    while len(cache)>32:
        cache.popitem(last=False)
    return result
