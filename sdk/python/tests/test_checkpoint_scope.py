"""Checkpoint keys must isolate every trusted identity dimension. / 完整作用域隔离。"""

from types import SimpleNamespace
from typing import TypedDict

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agent_platform_sdk.checkpoint import scoped_config


def _scope(**overrides: str) -> SimpleNamespace:
    values = {
        "tenant_id": "tenant-a",
        "department_id": "department-a",
        "application_id": "application-a",
        "installation_id": "install-a",
        "agent_instance_id": "instance-a",
        "agent_id": "agent-a",
        "agent_version_id": "version-a",
        "principal_type": "human",
        "actor_id": "same-name",
        "session_id": "session-a",
        "thread_id": "",
        "run_id": "run-a",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_every_persistent_scope_dimension_changes_checkpoint_key() -> None:
    baseline = scoped_config(_scope())["configurable"]["thread_id"]
    for name, different in {
        "tenant_id": "tenant-b",
        "department_id": "department-b",
        "application_id": "application-b",
        "installation_id": "install-b",
        "agent_instance_id": "instance-b",
        "agent_id": "agent-b",
        "agent_version_id": "version-b",
        "principal_type": "machine",
        "actor_id": "other-name",
        "session_id": "session-b",
    }.items():
        assert (
            scoped_config(_scope(**{name: different}))["configurable"]["thread_id"]
            != baseline
        ), name


def test_same_session_continues_across_runs_and_rejects_missing_scope() -> None:
    first = scoped_config(_scope(run_id="run-one"))["configurable"]
    resumed = scoped_config(_scope(run_id="run-two"))["configurable"]
    assert first["thread_id"] == resumed["thread_id"]
    assert first["checkpoint_ns"] == resumed["checkpoint_ns"]
    with pytest.raises(ValueError, match="complete trusted checkpoint scope"):
        scoped_config(_scope(installation_id=""))


def test_tuple_encoding_prevents_delimiter_collision() -> None:
    a = scoped_config(_scope(tenant_id="a:b", department_id="c"))
    b = scoped_config(_scope(tenant_id="a", department_id="b:c"))
    assert a["configurable"]["thread_id"] != b["configurable"]["thread_id"]


class _State(TypedDict):
    value: str


def test_checkpoint_state_isolated_and_same_session_continues_across_runs() -> None:
    graph = StateGraph(_State)
    graph.add_node("save", lambda state: state)
    graph.add_edge(START, "save")
    graph.add_edge("save", END)
    saver = MemorySaver()
    app = graph.compile(checkpointer=saver)
    original = scoped_config(_scope(run_id="run-one"))
    app.invoke({"value": "private"}, original)
    continuation = scoped_config(_scope(run_id="run-two"))
    checkpoint = saver.get_tuple(continuation)
    assert checkpoint is not None
    assert checkpoint.checkpoint["channel_values"]["value"] == "private"
    for change in (
        {"principal_type": "machine"},
        {"actor_id": "other-name"},
        {"installation_id": "install-b"},
        {"agent_instance_id": "instance-b"},
        {"agent_version_id": "version-b"},
        {"session_id": "session-b"},
    ):
        assert saver.get_tuple(scoped_config(_scope(**change))) is None
