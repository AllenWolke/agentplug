"""Checkpoint isolation regression / 持久化会话作用域隔离回归。"""

from types import SimpleNamespace

import pytest

from agent_platform_sdk.checkpoint import scoped_config


def context(**changes):
    values = dict(
        tenant_id="tenant",
        department_id="dept",
        application_id="app",
        installation_id="installation",
        agent_instance_id="instance",
        agent_id="agent",
        agent_version_id="version",
        principal_type="user",
        actor_id="actor",
        thread_id="session",
        session_id="session",
        task_id="run",
    )
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "department_id",
        "application_id",
        "installation_id",
        "agent_instance_id",
        "agent_id",
        "principal_type",
        "actor_id",
        "thread_id",
    ],
)
def test_checkpoint_identity_dimensions_are_isolated(field):
    assert scoped_config(context()) != scoped_config(context(**{field: "other"}))


def test_same_session_continues_across_runs():
    assert scoped_config(context(task_id="run-one")) == scoped_config(
        context(task_id="run-two")
    )


def test_delimiter_cannot_alias_another_scope():
    assert scoped_config(context(tenant_id="a:b", department_id="c")) != scoped_config(
        context(tenant_id="a", department_id="b:c")
    )


def test_missing_installation_is_rejected():
    with pytest.raises(ValueError, match="complete trusted checkpoint scope"):
        scoped_config(context(installation_id=""))
