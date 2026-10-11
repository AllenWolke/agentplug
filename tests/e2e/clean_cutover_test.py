"""Static assertions for the current modular product entry points."""
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_no_root_fused_runtime():
    assert not (ROOT / "py-ai").exists()


def test_compose_retains_public_core_and_excludes_retired_business():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "platform-app:" in compose
    assert "frontend:" in compose
    assert "regulatory-validation-agent:" not in compose
    assert "regulatory-qa-agent:" not in compose
    assert "go-backend:" not in compose
    assert "go-harness:" not in compose
    assert "lexagent-agent:" not in compose
    assert "./LexAgent/py-ai" not in compose
    assert ("AGENT_CAPABILITIES=" + "check,qa") not in compose


def test_default_compose_and_production_k8s_exclude_legacy_agents():
    """The maintained production bundle contains only the modular workloads."""
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "deploy" / "k8s" / "production").glob("*.yaml")
    )
    assert "name: lexagent-agent\n" not in production
    assert "app: lexagent-agent" not in production
    assert "agent.platform_entry" not in production
    assert "go-backend" not in production
    assert "go-harness" not in production


def test_only_current_e2e_and_agentctl_are_in_the_default_go_gates():
    workflow = (ROOT / ".github" / "workflows" / "three-project-quality.yml").read_text(encoding="utf-8")
    powershell = (ROOT / "scripts" / "unit.ps1").read_text(encoding="utf-8")
    posix = (ROOT / "scripts" / "unit.sh").read_text(encoding="utf-8")
    matrix = workflow.split("module:", 1)[1].splitlines()[0]
    assert "cli/agentctl" in matrix
    assert "tests/e2e" not in matrix
    assert "cli," not in matrix
    assert '"cli\\agentctl"' in powershell
    assert '"cli"' not in powershell
    assert '"tests\\e2e"' not in powershell
    assert '"cli/agentctl"' in posix
    assert '"cli"' not in posix
    assert '"tests/e2e"' not in posix
    assert not (ROOT / "tests" / "e2e" / "test_modular_negative_sql_assertions.py").exists()
    assert not list((ROOT / "tests" / "e2e").glob("*.go"))
    assert not (ROOT / "tests" / "e2e" / "go.mod").exists()
    assert not (ROOT / "cli" / "main.go").exists()
    # The pre-modular three-project smoke runner called the deleted Backend /
    # Harness. Historical Compose snapshots may mention its former path, but
    # no runnable copy remains under the current test tree.
    # 模块化前的三项目探针依赖已删除的 Backend/Harness，只保留历史配置记录，不留可执行脚本。
    assert not (ROOT / "tests" / "e2e" / "verify_three_project_chain.py").exists()


def test_database_acceptance_uses_postgresql_and_keeps_real_sql_suites():
    workflow = (ROOT / ".github" / "workflows" / "three-project-quality.yml").read_text(encoding="utf-8")
    assert "test_modular_negative_postgres_assertions.py" in workflow
    assert "test_modular_negative_sql_assertions.py" not in workflow
    assert "--suite administration" in workflow
    assert "--suite checkpoint --sdk-full" in workflow
    assert "python scripts/verify_postgres_backup_isolated.py" in workflow
    retired_mysql_entrypoints = (
        "first_admin_mysql_fixture.py",
        "checkpoint_mysql_fixture.py",
        "modular_data_restore_e2e.py",
    )
    assert all(not (ROOT / "tests" / "e2e" / name).exists() for name in retired_mysql_entrypoints)
    assert (ROOT / "tests" / "e2e" / "first_admin_postgres_fixture.py").is_file()
    assert (ROOT / "tests" / "e2e" / "checkpoint_postgres_fixture.py").is_file()
    assert (ROOT / "tests" / "e2e" / "postgres_data_restore_e2e.py").is_file()


def test_optional_minio_has_no_public_root_password_fallback():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    guard = (ROOT / "scripts" / "minio-entrypoint-guard.sh").read_text(encoding="utf-8")
    assert 'profiles: ["full"]' in compose
    assert "MINIO_ROOT_PASSWORD: ${EVALUATION_ARTIFACT_S3_SECRET_KEY:-}" in compose
    assert "minio-entrypoint-guard.sh" in compose
    assert 'if [ -z "${MINIO_ROOT_PASSWORD:-}" ]; then' in guard
    assert 'exec /usr/bin/docker-entrypoint.sh "$@"' in guard


def test_active_deployment_and_source_do_not_call_retired_backend_or_harness():
    """The modular runtime must not reach back into the retired processes."""
    active_configs = [
        ROOT / "compose.yaml",
        ROOT / ".github" / "workflows" / "three-project-quality.yml",
        ROOT / "scripts" / "platform.ps1",
        ROOT / "scripts" / "platform.sh",
        *sorted((ROOT / "deploy" / "k8s" / "production").glob("*.yaml")),
    ]
    forbidden_runtime_refs = (
        "http://go-backend:",
        "https://go-backend:",
        "http://go-harness:",
        "https://go-harness:",
        "BACKEND_URL",
        "HARNESS_URL",
        "deploy/compose/legacy/docker-compose",
    )
    for path in active_configs:
        text = path.read_text(encoding="utf-8")
        assert not any(token in text for token in forbidden_runtime_refs), path.relative_to(ROOT)

    # The root environment template is copied into disposable modular E2E
    # settings, so it must not seed removed services' endpoints or host ports.
    # 根环境模板会被复制进模块化临时验收配置，不得再注入已退役服务地址/端口。
    environment_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    retired_environment = (
        "E2E_BASE_URL",
        "E2E_API_KEY",
        "BACKEND_HOST_PORT",
        "HARNESS_HOST_PORT",
        "PY_AI_HOST_PORT",
        "BACKEND_RUN_MODE",
        "BACKEND_RUN_BOOTSTRAP",
        "go-backend:8080",
        "go-harness:8081",
    )
    assert not any(token in environment_example for token in retired_environment)

    active_go_roots = (
        "platform",
        "frontend",
        "adapters",
        "workers",
        "cli/agentctl",
        "sdk/go",
    )
    retired_imports = (
        '"github.com/lexagent/go-backend/',
        '"github.com/lexagent/go-harness/',
    )
    for relative_root in active_go_roots:
        for path in (ROOT / relative_root).rglob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            text = path.read_text(encoding="utf-8")
            assert not any(token in text for token in retired_imports), path.relative_to(ROOT)

    # The optional Kind workload is a future scheduling experiment. It must not
    # reintroduce the retired mock identity or Backend URL contract.
    # 可选 Kind 清单仅是未来调度实验，不得恢复已退役的 mock 身份或 Backend URL 契约。
    kind_workload = (ROOT / "tests" / "release-validation" / "kind-frontend-workload.yaml").read_text(encoding="utf-8")
    for token in ("name: AUTH_MODE", "BACKEND_URL", "DEMO_PASSWORD_"):
        assert token not in kind_workload
    assert "FRONTEND_AUTH_MODE" in kind_workload


def test_old_release_validation_entrypoints_are_retired():
    retired = (
        "docker-compose.real-model.yaml",
        "docker-compose.validation.yaml",
        "harness_capacity_probe.py",
        "prepare_business_eval_profile.sql",
        "profile_qa_latency.py",
        "probe_boundary_api.ps1",
        "probe_business_sources.ps1",
        "probe_canary_bff.ps1",
        "probe_candidate_sources.ps1",
        "probe_skill_prompt.py",
        "run_boundary_worker_ab.ps1",
        "run_real_model_quality_gate.ps1",
        "run_real_provider_governance_gate.ps1",
        "start_boundary_candidates.ps1",
        "start_python_boundary_candidate.ps1",
        "wire_boundary_chain.ps1",
    )
    release_validation = ROOT / "tests" / "release-validation"
    assert all(not (release_validation / name).exists() for name in retired)


def test_legacy_mock_identity_scheduler_load_script_is_retired():
    """Do not keep a load entrypoint tied to old API and mock identity headers."""
    assert not (ROOT / "tests" / "performance" / "agent_scheduler_load.py").exists()


def test_retired_backend_and_harness_have_no_runnable_service_entrypoints():
    # Clean cutover retires the old code modules themselves, not just their
    # Dockerfiles and service mains. Historical copies live in documentation.
    assert not (ROOT / "go-backend").exists()
    assert not (ROOT / "go-harness").exists()


def test_legacy_implementation_document_generator_is_retired():
    """Do not regenerate current implementation docs from deleted MVP sources."""
    assert not (ROOT / "scripts" / "generate-requirement-implementation-docs.ps1").exists()


def assert_historical_snapshot(text: str) -> None:
    """Keep archived source distinct from current runtime / 历史代码不能冒充现行实现。"""
    assert "历史快照（非当前实现）" in text
    assert "不可作为当前运行代码" in text
    assert "当前本地文件全文" not in text


def test_retired_business_history_is_not_in_public_docs():
    """Historical business code belongs in the interview/private archive."""
    for directory in ("校验Agent与口径Agent历史会话需求", "受控意图分类需求",
                      "普通用户注册登录与Agent授权需求", "模块化单体单实例改造"):
        assert not (ROOT / "docs" / "新增需求" / directory).exists()


@pytest.mark.parametrize("mutation", ["missing_snapshot", "missing_warning", "claims_current"])
def test_historical_snapshot_gate_rejects_misleading_archive(mutation):
    text = "历史快照（非当前实现）\n不可作为当前运行代码"
    assert_historical_snapshot(text)
    if mutation == "missing_snapshot":
        text = text.replace("历史快照（非当前实现）", "")
    elif mutation == "missing_warning":
        text = text.replace("不可作为当前运行代码", "")
    else:
        text += "\n当前本地文件全文"
    with pytest.raises(AssertionError):
        assert_historical_snapshot(text)
