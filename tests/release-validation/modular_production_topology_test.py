from __future__ import annotations

import re
import ast
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / "deploy" / "k8s" / "production"
COMPOSE = ROOT / "compose.yaml"
RETIRED = {"go-backend", "go-harness", "evaluation-worker", "backend-worker", "rag-server", "rag-worker"}
EXPECTED_DEPLOYMENTS = {
    "platform-app",
    "frontend",
    "metric-runner",
    "oauth2-proxy",
}
EXPECTED_JOBS = {"platform-schema-migrate"}


def test_embedded_python_probes_compile_and_checkpoint_checks_full_schema():
    for path in _active_resources():
        for resource in yaml.safe_load_all(path.read_text(encoding='utf-8')):
            if not resource or resource.get('kind') not in {'Job', 'Deployment'}:
                continue
            pod = resource['spec']['template']['spec']
            for container in pod.get('initContainers', []) + pod.get('containers', []):
                if container.get('command') != ['python', '-c']:
                    continue
                code = container['args'][0]
                ast.parse(code)
                if container['name'] == 'wait-for-checkpoint-schema':
                    assert 'checkpoint_schema_state(connection' in code
                    assert 'validate_checkpoint_dsn(' in code
                    assert 'except Exception:' not in code
                    assert "table_name='checkpoint_migrations'" not in code


def _active_resources() -> list[Path]:
    kustomization = yaml.safe_load((PRODUCTION / "kustomization.yaml").read_text(encoding="utf-8"))
    paths = [PRODUCTION / resource for resource in kustomization["resources"]]
    assert all(path.is_file() for path in paths), "Kustomize references a missing production manifest"
    return paths


def _is_host_absolute(path: str) -> bool:
    """Recognize Unix, Windows drive, and UNC paths independent of test OS."""

    normalized = path.strip()
    return bool(re.match(r"^(?:/|\\\\|[A-Za-z]:[\\/])", normalized))


def _interpolation_default(value: str) -> str | None:
    """Return a Compose ${VAR:-default} value, if one is present."""

    match = re.search(r"\$\{[^}:]+:-([^}]+)\}", value)
    return match.group(1) if match else None


def test_modular_compose_has_host_os_independent_build_and_storage_defaults() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = {**compose["services"], **yaml.safe_load((ROOT / "deploy/compose/compose.init.yaml").read_text(encoding="utf-8"))["services"]}
    assert compose.get("name") == "agentplug"
    assert 'mysql' not in services
    assert services['postgres']['image'] == 'pgvector/pgvector:pg16'
    assert services['postgres']['environment']['POSTGRES_INITDB_ARGS'] == '--auth-host=scram-sha-256 --auth-local=trust'
    assert services['postgres']['volumes'] == ['modular-postgres-data:/var/lib/postgresql/data']
    assert services['postgres']['ports'] == ['127.0.0.1:${POSTGRES_HOST_PORT:-5432}:5432']
    runtime = services["platform-app"]
    migration = services["platform-migrate"]
    assert "platform_runtime:" in runtime["environment"]["DB_DSN"]
    assert "root:" not in runtime["environment"]["DB_DSN"]
    assert "PLATFORM_DEV_RUNTIME_PASSWORD" not in runtime["environment"]
    assert migration["entrypoint"] == ["/app/migrate"]
    assert "PLATFORM_MIGRATION_DB_DSN" in migration["environment"]["DB_DSN"]
    assert set(migration["environment"]) == {"APP_ENV", "DB_DRIVER", "DB_DSN", "PLATFORM_DEV_RUNTIME_PASSWORD"}, "migration must not inherit runtime secrets"
    assert runtime["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert runtime["environment"]["DB_DRIVER"] == "${DB_DRIVER:-pgx}"
    assert "platform-migrate" not in runtime["depends_on"]
    assert migration["profiles"] == ["init"]
    for name in ("postgres", "platform-app", "frontend", "metric-runner"):
        assert services[name]["restart"] == "unless-stopped", f"{name} will remain down after Docker Engine restart"
    # A deliberately empty value must disable dev provisioning in production.
    # 单横杠保留显式空值，生产不能因空值自动回退为开发引导。
    assert migration["environment"]["PLATFORM_DEV_RUNTIME_PASSWORD"].startswith("${PLATFORM_DEV_RUNTIME_PASSWORD-")

    frontend = services['frontend']['environment']
    assert frontend['OIDC_PROXY_AUTH_URL'] == '${OIDC_PROXY_AUTH_URL:-}'
    assert frontend['OIDC_ISSUER_URL'] == '${OIDC_ISSUER_URL:-}'
    for service in ('platform-app', 'frontend'):
        assert all('HOST_BIND:-127.0.0.1}' in port for port in services[service]['ports'] if 'HOST_BIND' in port)

    # Build contexts and Dockerfiles are repository-relative; no host runtime
    # or OS-specific absolute checkout path is required to build the stack.
    for name, service in services.items():
        assert "container_name" not in service, f"{name} pins a global container name"
        build = service.get("build")
        if build:
            context = build["context"] if isinstance(build, dict) else build
            assert isinstance(context, str) and not _is_host_absolute(context), (name, context)
            if isinstance(build, dict):
                dockerfile = build.get("dockerfile", "Dockerfile")
                assert not _is_host_absolute(dockerfile), (name, dockerfile)
                assert (ROOT / context / dockerfile).is_file(), (name, context, dockerfile)

        # Bind-mount defaults must be relative; callers may still override a
        # secret directory for their own environment. Named data volumes are
        # portable and avoid host-specific storage locations.
        for volume in service.get("volumes", []):
            if isinstance(volume, str):
                source = volume.split(":", 1)[0]
                default = _interpolation_default(source)
                if default is not None:
                    assert not _is_host_absolute(default), (name, source, default)
                elif source.startswith(("./", "../", "/", "\\")) or re.match(r"^[A-Za-z]:", source):
                    assert not _is_host_absolute(source), (name, source)
            elif isinstance(volume, dict) and volume.get("type") == "bind":
                source = str(volume.get("source", ""))
                default = _interpolation_default(source)
                if default is not None:
                    assert not _is_host_absolute(default), (name, source, default)
                else:
                    assert not _is_host_absolute(source), (name, source)

    assert "modular-postgres-data" in compose.get("volumes", {})
    assert "modular-artifact-data" in compose.get("volumes", {})

    # Host access is an optional operator-selected local-model route. It must
    # use Docker's portable gateway alias, never a hard-coded host IP.
    for name, service in services.items():
        for mapping in service.get("extra_hosts", []):
            host, separator, address = str(mapping).partition("=" if "=" in str(mapping) else ":")
            assert separator and host == "host.docker.internal" and address == "host-gateway", (name, mapping)


def test_production_kustomize_is_the_modular_monolith_topology() -> None:
    documents = [
        document
        for path in _active_resources()
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(document, dict)
    ]
    deployments = {
        document["metadata"]["name"]: document
        for document in documents
        if document.get("kind") == "Deployment"
    }
    assert set(deployments) == EXPECTED_DEPLOYMENTS
    jobs = {
        document["metadata"]["name"]: document
        for document in documents
        if document.get("kind") == "Job"
    }
    assert set(jobs) == EXPECTED_JOBS
    migration = jobs["platform-schema-migrate"]["spec"]
    assert migration["backoffLimit"] == 1
    assert migration["activeDeadlineSeconds"] == 300
    migration_pod = migration["template"]["spec"]
    assert migration_pod["restartPolicy"] == "Never"
    migration_container = migration_pod["containers"][0]
    assert migration_container["command"] == ["/app/migrate"]
    assert next(item for item in migration_container["env"] if item["name"] == "DB_DRIVER")["value"] == "pgx"
    assert migration_container.get("envFrom", []) == [], "migration must not receive runtime secrets"
    assert {item["name"] for item in migration_container["env"]} == {"APP_ENV", "DB_DRIVER", "DB_DSN"}
    assert next(item for item in migration_container["env"] if item["name"] == "APP_ENV")["valueFrom"]["configMapKeyRef"] == {
        "name": "lexagent-production-config", "key": "APP_ENV"
    }
    runtime_container = deployments["platform-app"]["spec"]["template"]["spec"]["containers"][0]
    assert migration_container["image"] == runtime_container["image"]
    migration_dsn = next(item for item in migration_container["env"] if item["name"] == "DB_DSN")
    assert migration_dsn["valueFrom"]["secretKeyRef"] == {
        "name": "lexagent-platform-migration-secret", "key": "DB_DSN"
    }
    assert not any(
        item.get("secretRef", {}).get("name") == "lexagent-platform-migration-secret"
        for item in runtime_container["envFrom"]
    ), "migration credentials must not enter the runtime"
    policies = {
        document["metadata"]["name"]: document["spec"]
        for document in documents if document.get("kind") == "NetworkPolicy"
    }
    migration_network = policies["platform-migration-traffic"]
    assert migration_network["podSelector"] == {"matchLabels": {"app": "platform-schema-migrate"}}
    assert migration_network["ingress"] == []
    assert {port["port"] for rule in migration_network["egress"] for port in rule["ports"]} == {5432, 53}
    assert deployments["platform-app"]["spec"]["replicas"] == 1
    assert deployments["platform-app"]["spec"]["strategy"]["type"] == "Recreate"
    for name in ("metric-runner",):
        assert deployments[name]["spec"]["replicas"] == 1
        assert deployments[name]["spec"]["strategy"]["type"] == "Recreate"
    services = {
        document["metadata"]["name"]: document
        for document in documents
        if document.get("kind") == "Service"
    }
    for name in ("platform-app", "frontend", "metric-runner"):
        assert name in services
        selector = services[name]["spec"]["selector"]
        pod_labels = deployments[name]["spec"]["template"]["metadata"]["labels"]
        assert all(pod_labels.get(key) == value for key, value in selector.items())

    active_yaml = "\n".join(path.read_text(encoding="utf-8") for path in _active_resources()).lower()
    assert not any(name in active_yaml for name in RETIRED)
    assert "http://platform-app:8080" in active_yaml
    secret_shape = (PRODUCTION / "secret.example.yaml").read_text(encoding="utf-8")
    assert "KNOWLEDGE_DATABASE_DSN:" in secret_shape
    assert "name: migration-job" not in active_yaml


def test_production_apply_waits_for_only_current_workloads() -> None:
    script = (PRODUCTION / "apply.ps1").read_text(encoding="utf-8")
    expected_waits = {
        "platform-app",
                "metric-runner",
        "frontend",
        "oauth2-proxy",
    }
    assert "Apply-RenderedKind 'Job' 'platform-schema-migrate'" in script
    assert "Apply-RenderedKind 'Deployment'" in script
    assert "migration-job.yaml" not in script
    assert "deployment/evaluation-worker" not in script
    assert "$releaseBundle.secret_keys.PSObject.Properties" in script
    assert "required Secret '$secret' is missing key '$key'" in script
    assert "job/platform-schema-migrate" in script
    assert 'cosign verify -a "source_commit=$sourceCommit" --certificate-identity' in script
    assert "cosign verify-attestation --type spdxjson" in script
    assert "validate_production_release.py" in script
    assert script.index("Apply-RenderedKind 'Job' 'platform-schema-migrate'") < script.index("Apply-RenderedKind 'Deployment'")
    assert script.index("job/platform-schema-migrate") < script.index("Apply-RenderedKind 'Deployment'")
    waits = {
        line.split("deployment/", 1)[1].split(" ", 1)[0]
        for line in script.splitlines()
        if "kubectl rollout status deployment/" in line
    }
    assert waits == expected_waits


def test_restricted_pods_and_migration_network_are_deployable() -> None:
    documents = [
        document
        for path in _active_resources()
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(document, dict)
    ]
    namespace = next(item for item in documents if item.get("kind") == "Namespace")
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    workloads = [item for item in documents if item.get("kind") in {"Deployment", "Job"}]
    for workload in workloads:
        pod = workload["spec"]["template"]["spec"]
        for container in pod.get("initContainers", []) + pod.get("containers", []):
            security = container.get("securityContext", {})
            assert security.get("allowPrivilegeEscalation") is False, (workload["metadata"]["name"], container["name"])
            capabilities = security.get("capabilities", {})
            assert "ALL" in capabilities.get("drop", []), (workload["metadata"]["name"], container["name"])
            assert set(capabilities.get("add", [])) <= {"NET_BIND_SERVICE"}

    policies = {item["metadata"]["name"]: item["spec"] for item in documents if item.get("kind") == "NetworkPolicy"}
    assert policies["default-deny"]["podSelector"] == {}
    migration = next(item for item in workloads if item["metadata"]["name"] == "platform-schema-migrate")
    pod_labels = migration["spec"]["template"]["metadata"]["labels"]
    policy = policies["platform-migration-traffic"]
    assert all(pod_labels.get(key) == value for key, value in policy["podSelector"]["matchLabels"].items())
    assert policy["ingress"] == []
    assert policy["egress"]


def test_default_quality_gate_and_offline_bundle_exclude_retired_processes() -> None:
    unit_ps = (ROOT / "scripts" / "unit.ps1").read_text(encoding="utf-8")
    unit_sh = (ROOT / "scripts" / "unit.sh").read_text(encoding="utf-8")
    images = (ROOT / "deploy" / "offline" / "images.txt").read_text(encoding="utf-8")
    prometheus = (ROOT / "deploy" / "observability" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    for retired in RETIRED:
        assert retired not in unit_ps
        assert retired not in unit_sh
        assert retired not in images
        assert retired not in prometheus
    assert "agentplug:platform" in images
    assert "job_name: agentplug-platform" in prometheus
    assert "platform-app.lexagent.svc.cluster.local:8081" in prometheus

    ps_match = re.search(r"foreach \(\$module in @\((.*?)\)\)", unit_ps, re.DOTALL)
    sh_match = re.search(r"go_modules=\((.*?)\n\)", unit_sh, re.DOTALL)
    assert ps_match and sh_match, "could not find the cross-platform Go module lists"
    ps_modules = {name.replace("\\", "/") for name in re.findall(r'"([^"]+)"', ps_match.group(1))}
    sh_modules = set(re.findall(r'"([^"]+)"', sh_match.group(1)))
    assert ps_modules == sh_modules


def test_obsolete_kind_overlay_and_legacy_source_presence_gates_are_retired() -> None:
    # These artifacts describe the pre-cutover split Backend/Harness topology.
    # Keeping them runnable invites operators to deploy an architecture that
    # no longer matches the current modular Platform. / 这些入口描述切换前的
    # Backend/Harness 双进程拓扑；保留可运行版本会诱导部署已经退役的架构。
    assert not (ROOT / "deploy" / "k8s" / "kind-e2e").exists()
    assert not (ROOT / "domain-agents").exists(), "obsolete domain agent package still imports retired Harness contracts"
    assert not (ROOT / "workers" / "evaluation-worker").exists(), "retired evaluation worker source remains beside the active Product Runner"
    for retired_gate in (
        "scripts/verify_ar_tasks.py",
        "scripts/verify_agent_productization_tasks.py",
        "scripts/verify_model_governance_tasks.py",
    ):
        assert not (ROOT / retired_gate).exists(), f"obsolete source-presence gate remains: {retired_gate}"
