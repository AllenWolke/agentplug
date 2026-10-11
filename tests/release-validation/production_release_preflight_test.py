"""Release preflight must reject omissions and unsafe image substitutions."""

from __future__ import annotations

from copy import deepcopy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts.validate_production_release import (
    EXPECTED_DEPLOYMENTS,
    EXPECTED_JOBS,
    REQUIRED_NETWORK_POLICIES,
    main,
    required_secret_keys,
    release_inventory,
    validate_bundle,
    validate_release_manifest,
)


DIGEST = "1" * 64
COMMIT = "a" * 40


def bundle() -> list[dict]:
    resources = [{"kind": "Namespace", "metadata": {"name": "lexagent"}}]
    resources.append({"kind": "ConfigMap", "metadata": {"name": "lexagent-production-config", "namespace": "lexagent"},
                      "data": {"APP_ENV": "production", "FRONTEND_AUTH_MODE": "oidc", "OIDC_PROXY_TRUSTED": "true",
                               "OIDC_PROXY_AUTH_URL": "http://oauth2-proxy:4180/oauth2/auth"}})
    for kind, names in (("Deployment", EXPECTED_DEPLOYMENTS), ("Job", EXPECTED_JOBS)):
        for name in sorted(names):
            workload = {
                "kind": kind,
                "metadata": {"name": name, "namespace": "lexagent"},
                "spec": {"template": {"spec": {
                    "initContainers": [{"name": "init", "image": f"registry.test/init@sha256:{DIGEST}"}],
                    "containers": [{"name": "main", "image": f"registry.test/{name}@sha256:{DIGEST}"}],
                }}},
            }
            container = workload["spec"]["template"]["spec"]["containers"][0]
            if name in {"frontend", "oauth2-proxy"}:
                variable = "OIDC_ISSUER_URL" if name == "frontend" else "OAUTH2_PROXY_OIDC_ISSUER_URL"
                container["env"] = [{"name": variable, "valueFrom": {"secretKeyRef": {
                    "name": "lexagent-oidc-secret", "key": "issuer_url"}}}]
            if name == "frontend":
                container["envFrom"] = [{"configMapRef": {"name": "lexagent-production-config"}}]
                container["env"].extend({"name": variable, "valueFrom": {"secretKeyRef": {"name": "lexagent-oidc-secret", "key": key}}} for variable, key in {
                    "OIDC_STEP_UP_CLIENT_ID": "client_id", "OIDC_STEP_UP_CLIENT_SECRET": "client_secret", "OIDC_STEP_UP_REDIRECT_URL": "step_up_redirect_url"}.items())
            if name == "oauth2-proxy":
                container["args"] = ["--provider=oidc", "--set-xauthrequest=true", "--upstream=static://202"]
            resources.append(workload)
    for name in sorted(REQUIRED_NETWORK_POLICIES):
        spec = {"podSelector": {"matchLabels": {"app": "platform-app"}}, "policyTypes": ["Ingress", "Egress"]}
        if name == "default-deny":
            spec["podSelector"] = {}
        elif name in {"platform-migration-traffic"}:
            app = "platform-schema-migrate"
            spec.update({
                "podSelector": {"matchLabels": {"app": app}}, "ingress": [],
                "egress": [
                    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "database"}}}],
                     "ports": [{"protocol": "TCP", "port": 5432}]},
                    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                     "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                ],
            })
        elif name == "example-agents-traffic":
            spec["podSelector"] = {"matchExpressions": [{"key": "app", "operator": "In", "values": ["example-go", "example-python", "example-java"]}]}
            spec["egress"] = [
                {"to": [{"podSelector": {"matchLabels": {"app": "platform-app"}}}],
                 "ports": [{"protocol": "TCP", "port": 8080}, {"protocol": "TCP", "port": 8081}]},
                {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                 "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
            ]
        else:
            app = {
                "frontend-platform-traffic": "frontend",
                "platform-app-traffic": "platform-app",
                "metric-runner-isolation": "metric-runner",
                "oauth2-proxy-traffic": "oauth2-proxy",
            }[name]
            spec["podSelector"] = {"matchLabels": {"app": app}}
            if name == "metric-runner-isolation":
                spec["ingress"] = [{"from": [{"podSelector": {"matchLabels": {"app": "platform-app"}}}],
                                    "ports": [{"protocol": "TCP", "port": 8085}]}]
            if name == "frontend-platform-traffic":
                spec["egress"] = [
                    {"to": [{"podSelector": {"matchLabels": {"app": "platform-app"}}}],
                     "ports": [{"protocol": "TCP", "port": 8080}]},
                    {"to": [{"podSelector": {"matchLabels": {"app": "oauth2-proxy"}}}],
                     "ports": [{"protocol": "TCP", "port": 4180}]},
                    {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                     "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
                ]
            if name == "oauth2-proxy-traffic":
                spec["ingress"] = [
                    {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}],
                     "ports": [{"protocol": "TCP", "port": 4180}]},
                    {"from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}],
                     "ports": [{"protocol": "TCP", "port": 4180}]},
                ]
        if name in {"frontend-platform-traffic", "platform-app-traffic", "oauth2-proxy-traffic"}:
            spec.setdefault("egress", []).append({"to": [{"ipBlock": {"cidr": "10.20.30.10/32"}}],
                                                 "ports": [{"protocol": "TCP", "port": 443}]})
        resources.append({"kind": "NetworkPolicy", "metadata": {"name": name, "namespace": "lexagent"}, "spec": spec})
    resources.append({"kind": "Ingress", "metadata": {"name": "lexagent", "namespace": "lexagent",
                      "annotations": {"nginx.ingress.kubernetes.io/auth-url": "http://oauth2-proxy.lexagent.svc.cluster.local/oauth2/auth"}}})
    resources.append({"kind": "Ingress", "metadata": {"name": "lexagent-oauth2", "namespace": "lexagent"}})
    return resources


def validate(resources: list[dict]) -> list[str]:
    return validate_bundle(yaml.safe_dump_all(resources), "lexagent")


def test_complete_bundle_includes_init_container_images() -> None:
    images = validate(bundle())
    assert f"registry.test/init@sha256:{DIGEST}" in images
    assert len(images) == len(EXPECTED_DEPLOYMENTS | EXPECTED_JOBS) + 1


@pytest.mark.parametrize("port", [3306, 5432, 443, 8000])
def test_agents_cannot_bypass_platform_for_database_or_models(port: int) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["kind"] == "NetworkPolicy" and item["metadata"]["name"] == "example-agents-traffic")
    policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "10.20.30.10/32"}}],
                                   "ports": [{"protocol": "TCP", "port": port}]})
    with pytest.raises(ValueError, match="Agent egress"):
        validate(resources)


def test_agents_cannot_redirect_platform_ports_to_other_pods() -> None:
    resources = bundle()
    policy = next(item for item in resources if item["kind"] == "NetworkPolicy" and item["metadata"]["name"] == "example-agents-traffic")
    policy["spec"]["egress"][0]["to"] = [{"podSelector": {"matchLabels": {"app": "other"}}}]
    with pytest.raises(ValueError, match="Agent egress"):
        validate(resources)


@pytest.mark.parametrize("mutation", [
    "session_url", "frontend_issuer", "proxy_issuer", "proxy_auth_header",
    "ingress_forward", "frontend_egress", "proxy_ingress", "extra_proxy_port",
    "frontend_portless", "proxy_portless", "frontend_override", "frontend_env_from",
    "step_up_client", "step_up_secret", "step_up_callback",
])
def test_oidc_release_boundary_rejects_broken_or_untrusted_wiring(mutation: str) -> None:
    resources = bundle()
    get = lambda kind, name: next(item for item in resources if item["kind"] == kind and item["metadata"]["name"] == name)
    if mutation == "session_url":
        get("ConfigMap", "lexagent-production-config")["data"].pop("OIDC_PROXY_AUTH_URL")
    elif mutation == "frontend_issuer":
        get("Deployment", "frontend")["spec"]["template"]["spec"]["containers"][0]["env"] = []
    elif mutation == "proxy_issuer":
        get("Deployment", "oauth2-proxy")["spec"]["template"]["spec"]["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]["key"] = "other_issuer"
    elif mutation == "proxy_auth_header":
        get("Deployment", "oauth2-proxy")["spec"]["template"]["spec"]["containers"][0]["args"].remove("--set-xauthrequest=true")
    elif mutation == "ingress_forward":
        get("Ingress", "lexagent")["metadata"]["annotations"]["nginx.ingress.kubernetes.io/auth-response-headers"] = "X-Auth-Request-Roles"
    elif mutation == "frontend_egress":
        get("NetworkPolicy", "frontend-platform-traffic")["spec"]["egress"] = []
    elif mutation == "proxy_ingress":
        get("NetworkPolicy", "oauth2-proxy-traffic")["spec"]["ingress"] = []
    elif mutation == "extra_proxy_port":
        get("NetworkPolicy", "frontend-platform-traffic")["spec"]["egress"].append({
            "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "default"}}}],
            "ports": [{"protocol": "TCP", "port": 4180}],
        })
    elif mutation == "frontend_portless":
        get("NetworkPolicy", "frontend-platform-traffic")["spec"]["egress"].append({"to": [{"podSelector": {"matchLabels": {"app": "oauth2-proxy"}}}]})
    elif mutation == "proxy_portless":
        get("NetworkPolicy", "oauth2-proxy-traffic")["spec"]["ingress"].append({"from": [{"podSelector": {"matchLabels": {"app": "other"}}}]})
    elif mutation == "frontend_override":
        get("Deployment", "frontend")["spec"]["template"]["spec"]["containers"][0]["env"].append({
            "name": "OIDC_PROXY_AUTH_URL", "value": "http://attacker:4180/oauth2/auth"})
    elif mutation.startswith("step_up_"):
        variable = {"step_up_client": "OIDC_STEP_UP_CLIENT_ID", "step_up_secret": "OIDC_STEP_UP_CLIENT_SECRET", "step_up_callback": "OIDC_STEP_UP_REDIRECT_URL"}[mutation]
        environment = get("Deployment", "frontend")["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in environment if item["name"] == variable)["valueFrom"]["secretKeyRef"]["key"] = "unverified"
    else:
        get("Deployment", "frontend")["spec"]["template"]["spec"]["containers"][0]["envFrom"] = []
    with pytest.raises(ValueError, match="OIDC"):
        validate(resources)


def test_release_manifest_binds_commit_config_and_every_container() -> None:
    rendered = yaml.safe_dump_all(bundle())
    inventory = release_inventory(rendered, "lexagent")
    assert len(inventory["images"]) == 10
    assert any("/init/init" in key for key in inventory["images"])
    manifest = {"schema_version": 1, "commit_sha": COMMIT, **inventory}
    validate_release_manifest(rendered, "lexagent", manifest, COMMIT)
    for mutation in ("commit_sha", "namespace", "rendered_sha256", "images"):
        changed = deepcopy(manifest)
        if mutation == "images":
            changed[mutation].pop(next(iter(changed[mutation])))
        else:
            changed[mutation] = "wrong"
        with pytest.raises(ValueError, match="release manifest"):
            validate_release_manifest(rendered, "lexagent", changed, COMMIT)
    changed_render = deepcopy(bundle())
    changed_render.append({"kind": "ConfigMap", "metadata": {"name": "extra", "namespace": "lexagent"}, "data": {"policy": "changed"}})
    with pytest.raises(ValueError, match="rendered_sha256"):
        validate_release_manifest(yaml.safe_dump_all(changed_render), "lexagent", manifest, COMMIT)


@pytest.mark.parametrize("mutation", ["missing", "extra", "tag", "zero", "namespace", "init_tag"])
def test_unsafe_bundle_is_rejected(mutation: str) -> None:
    resources = deepcopy(bundle())
    if mutation == "missing":
        resources = [item for item in resources if not (item["kind"] == "Job" and item["metadata"]["name"] == "platform-schema-migrate")]
    elif mutation == "extra":
        resources.append(deepcopy(next(item for item in resources if item["kind"] == "Job")))
        resources[-1]["metadata"]["name"] = "unexpected-job"
    elif mutation == "tag":
        resources[2]["spec"]["template"]["spec"]["containers"][0]["image"] = "registry.test/app:latest"
    elif mutation == "zero":
        resources[2]["spec"]["template"]["spec"]["containers"][0]["image"] = "registry.test/app@sha256:" + "0" * 64
    elif mutation == "namespace":
        resources[2]["metadata"]["namespace"] = "other"
    else:
        resources[2]["spec"]["template"]["spec"]["initContainers"][0]["image"] = "registry.test/init:latest"
    with pytest.raises(ValueError):
        validate(resources)


def test_missing_network_policy_is_rejected_before_release() -> None:
    for name in ("platform-migration-traffic", "frontend-platform-traffic"):
        resources = [item for item in bundle() if item["metadata"]["name"] != name]
        with pytest.raises(ValueError, match="required network policies"):
            validate(resources)


def test_extra_allow_all_network_policy_is_rejected_before_release() -> None:
    resources = bundle()
    resources.append({
        "kind": "NetworkPolicy", "metadata": {"name": "allow-all", "namespace": "lexagent"},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                 "ingress": [{}], "egress": [{}]},
    })
    with pytest.raises(ValueError, match="unreviewed network policies"):
        validate(resources)


@pytest.mark.parametrize("mutation", ["deny_selector", "deny_egress", "job_selector", "job_ingress", "job_port", "job_anywhere", "job_no_ports", "job_wrong_dns", "job_mysql_port"])
def test_weakened_job_isolation_is_rejected(mutation: str) -> None:
    resources = bundle()
    policies = {item["metadata"]["name"]: item["spec"] for item in resources if item["kind"] == "NetworkPolicy"}
    if mutation == "deny_selector":
        policies["default-deny"]["podSelector"] = {"matchLabels": {"app": "platform-app"}}
    elif mutation == "deny_egress":
        policies["default-deny"]["egress"] = [{}]
    elif mutation == "job_selector":
        policies["platform-migration-traffic"]["podSelector"] = {}
    elif mutation == "job_ingress":
        policies["platform-migration-traffic"]["ingress"] = [{"from": [{}]}]
    elif mutation == "job_port":
        policies["platform-migration-traffic"]["egress"][0]["ports"].append({"protocol": "TCP", "port": 443})
    elif mutation == "job_mysql_port":
        policies["platform-migration-traffic"]["egress"][0]["ports"] = [{"protocol": "TCP", "port": 3306}]
    elif mutation == "job_no_ports":
        policies["platform-migration-traffic"]["egress"].append({"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "database"}}}]})
    elif mutation == "job_wrong_dns":
        policies["platform-migration-traffic"]["egress"][1]["to"] = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "default"}}}]
    else:
        policies["platform-migration-traffic"]["egress"][0]["to"] = [{"ipBlock": {"cidr": "0.0.0.0/0"}}]
    with pytest.raises(ValueError, match="network policy"):
        validate(resources)


@pytest.mark.parametrize("name", ["frontend-platform-traffic", "platform-app-traffic", "metric-runner-isolation", "oauth2-proxy-traffic", "example-agents-traffic"])
def test_runtime_policy_must_select_intended_pods(name: str) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["metadata"]["name"] == name)
    policy["spec"]["podSelector"] = {}
    with pytest.raises(ValueError, match="network policy"):
        validate(resources)


@pytest.mark.parametrize("mutation", ["egress", "ingress"])
def test_metric_runner_policy_cannot_be_opened(mutation: str) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["metadata"]["name"] == "metric-runner-isolation")
    if mutation == "egress":
        policy["spec"]["egress"] = [{"ports": [{"protocol": "TCP", "port": 443}]}]
    else:
        policy["spec"]["ingress"] = [{"from": [{}], "ports": [{"protocol": "TCP", "port": 8085}]}]
    with pytest.raises(ValueError, match="Metric Runner network policy"):
        validate(resources)


@pytest.mark.parametrize("mutation", ["missing", "unrestricted", "wide", "reserved", "documentation", "wrong_protocol", "extra_port"])
def test_external_https_requires_scoped_gateway(mutation: str) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["metadata"]["name"] == "platform-app-traffic")
    rule = policy["spec"]["egress"][0]
    if mutation == "missing":
        policy["spec"]["egress"] = []
    elif mutation == "unrestricted":
        rule.pop("to")
    elif mutation == "wide":
        rule["to"][0]["ipBlock"]["cidr"] = "10.0.0.0/8"
    elif mutation == "reserved":
        rule["to"][0]["ipBlock"]["cidr"] = "127.0.0.1/32"
    elif mutation == "documentation":
        rule["to"][0]["ipBlock"]["cidr"] = "192.0.2.10/32"
    elif mutation == "wrong_protocol":
        rule["ports"][0]["protocol"] = "UDP"
    else:
        rule["ports"].append({"protocol": "TCP", "port": 8443})
    with pytest.raises(ValueError, match="egress"):
        validate(resources)


@pytest.mark.parametrize("cidr", ["10.20.30.11/32", "fd00:1234::11/128"])
def test_frontend_oidc_step_up_accepts_fixed_https_gateway(cidr: str) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["metadata"]["name"] == "frontend-platform-traffic")
    policy["spec"]["egress"][-1]["to"][0]["ipBlock"]["cidr"] = cidr
    assert validate(resources)


@pytest.mark.parametrize("mutation", [
    "missing", "missing_ports", "missing_target", "wide", "invalid", "documentation",
    "ipv6_wide", "namespace", "extra_peer", "except", "wrong_protocol", "extra_port",
    "port_range", "extra_field", "duplicate_internal", "duplicate_dns",
])
def test_frontend_oidc_step_up_rejects_unrestricted_egress(mutation: str) -> None:
    resources = bundle()
    policy = next(item for item in resources if item["metadata"]["name"] == "frontend-platform-traffic")
    egress = policy["spec"]["egress"]
    rule = egress[-1]
    if mutation == "missing":
        egress.pop()
    elif mutation == "missing_ports":
        rule.pop("ports")
    elif mutation == "missing_target":
        rule.pop("to")
    elif mutation in {"wide", "invalid", "documentation", "ipv6_wide"}:
        rule["to"][0]["ipBlock"]["cidr"] = {
            "wide": "10.0.0.0/8", "invalid": "not-a-cidr", "documentation": "192.0.2.10/32",
            "ipv6_wide": "fd00::/32",
        }[mutation]
    elif mutation == "namespace":
        rule["to"] = [{"namespaceSelector": {}}]
    elif mutation == "extra_peer":
        rule["to"].append({})
    elif mutation == "except":
        rule["to"][0]["ipBlock"]["except"] = ["10.20.30.10/32"]
    elif mutation == "wrong_protocol":
        rule["ports"][0]["protocol"] = "UDP"
    elif mutation == "extra_port":
        rule["ports"].append({"protocol": "TCP", "port": 8443})
    elif mutation == "port_range":
        rule["ports"][0]["endPort"] = 8443
    elif mutation == "extra_field":
        rule["extra"] = True
    elif mutation == "duplicate_internal":
        egress.append(deepcopy(egress[0]))
    else:
        egress.append(deepcopy(egress[2]))
    with pytest.raises(ValueError, match="egress|OIDC"):
        validate(resources)


@pytest.mark.parametrize("broad_frontend", [False, True])
def test_rendered_external_overlay_preserves_oidc_preflight_boundary(broad_frontend: bool) -> None:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        pytest.skip("kubectl kustomize required for actual overlay rendering")
    root = Path(__file__).resolve().parents[2]
    rendered = subprocess.run(
        [kubectl, "kustomize", str(root / "deploy/k8s/overlays/external-egress-example")],
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
    ).stdout
    # Complete the public example's explicit deployment placeholders without
    # changing the rendered selectors, ports, client references or Ingress.
    for placeholder, cidr in {
        "REPLACE_WITH_APPROVED_POSTGRES_CIDR": "10.20.30.9/32",
        "REPLACE_WITH_APPROVED_IDP_GATEWAY_CIDR": "10.20.30.11/32",
        "REPLACE_WITH_APPROVED_MODEL_OTLP_GATEWAY_CIDR": "10.20.30.12/32",
    }.items():
        rendered = rendered.replace(placeholder, cidr)
    resources = list(yaml.safe_load_all(rendered))
    for item in resources:
        if item["kind"] in {"Deployment", "Job"}:
            pod = item["spec"]["template"]["spec"]
            for container in pod.get("initContainers", []) + pod["containers"]:
                container["image"] = f"registry.test/{container['name']}@sha256:{DIGEST}"
    if broad_frontend:
        policy = next(item for item in resources if item["metadata"]["name"] == "frontend-platform-traffic")
        policy["spec"]["egress"][-1]["to"][0]["ipBlock"]["cidr"] = "10.0.0.0/8"
        with pytest.raises(ValueError, match="gateway CIDR"):
            validate(resources)
    else:
        assert validate(resources)


def test_secret_references_include_explicit_keys_and_mounted_secrets() -> None:
    resources = bundle()
    pod = resources[2]["spec"]["template"]["spec"]
    pod["containers"][0]["env"] = [{
        "name": "CHECKPOINT_DSN",
        "valueFrom": {"secretKeyRef": {"name": "checkpoint-secret", "key": "CHECKPOINT_DSN"}},
    }]
    pod["containers"][0]["envFrom"] = [{"secretRef": {"name": "runtime-secret"}}]
    pod["volumes"] = [{"name": "provider", "secret": {"secretName": "provider-secret"}}]
    pod["imagePullSecrets"] = [{"name": "registry-secret"}]
    resources.append({"kind": "Ingress", "metadata": {"name": "web", "namespace": "lexagent"},
                      "spec": {"tls": [{"hosts": ["agent.example.test"], "secretName": "tls-secret"}]}})
    assert required_secret_keys(yaml.safe_dump_all(resources)) == {
        "checkpoint-secret": ["CHECKPOINT_DSN"],
        "provider-secret": [],
        "registry-secret": [],
        "runtime-secret": [],
        "lexagent-oidc-secret": ["issuer_url"],
        "tls-secret": ["tls.crt", "tls.key"],
    }


def test_secret_key_reference_without_key_is_rejected() -> None:
    resources = bundle()
    resources[2]["spec"]["template"]["spec"]["containers"][0]["env"] = [{
        "name": "CHECKPOINT_DSN", "valueFrom": {"secretKeyRef": {"name": "checkpoint-secret"}},
    }]
    with pytest.raises(ValueError, match="without a key"):
        required_secret_keys(yaml.safe_dump_all(resources))


def test_cli_reports_required_production_secret_keys(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(yaml.safe_dump_all(bundle())))
    monkeypatch.setattr(sys, "argv", ["validator", "--namespace", "lexagent"])
    assert main() == 0
    reported = json.loads(capsys.readouterr().out)
    assert "DB_DSN" in reported["secret_keys"]["lexagent-production-secret"]
    assert "CHECKPOINT_DSN" in reported["secret_keys"]["lexagent-agent-secret"]
    assert "context-public.b64" in reported["secret_keys"]["agent-platform-context-public-key"]
