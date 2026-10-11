"""Validate the complete rendered production bundle before any kubectl apply."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys

import yaml


EXPECTED_DEPLOYMENTS = {
    "frontend", "metric-runner", "oauth2-proxy", "platform-app",
}
EXPECTED_JOBS = {"platform-schema-migrate"}
REQUIRED_NETWORK_POLICIES = {
    "default-deny", "platform-migration-traffic",
    "frontend-platform-traffic", "platform-app-traffic", "metric-runner-isolation",
    "example-agents-traffic", "oauth2-proxy-traffic",
}
JOB_POLICY_SELECTORS = {
    "platform-migration-traffic": "platform-schema-migrate",
}
RUNTIME_POLICY_SELECTORS = {
    "frontend-platform-traffic": "frontend",
    "platform-app-traffic": "platform-app",
    "metric-runner-isolation": "metric-runner",
    "oauth2-proxy-traffic": "oauth2-proxy",
}
EXTERNAL_HTTPS_POLICIES = {
    "frontend-platform-traffic", "platform-app-traffic", "oauth2-proxy-traffic",
}
ALLOWED_KINDS = {
    "Namespace", "ConfigMap", "NetworkPolicy", "ServiceAccount",
    "Service", "Job", "Deployment", "Ingress",
}
IMAGE_PATTERN = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SECRET_NAME_PATTERN = re.compile(r"^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
EXPECTED_SECRET_KEYS = {
    "lexagent-production-secret": {
        "DB_DSN", "INTERNAL_TOKEN", "BROWSER_GATEWAY_TOKEN", "INTERNAL_SIGNING_SECRET", "KNOWLEDGE_DATABASE_DSN",
        "PLATFORM_CONTEXT_PRIVATE_KEY", "PLATFORM_CONTEXT_PUBLIC_KEY",
        "METRIC_RUNNER_TOKEN",
    },
    "lexagent-agent-secret": {"CHECKPOINT_DSN", "INTERNAL_TOKEN", "INTERNAL_SIGNING_SECRET"},
    "agent-platform-context-public-key": {"context-public.b64"},
}


def selects_app(policy: object, app: str) -> bool:
    if not isinstance(policy, dict):
        return False
    selector = policy.get("podSelector")
    if not isinstance(selector, dict) or set(selector) != {"matchLabels"}:
        return False
    labels = selector["matchLabels"]
    return (isinstance(labels, dict) and labels.get("app") == app
            and all(key in {"app", "app.kubernetes.io/part-of"} for key in labels)
            and labels.get("app.kubernetes.io/part-of", "agentplug") == "agentplug")


def validate_oidc_boundary(documents: list[dict], policies: dict[str, dict], namespace: str) -> None:
    by_key = {(item["kind"], item["metadata"]["name"]): item for item in documents}
    try:
        config = by_key[("ConfigMap", "lexagent-production-config")]["data"]
        frontend = by_key[("Deployment", "frontend")]["spec"]["template"]["spec"]["containers"][0]
        proxy = by_key[("Deployment", "oauth2-proxy")]["spec"]["template"]["spec"]["containers"][0]
        ingress = by_key[("Ingress", "lexagent")]["metadata"]["annotations"]
        oauth_ingress = by_key[("Ingress", "lexagent-oauth2")]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("OIDC release boundary lacks a required configuration or Ingress") from exc
    if not isinstance(config, dict) or any(config.get(key) != value for key, value in {
        "APP_ENV": "production", "FRONTEND_AUTH_MODE": "oidc", "OIDC_PROXY_TRUSTED": "true",
        "OIDC_PROXY_AUTH_URL": "http://oauth2-proxy:4180/oauth2/auth",
    }.items()):
        raise ValueError("OIDC frontend configuration does not use the verified proxy session")
    issuer_ref = {"secretKeyRef": {"name": "lexagent-oidc-secret", "key": "issuer_url"}}
    frontend_env = {item.get("name"): item for item in frontend.get("env", []) if isinstance(item, dict)}
    proxy_env = {item.get("name"): item for item in proxy.get("env", []) if isinstance(item, dict)}
    if (frontend.get("envFrom") != [{"configMapRef": {"name": "lexagent-production-config"}}]
            or any(name in frontend_env for name in ("APP_ENV", "FRONTEND_AUTH_MODE", "OIDC_PROXY_TRUSTED", "OIDC_PROXY_AUTH_URL"))
            or frontend_env.get("OIDC_ISSUER_URL", {}).get("valueFrom") != issuer_ref
            or proxy_env.get("OAUTH2_PROXY_OIDC_ISSUER_URL", {}).get("valueFrom") != issuer_ref):
        raise ValueError("OIDC frontend and proxy must read the same issuer Secret")
    for key, secret_key in {"OIDC_STEP_UP_CLIENT_ID": "client_id", "OIDC_STEP_UP_CLIENT_SECRET": "client_secret", "OIDC_STEP_UP_REDIRECT_URL": "step_up_redirect_url"}.items():
        reference = {"secretKeyRef": {"name": "lexagent-oidc-secret", "key": secret_key}}
        if frontend_env.get(key, {}).get("valueFrom") != reference:
            raise ValueError("OIDC fresh authentication must use the verified client's credentials and registered callback")
    args = proxy.get("args", [])
    if not isinstance(args, list) or not {"--provider=oidc", "--set-xauthrequest=true", "--upstream=static://202"}.issubset(args):
        raise ValueError("OIDC proxy must verify sessions and return the user header")
    if (not isinstance(ingress, dict)
            or ingress.get("nginx.ingress.kubernetes.io/auth-url") != f"http://oauth2-proxy.{namespace}.svc.cluster.local/oauth2/auth"
            or "nginx.ingress.kubernetes.io/auth-response-headers" in ingress
            or "nginx.ingress.kubernetes.io/auth-url" in oauth_ingress.get("metadata", {}).get("annotations", {})):
        raise ValueError("OIDC Ingress auth request must not forward browser identity headers")
    def scoped_pod_rule(rule: object, direction: str, app: str, port: int) -> bool:
        if not isinstance(rule, dict) or set(rule) != {direction, "ports"} or rule["ports"] != [{"protocol": "TCP", "port": port}]:
            return False
        peers = rule[direction]
        return (isinstance(peers, list) and len(peers) == 1 and isinstance(peers[0], dict)
                and set(peers[0]) == {"podSelector"} and selects_app({"podSelector": peers[0]["podSelector"]}, app))

    ingress_from_controller = {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}],
                               "ports": [{"protocol": "TCP", "port": 4180}]}
    dns_egress = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                  "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}
    frontend_egress = policies["frontend-platform-traffic"].get("egress", [])
    proxy_ingress = policies["oauth2-proxy-traffic"].get("ingress", [])
    if (not isinstance(frontend_egress, list) or len(frontend_egress) < 4
            or sum(scoped_pod_rule(rule, "to", "platform-app", 8080) for rule in frontend_egress) != 1
            or sum(scoped_pod_rule(rule, "to", "oauth2-proxy", 4180) for rule in frontend_egress) != 1
            or frontend_egress.count(dns_egress) != 1
            or not all(scoped_pod_rule(rule, "to", "platform-app", 8080)
                       or scoped_pod_rule(rule, "to", "oauth2-proxy", 4180)
                       or rule == dns_egress
                       or (isinstance(rule, dict) and set(rule) == {"to", "ports"}
                           and rule["ports"] == [{"protocol": "TCP", "port": 443}])
                       for rule in frontend_egress)
            or not isinstance(proxy_ingress, list) or len(proxy_ingress) != 2
            or not any(scoped_pod_rule(rule, "from", "frontend", 4180) for rule in proxy_ingress)
            or ingress_from_controller not in proxy_ingress
            or not all(scoped_pod_rule(rule, "from", "frontend", 4180)
                       or rule == ingress_from_controller for rule in proxy_ingress)):
        raise ValueError("OIDC proxy TCP/4180 must be scoped to Frontend and Ingress; Frontend also requires scoped IdP HTTPS egress")


def validate_bundle(rendered: str, namespace: str) -> list[str]:
    documents = list(yaml.safe_load_all(rendered))
    if not documents or any(not isinstance(item, dict) for item in documents):
        raise ValueError("release bundle contains an empty or invalid resource")
    resources: set[tuple[str, str]] = set()
    deployments: set[str] = set()
    jobs: set[str] = set()
    images: set[str] = set()
    for item in documents:
        kind = item.get("kind")
        metadata = item.get("metadata")
        if kind not in ALLOWED_KINDS or not isinstance(metadata, dict):
            raise ValueError("release bundle contains an unsupported resource kind")
        name = metadata.get("name")
        if not isinstance(name, str) or not SECRET_NAME_PATTERN.fullmatch(name):
            raise ValueError("release resource has no name")
        key = (kind, name)
        if key in resources:
            raise ValueError(f"duplicate release resource: {kind}/{name}")
        resources.add(key)
        if kind == "Namespace":
            if name != namespace:
                raise ValueError("release Namespace does not match the requested namespace")
        elif metadata.get("namespace") != namespace:
            raise ValueError(f"release resource has a wrong namespace: {kind}/{name}")
        if kind not in {"Deployment", "Job"}:
            continue
        (deployments if kind == "Deployment" else jobs).add(name)
        try:
            pod = item["spec"]["template"]["spec"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"missing pod template: {kind}/{name}") from exc
        containers = pod.get("containers")
        if not isinstance(containers, list) or not containers:
            raise ValueError(f"missing containers: {kind}/{name}")
        for container in pod.get("initContainers", []) + containers:
            image = container.get("image") if isinstance(container, dict) else None
            if not isinstance(image, str) or not IMAGE_PATTERN.fullmatch(image):
                raise ValueError(f"image is not pinned to a SHA256 digest: {kind}/{name}")
            if any(marker in image.lower() for marker in ("example.com", ".invalid", "replace")):
                raise ValueError(f"placeholder image remains: {kind}/{name}")
            if image.endswith("0" * 64):
                raise ValueError(f"zero digest remains: {kind}/{name}")
            images.add(image)
    if ("Namespace", namespace) not in resources:
        raise ValueError("release Namespace is missing")
    if deployments != EXPECTED_DEPLOYMENTS or jobs != EXPECTED_JOBS:
        raise ValueError(
            f"release workloads differ from approved topology: "
            f"deployments={sorted(deployments)}, jobs={sorted(jobs)}"
        )
    actual_policies = {
        name for kind, name in resources if kind == "NetworkPolicy"
    }
    missing_policies = REQUIRED_NETWORK_POLICIES - actual_policies
    if missing_policies:
        raise ValueError(f"release bundle lacks required network policies: {sorted(missing_policies)}")
    extra_policies = actual_policies - REQUIRED_NETWORK_POLICIES
    if extra_policies:
        raise ValueError(f"release bundle has unreviewed network policies: {sorted(extra_policies)}")
    policies = {
        item["metadata"]["name"]: item.get("spec")
        for item in documents if item["kind"] == "NetworkPolicy"
    }
    deny = policies["default-deny"]
    if (not isinstance(deny, dict) or deny.get("podSelector") != {}
            or set(deny.get("policyTypes", [])) != {"Ingress", "Egress"}
            or deny.get("ingress") or deny.get("egress")):
        raise ValueError("default-deny network policy must isolate every Pod in both directions")
    for name, app in JOB_POLICY_SELECTORS.items():
        policy = policies[name]
        if (not isinstance(policy, dict)
                or not selects_app(policy, app)
                or set(policy.get("policyTypes", [])) != {"Ingress", "Egress"}
                or policy.get("ingress") != []):
            raise ValueError(f"job network policy is not isolated: {name}")
        egress = policy.get("egress")
        if not isinstance(egress, list) or not egress:
            raise ValueError(f"job network policy lacks scoped egress: {name}")
        observed_groups: set[str] = set()
        for rule in egress:
            if not isinstance(rule, dict) or not isinstance(rule.get("to"), list) or not rule["to"]:
                raise ValueError(f"job network policy has unrestricted destination: {name}")
            rule_ports = rule.get("ports")
            if not isinstance(rule_ports, list) or not rule_ports or any(not isinstance(port, dict) for port in rule_ports):
                raise ValueError(f"job network policy has unrestricted ports: {name}")
            ports = {(port.get("protocol"), port.get("port")) for port in rule_ports}
            if ports == {("TCP", 5432)}:
                group = "database"
            elif ports == {("TCP", 53), ("UDP", 53)}:
                group = "dns"
            else:
                raise ValueError(f"job network policy permits unexpected ports: {name}")
            for destination in rule["to"]:
                if not isinstance(destination, dict):
                    raise ValueError(f"job network policy has unrestricted destination: {name}")
                expected_namespace = "database" if group == "database" else "kube-system"
                if destination == {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": expected_namespace}}}:
                    continue
                ip_block = destination.get("ipBlock")
                if group == "database" and set(destination) == {"ipBlock"} and isinstance(ip_block, dict) and set(ip_block) == {"cidr"}:
                    try:
                        network = ipaddress.ip_network(ip_block["cidr"], strict=True)
                    except (ValueError, TypeError):
                        pass
                    else:
                        if network.prefixlen > 0:
                            continue
                raise ValueError(f"job network policy has unrestricted destination: {name}")
            observed_groups.add(group)
        if observed_groups != {"database", "dns"}:
            raise ValueError(f"job network policy lacks database or DNS egress: {name}")
    for name, app in RUNTIME_POLICY_SELECTORS.items():
        policy = policies[name]
        if (not selects_app(policy, app)
                or set(policy.get("policyTypes", [])) != {"Ingress", "Egress"}):
            raise ValueError(f"runtime network policy selects the wrong Pods: {name}")
    validate_oidc_boundary(documents, policies, namespace)
    agents = policies["example-agents-traffic"]
    agent_selector = agents.get("podSelector") if isinstance(agents, dict) else None
    if (not isinstance(agent_selector, dict)
            or agent_selector != {"matchExpressions": [{
                "key": "app", "operator": "In",
                "values": ["example-go", "example-python", "example-java"],
            }]}
            or set(agents.get("policyTypes", [])) != {"Ingress", "Egress"}):
        raise ValueError("Agent network policy selects the wrong Pods")
    agent_egress = agents.get("egress")
    if not isinstance(agent_egress, list) or not agent_egress:
        raise ValueError("Agent egress must use Platform capabilities and DNS")
    groups = set()
    for rule in agent_egress:
        if not isinstance(rule, dict):
            raise ValueError("Agent egress must use Platform capabilities and DNS")
        ports = rule.get("ports")
        if (not isinstance(ports, list) or not ports
                or any(not isinstance(port, dict) or set(port) != {"protocol", "port"} for port in ports)):
            raise ValueError("Agent egress has unrestricted ports")
        observed = {(port["protocol"], port["port"]) for port in ports}
        if observed and observed <= {("TCP", 8080), ("TCP", 8081)}:
            destinations = rule.get("to")
            if not isinstance(destinations, list) or not destinations:
                raise ValueError("Agent egress must target Platform")
            for peer in destinations:
                if peer not in (
                    {"podSelector": {"matchLabels": {"app": "platform-app"}}},
                    {"podSelector": {"matchLabels": {"app": "platform-app", "app.kubernetes.io/part-of": "agentplug"}}},
                ):
                    raise ValueError("Agent egress must target Platform")
            groups.add("platform")
        elif observed == {("TCP", 53), ("UDP", 53)}:
            if rule.get("to") != [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}]:
                raise ValueError("Agent DNS egress must target kube-system")
            groups.add("dns")
        else:
            raise ValueError("Agent egress must use Platform capabilities and DNS")
    if groups != {"platform", "dns"}:
        raise ValueError("Agent egress must use Platform capabilities and DNS")
    runner = policies["metric-runner-isolation"]
    allowed_runner_ingress = [{
        "from": [{"podSelector": {"matchLabels": {"app": "platform-app"}}}],
        "ports": [{"protocol": "TCP", "port": 8085}],
    }], [{
        "from": [{"podSelector": {"matchLabels": {
            "app": "platform-app", "app.kubernetes.io/part-of": "agentplug",
        }}}],
        "ports": [{"protocol": "TCP", "port": 8085}],
    }]
    if runner.get("egress") or runner.get("ingress") not in allowed_runner_ingress:
        raise ValueError("Metric Runner network policy must deny egress and accept only Platform")
    for name in (*RUNTIME_POLICY_SELECTORS, "example-agents-traffic"):
        for rule in policies[name].get("egress", []):
            if (not isinstance(rule, dict) or not isinstance(rule.get("to"), list)
                    or not rule["to"] or any(not isinstance(peer, dict) or not peer for peer in rule["to"])):
                raise ValueError(f"runtime network policy has unrestricted egress destination: {name}")
    for name in EXTERNAL_HTTPS_POLICIES:
        egress = policies[name].get("egress")
        if not isinstance(egress, list):
            raise ValueError(f"external HTTPS egress requires an approved gateway: {name}")
        https_rules = []
        for rule in egress:
            if not isinstance(rule, dict):
                raise ValueError(f"invalid runtime egress rule: {name}")
            ports = rule.get("ports")
            if not isinstance(ports, list):
                raise ValueError(f"runtime egress rule has unrestricted ports: {name}")
            if any(isinstance(port, dict) and port.get("port") == 443 for port in ports):
                https_rules.append(rule)
        if not https_rules:
            raise ValueError(f"external HTTPS egress requires an approved gateway: {name}")
        for rule in https_rules:
            if set(rule) != {"to", "ports"} or rule.get("ports") != [{"protocol": "TCP", "port": 443}]:
                raise ValueError(f"external HTTPS egress has extra ports: {name}")
            destinations = rule.get("to")
            if not isinstance(destinations, list) or not destinations:
                raise ValueError(f"external HTTPS egress has unrestricted destination: {name}")
            for destination in destinations:
                if not isinstance(destination, dict) or set(destination) != {"ipBlock"}:
                    raise ValueError(f"external HTTPS egress requires a fixed gateway CIDR: {name}")
                block = destination["ipBlock"]
                if not isinstance(block, dict) or set(block) != {"cidr"}:
                    raise ValueError(f"external HTTPS egress has an invalid gateway CIDR: {name}")
                try:
                    network = ipaddress.ip_network(block["cidr"], strict=True)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"external HTTPS egress has an invalid gateway CIDR: {name}") from exc
                minimum_prefix = 24 if network.version == 4 else 64
                if (network.prefixlen < minimum_prefix or network.is_multicast
                        or network.is_loopback or network.is_link_local
                        or any(network.subnet_of(example) for example in DOCUMENTATION_NETWORKS if example.version == network.version)):
                    raise ValueError(f"external HTTPS egress gateway CIDR is too broad or reserved: {name}")
    return sorted(images)


def release_inventory(rendered: str, namespace: str) -> dict[str, object]:
    """Bind every workload container and the complete rendered config to a release."""
    validate_bundle(rendered, namespace)
    documents = list(yaml.safe_load_all(rendered))
    coordinates: dict[str, str] = {}
    for item in documents:
        kind = item["kind"]
        if kind not in {"Deployment", "Job"}:
            continue
        workload = f"{kind}/{item['metadata']['name']}"
        pod = item["spec"]["template"]["spec"]
        for field, prefix in (("initContainers", "init"), ("containers", "container")):
            for container in pod.get(field, []):
                name = container.get("name") if isinstance(container, dict) else None
                if not isinstance(name, str) or not SECRET_NAME_PATTERN.fullmatch(name):
                    raise ValueError(f"invalid container name: {workload}")
                key = f"{workload}/{prefix}/{name}"
                if key in coordinates:
                    raise ValueError(f"duplicate container in release: {key}")
                coordinates[key] = container["image"]
    canonical = json.dumps(documents, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "namespace": namespace,
        "rendered_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "images": dict(sorted(coordinates.items())),
    }


def validate_release_manifest(rendered: str, namespace: str, manifest: object, commit: str) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("release manifest schema_version must be 1")
    if not COMMIT_PATTERN.fullmatch(commit) or manifest.get("commit_sha") != commit:
        raise ValueError("release manifest commit does not match checked-out source")
    expected = release_inventory(rendered, namespace)
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ValueError(f"release manifest {field} does not match rendered bundle")


def required_secret_keys(rendered: str) -> dict[str, list[str]]:
    """Collect Secret references without reading any Secret contents."""
    required: dict[str, set[str]] = {}

    def add(name: object, key: object = None) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("release bundle contains an invalid Secret reference")
        keys = required.setdefault(name, set())
        if key is not None:
            if not isinstance(key, str) or not key:
                raise ValueError(f"release bundle contains an invalid Secret key: {name}")
            keys.add(key)

    def walk(value: object) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for field, child in value.items():
                if field == "secretKeyRef" and isinstance(child, dict):
                    if not child.get("key"):
                        raise ValueError("release bundle contains a Secret key reference without a key")
                    add(child.get("name"), child.get("key"))
                elif field == "secretRef" and isinstance(child, dict):
                    add(child.get("name"))
                elif field == "secretName":
                    add(child)
                    if value.get("hosts") is not None:
                        add(child, "tls.crt")
                        add(child, "tls.key")
                elif field == "imagePullSecrets" and isinstance(child, list):
                    for item in child:
                        add(item.get("name") if isinstance(item, dict) else None)
                walk(child)

    for document in yaml.safe_load_all(rendered):
        walk(document)
    return {name: sorted(keys) for name, keys in sorted(required.items())}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--commit")
    parser.add_argument("--draft-manifest", action="store_true")
    args = parser.parse_args()
    try:
        rendered = sys.stdin.read()
        images = validate_bundle(rendered, args.namespace)
        if args.draft_manifest:
            if not args.commit or not COMMIT_PATTERN.fullmatch(args.commit):
                raise ValueError("draft release manifest requires a full Git commit SHA")
            print(json.dumps({"schema_version": 1, "commit_sha": args.commit,
                              **release_inventory(rendered, args.namespace)},
                             ensure_ascii=False, indent=2))
            return 0
        if bool(args.manifest) != bool(args.commit):
            raise ValueError("release manifest and source commit must be supplied together")
        if args.manifest:
            with open(args.manifest, encoding="utf-8") as source:
                validate_release_manifest(rendered, args.namespace, json.load(source), args.commit)
        secrets = required_secret_keys(rendered)
        for name, keys in EXPECTED_SECRET_KEYS.items():
            secrets[name] = sorted(set(secrets.get(name, [])) | keys)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"production release preflight rejected bundle: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"images": images, "secret_keys": secrets}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
