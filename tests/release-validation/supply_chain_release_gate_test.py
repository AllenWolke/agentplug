"""Only a successful quality run for the exact main-branch commit may sign images."""

from pathlib import Path
import re
import subprocess
import sys
import tomllib

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_all_image_operations_use_the_same_normalized_registry_owner() -> None:
    supply = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = supply['jobs']['image-provenance']['steps']
    normalize = next(step for step in steps if step.get('id') == 'registry')
    assert normalize['shell'] == 'bash'
    assert normalize['env']['REGISTRY_OWNER'] == '${{ github.repository_owner }}'
    assert '${REGISTRY_OWNER,,}' in normalize['run']
    prefix = '${{ steps.registry.outputs.prefix }}/agentplug'
    build = next(step for step in steps if step.get('id') == 'build')
    assert steps.index(normalize) < steps.index(build)
    operations = [build['with']['tags']]
    operations += [step['with']['image-ref'] for step in steps if step.get('uses', '').startswith('aquasecurity/trivy-action')]
    operations += [step['with']['image'] for step in steps if step.get('uses') == 'anchore/sbom-action@v0']
    operations += [step['run'] for step in steps if 'cosign ' in step.get('run', '')]
    assert len(operations) == 6  # Both published architectures must be scanned.
    assert all(prefix in operation and 'github.repository_owner' not in operation for operation in operations)


def test_scanner_exceptions_require_exact_path_and_value_and_keep_defaults() -> None:
    config = tomllib.loads((ROOT / '.gitleaks.toml').read_text(encoding='utf-8'))
    assert config['extend'] == {'useDefault': True}
    assert 'allowlist' not in config and 'allowlists' not in config
    assert set(config) == {'title', 'extend', 'rules'}
    for rule in config['rules']:
        assert set(rule) == {'id', 'allowlists'}
        for allowance in rule['allowlists']:
            assert set(allowance) == {'description', 'condition', 'regexTarget', 'paths', 'regexes'}
            assert allowance['condition'] == 'AND'
            assert allowance['regexTarget'] == 'secret'
            assert len(allowance['paths']) == len(allowance['regexes']) == 1
            for expression in allowance['paths'] + allowance['regexes']:
                assert expression.startswith('^') and expression.endswith('$')
                assert '.*' not in expression and '.+' not in expression


def test_history_scan_runs_real_exception_negative_controls() -> None:
    workflow = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = workflow['jobs']['history-secret-scan']['steps']
    control = next(step for step in steps if step.get('run') == 'python scripts/test_gitleaks_allowlists.py')
    assert control.get('continue-on-error', 'false') == 'false'
    scan = next(step for step in steps if '--log-opts=--all' in step.get('run', ''))
    assert steps.index(control) < steps.index(scan)


def test_compose_jobs_use_generated_tokens_instead_of_weak_overrides() -> None:
    quality = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    for name in ('compose-e2e', 'modular-cutover'):
        job = quality['jobs'][name]
        for scope in (quality.get('env', {}), job.get('env', {})):
            assert 'INTERNAL_TOKEN' not in scope
            assert 'INTERNAL_SIGNING_SECRET' not in scope
        actual = next(step for step in job['steps'] if 'bash scripts/platform.sh e2e-modular' in step.get('run', ''))
        assert 'INTERNAL_TOKEN' not in actual.get('env', {})
        assert 'INTERNAL_SIGNING_SECRET' not in actual.get('env', {})


def test_checkpoint_sql_is_required_and_cannot_pass_by_skipping() -> None:
    quality = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    job = quality['jobs']['checkpoint-sql']
    assert not job.get('services'), 'the verifier creates its owned PostgreSQL fixture'
    step = next(step for step in job['steps'] if '--suite checkpoint' in step.get('run', ''))
    assert step['run'] == 'python scripts/verify_public_knowledge_postgres.py --suite checkpoint --sdk-full'
    assert any(step.get('run') == 'docker pull pgvector/pgvector:pg16' for step in job['steps'])
    assert step.get('continue-on-error', 'false') == 'false'
    verifier = (ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8')
    assert "'checkpoint': {'test_checkpoint_postgres_roles_upgrade_and_resume'}" in verifier
    assert 'not receipt["skipped_tests"]' in verifier
    assert "required.issubset(receipt['passed_tests'])" in verifier
    assert 'raise SystemExit(0 if receipt["complete"] else 1)' in verifier
    assert 'checkpoint-sql' in quality['jobs']['compose-e2e']['needs']


def test_first_administrator_sql_is_required_after_actual_migration():
    quality = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    job = quality['jobs']['first-administrator-sql']
    assert not job.get('services'), 'the verifier creates its owned PostgreSQL fixture'
    step = next(step for step in job['steps'] if '--suite administration' in step.get('run', ''))
    assert step['run'].strip().splitlines() == [
        'python scripts/verify_public_knowledge_postgres.py --suite administration',
        'python scripts/verify_public_knowledge_postgres.py --suite administration --local-admin-bootstrap',
    ]
    assert any(step.get('run') == 'docker pull pgvector/pgvector:pg16' for step in job['steps'])
    verifier = (ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8')
    migration = verifier.index("run(['go', 'run', './cmd/migrate']")
    tests = verifier.index('process = subprocess.run(["go", "test"')
    assert migration < tests
    assert "'administration': {'TestFirstAdministratorPostgres'}" in verifier
    assert step.get('continue-on-error', 'false') == 'false'
    assert 'first-administrator-sql' in quality['jobs']['compose-e2e']['needs']


def test_compose_parser_has_its_own_token_without_overriding_runtime_initializer() -> None:
    quality = yaml.load((ROOT / '.github/workflows/three-project-quality.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    job = quality['jobs']['compose-e2e']
    parser = next(step for step in job['steps'] if 'docker compose -f compose.yaml --profile modular config --quiet' in step.get('run', ''))
    assert 'export INTERNAL_TOKEN=' in parser['run']
    assert 'secrets.token_hex(32)' in parser['run']
    assert 'INTERNAL_TOKEN' not in job['env']


def test_public_quality_gate_retains_sql_and_full_chain_requirements() -> None:
    quality = yaml.load((ROOT / ".github/workflows/three-project-quality.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert "regulatory-agent" not in quality["jobs"]
    assert {"identity-sql", "first-administrator-sql", "checkpoint-sql"} <= set(quality["jobs"])
    assert "first-administrator-sql" in quality["jobs"]["compose-e2e"]["needs"]
    assert all(step.get("continue-on-error", "false") == "false"
               for step in quality["jobs"]["compose-e2e"]["steps"])


def test_every_active_production_workload_has_a_supply_chain_owner() -> None:
    production = ROOT / "deploy/k8s/production"
    kustomization = yaml.safe_load((production / "kustomization.yaml").read_text(encoding="utf-8"))
    supply = yaml.load((ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    build_matrix = supply["jobs"]["image-provenance"]["strategy"]["matrix"]["include"]
    built_names = {entry["name"] for entry in build_matrix}
    for entry in build_matrix:
        assert (ROOT / entry["context"]).is_dir(), entry["name"]
        assert (ROOT / entry["dockerfile"]).is_file(), entry["name"]
    external_images = {"oauth2-proxy"}  # Approved mirror/digest and independent signature are required by release preflight.
    active_images: set[str] = set()
    for relative_path in kustomization["resources"]:
        for resource in yaml.safe_load_all((production / relative_path).read_text(encoding="utf-8")):
            if not resource or resource.get("kind") not in {"Deployment", "Job"}:
                continue
            pod_spec = resource["spec"]["template"]["spec"]
            for container in pod_spec.get("initContainers", []) + pod_spec.get("containers", []):
                image = container["image"]
                coordinate = image.split("@", 1)[0].rsplit("/", 1)[-1]
                repository, _, tag = coordinate.partition(":")
                active_images.add(tag if repository == "agentplug" else repository)
    assert active_images, "no active production workload images found"
    assert active_images - built_names == external_images


def test_signed_image_promotion_depends_on_quality_and_scans() -> None:
    supply = yaml.load(
        (ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    quality = yaml.load(
        (ROOT / ".github/workflows/three-project-quality.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert supply["on"]["workflow_run"]["workflows"] == [quality["name"]]
    assert "push" not in supply["on"]
    image_job = supply["jobs"]["image-provenance"]
    assert set(image_job["needs"]) == {"sast-and-secrets", "sbom-and-vulnerability", "history-secret-scan"}
    condition = image_job["if"]
    for requirement in (
        "github.event_name == 'workflow_run'",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        "github.event.workflow_run.head_repository.id == github.event.repository.id",
    ):
        assert requirement in condition
    checkout = next(step for step in image_job["steps"] if step.get("uses") == "actions/checkout@v5")
    assert "workflow_run.head_sha" in checkout["with"]["ref"]
    build = next(step for step in image_job["steps"] if step.get("id") == "build")
    assert "workflow_run.head_sha" in build["with"]["tags"]
    image_sbom = next(
        step for step in image_job["steps"]
        if step.get("uses") == "anchore/sbom-action@v0"
    )
    assert image_sbom["with"]["format"] == "spdx-json"
    assert "steps.build.outputs.digest" in image_sbom["with"]["image"]
    assert image_sbom["with"]["output-file"] == "image-sbom.spdx.json"
    attest = next(step for step in image_job["steps"] if "cosign attest" in step.get("run", ""))
    sign = next(step for step in image_job["steps"] if "cosign sign" in step.get("run", ""))
    assert "-a source_commit=${{ github.event.workflow_run.head_sha }}" in sign["run"]
    assert "--type spdxjson --predicate image-sbom.spdx.json" in attest["run"]
    assert "steps.build.outputs.digest" in attest["run"]
    assert image_job["steps"].index(image_sbom) < image_job["steps"].index(attest)


def test_pull_request_scans_cannot_publish_packages_or_mint_signing_identity() -> None:
    supply = yaml.load(
        (ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert supply["permissions"] == {"contents": "read"}
    for name in ("sast-and-secrets", "sbom-and-vulnerability", "history-secret-scan"):
        permissions = supply["jobs"][name].get("permissions", supply["permissions"])
        assert permissions.get("packages", "none") != "write"
        assert permissions.get("id-token", "none") != "write"
    assert supply["jobs"]["image-provenance"]["permissions"] == {
        "contents": "read", "packages": "write", "id-token": "write",
    }


def test_required_sql_checks_fail_if_tests_are_skipped_or_not_selected() -> None:
    quality = yaml.load(
        (ROOT / ".github/workflows/three-project-quality.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    sql = quality['jobs']['identity-sql']
    command = '\n'.join(step.get('run', '') for step in sql['steps'])
    for suite in ('identity', 'capability', 'conversation'):
        assert 'python scripts/verify_public_knowledge_postgres.py --suite ' + suite in command
    verifier = (ROOT / 'scripts/verify_public_knowledge_postgres.py').read_text(encoding='utf-8')
    for name in (
        'TestSQLOIDCBindingFollowsCurrentIAMState',
        'TestSQLAuthorizationEpochTracksIAMAndRejectsRevocation',
        'TestSQLMemoryExpiryCleanupPreservesConcurrentRefresh',
        'TestSQLConversationExportCompletenessAndRollback',
        'TestSQLRetentionAndLegalHoldSerializeOnSession',
        'TestSQLRetentionSweepLimitSkipsUnexpiredOlderSession',
    ):
        assert "'" + name + "'" in verifier, 'named acceptance must remain mandatory, not merely selected'
    assert 'not receipt["skipped_tests"]' in verifier
    assert "required.issubset(receipt['passed_tests'])" in verifier
    assert 'raise SystemExit(0 if receipt["complete"] else 1)' in verifier


def test_codeql_has_per_language_builds_for_all_active_go_and_java_sources() -> None:
    supply = yaml.load(
        (ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    job = supply["jobs"]["sast-and-secrets"]
    modes = {item["language"]: item["build-mode"] for item in job["strategy"]["matrix"]["include"]}
    assert modes == {"go": "manual", "java-kotlin": "manual", "javascript-typescript": "none", "python": "none"}
    init = next(step for step in job["steps"] if step.get("uses") == "github/codeql-action/init@v4")
    assert init["with"]["languages"] == "${{ matrix.language }}"
    go_build = next(step for step in job["steps"] if step.get("name") == "Trace every active Go module")
    java_build = next(step for step in job["steps"] if step.get("name") == "Trace Java SDK reactor and generated templates")
    for path in ROOT.rglob("go.mod"):
        if any(part.startswith(".") or part in {"node_modules", "target", "out", "venv", "artifacts"} for part in path.relative_to(ROOT).parts):
            continue
        assert path.parent.relative_to(ROOT).as_posix() in go_build["run"]
    # Go's interceptor dispatches on argv[1]; -C before build is not recognized.
    executable_lines = [line.strip() for line in go_build['run'].splitlines() if not line.lstrip().startswith('#')]
    assert not any('go -C ' in line for line in executable_lines)
    assert 'go build ' in go_build['run']
    assert 'cd "$module"' in go_build['run']
    for pom in ("sdk/java/pom.xml", "templates/java-generic/pom.xml", "templates/java-spring-ai/pom.xml"):
        assert pom + " clean test" in java_build["run"]
    analyze = next(step for step in job["steps"] if step.get("uses") == "github/codeql-action/analyze@v4")
    assert job["steps"].index(init) < job["steps"].index(go_build) < job["steps"].index(analyze)
    assert job["steps"].index(init) < job["steps"].index(java_build) < job["steps"].index(analyze)


def test_codeql_reviews_only_go_after_successful_full_analysis_and_preserves_raw_results() -> None:
    supply = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = supply['jobs']['sast-and-secrets']['steps']
    init = next(step for step in steps if step.get('uses') == 'github/codeql-action/init@v4')
    assert init['with']['queries'] == "${{ matrix.language == 'go' && '+security-and-quality' || '' }}"
    assert not any(key in init['with'] for key in ('paths-ignore', 'query-filters', 'disable-default-queries'))
    analyze = next(step for step in steps if step.get('id') == 'codeql')
    assert analyze['with']['upload'] == "${{ matrix.language == 'go' && 'failure-only' || 'always' }}"
    controls = next(step for step in steps if step.get('run') == 'python scripts/test_codeql_false_positives.py')
    process = next(step for step in steps if 'python scripts/filter_codeql_false_positives.py' in step.get('run', ''))
    upload = next(step for step in steps if step.get('uses') == 'github/codeql-action/upload-sarif@v4')
    assert steps.index(analyze) < steps.index(controls) < steps.index(process) < steps.index(upload)
    for step in (controls, process, upload):
        assert step['if'] == "matrix.language == 'go'"  # implicit success(), never always()
        assert step.get('continue-on-error', 'false') == 'false'
    assert '--input "${{ steps.codeql.outputs.sarif-output }}/go.sarif"' in process['run']
    assert '--output "$RUNNER_TEMP/codeql-reviewed/go.sarif"' in process['run']
    assert upload['with']['sarif_file'] == '${{ runner.temp }}/codeql-reviewed/go.sarif'
    assert upload['with']['category'] == '/language:go'
    for step in (analyze, upload):
        assert step['with']['sha'] == '${{ github.event.workflow_run.head_sha || github.sha }}'
        assert step['with']['ref'] == "${{ github.event_name == 'workflow_run' && 'refs/heads/main' || github.ref }}"
    artifact = next(step for step in steps if step.get('uses') == 'actions/upload-artifact@v6')
    assert artifact['if'] == "always() && matrix.language == 'go'"
    for evidence in ('codeql-raw/*.sarif', 'codeql-reviewed/*.sarif', 'codeql-reviewed/review.json'):
        assert evidence in artifact['with']['path']
    assert artifact['with']['retention-days'] == '90'


def test_codeql_exception_security_negative_controls() -> None:
    process = subprocess.run([sys.executable, str(ROOT / 'scripts/test_codeql_false_positives.py')],
                             cwd=ROOT, capture_output=True, text=True, encoding='utf-8', check=False)
    assert process.returncode == 0, process.stdout + process.stderr
    assert 'Ran ' in process.stderr and process.stderr.endswith('OK\n')


def test_history_scanner_supports_workflow_run_and_does_not_need_comment_permissions() -> None:
    supply = yaml.load(
        (ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    job = supply["jobs"]["history-secret-scan"]
    checkout = next(step for step in job["steps"] if step.get("uses") == "actions/checkout@v5")
    assert checkout["with"]["fetch-depth"] == "0"
    assert "workflow_run.head_sha" in checkout["with"]["ref"]
    command = next(step["run"] for step in job["steps"] if "git /repo" in step.get("run", ""))
    for required in ("git /repo", "--log-opts=--all", "--redact", "--network none", "readonly", "safe.directory"):
        assert required in command
    assert all(step.get("uses") != "gitleaks/gitleaks-action@v2" for job in supply["jobs"].values() for step in job["steps"])


def test_every_published_architecture_is_scanned_before_signing() -> None:
    supply = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = supply['jobs']['image-provenance']['steps']
    build = next(step for step in steps if step.get('id') == 'build')
    required = set(build['with']['platforms'].split(','))
    scanned = set()
    for step in steps:
        if not step.get('uses', '').startswith('aquasecurity/trivy-action'):
            continue
        settings = step['with']
        config = yaml.safe_load((ROOT / settings['trivy-config']).read_text(encoding='utf-8'))
        scanned.add(config['image']['platform'])
        assert settings['image-ref'].endswith('@${{ steps.build.outputs.digest }}')
        assert settings['exit-code'] == '1'
        assert step.get('continue-on-error', 'false') == 'false'
        assert steps.index(step) < next(i for i, s in enumerate(steps) if 'cosign sign' in s.get('run', ''))
    assert scanned == required


def test_security_failures_keep_redacted_diagnostics() -> None:
    supply = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    for name in ('sbom-and-vulnerability', 'history-secret-scan', 'image-provenance'):
        steps = supply['jobs'][name]['steps']
        upload = next(step for step in steps if step.get('uses') == 'actions/upload-artifact@v6')
        assert upload['if'] == 'always()'
        assert '.json' in upload['with']['path']
    history = next(step['run'] for step in supply['jobs']['history-secret-scan']['steps'] if 'git /repo' in step.get('run', ''))
    assert '--redact' in history and '--report-format=json' in history
    # Gitleaks creates mode-0600 reports. The upload action must own that file.
    assert '--user "$(id -u):$(id -g)"' in history


def test_image_matrix_supplies_required_base_image_arguments() -> None:
    supply = yaml.load((ROOT / '.github/workflows/supply-chain.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    job = supply['jobs']['image-provenance']
    build = next(step for step in job['steps'] if step.get('id') == 'build')
    assert build['with']['build-args'] == "${{ matrix.build-args || '' }}"
    for entry in job['strategy']['matrix']['include']:
        dockerfile = (ROOT / entry['dockerfile']).read_text(encoding='utf-8')
        arguments = dict(line.split('=', 1) for line in entry.get('build-args', '').splitlines() if '=' in line)
        for required in re.findall(r'^FROM\s+\$\{([A-Z_]+)\}', dockerfile, flags=re.MULTILINE):
            assert re.fullmatch(r'.+@sha256:[a-f0-9]{64}', arguments.get(required, '')), entry['name']
