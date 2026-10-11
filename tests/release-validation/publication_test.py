import importlib.util
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("publication", ROOT / "scripts/check_publication.py")
PUBLICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLICATION)


def baseline(root):
    files = ["LICENSE", "THIRD_PARTY_NOTICES.md", "README.md", ".env.example", "compose.yaml"]
    for name in files:
        (root / name).write_text("example")
    return files


def test_source_target_package_is_preserved_and_maven_output_rejected(tmp_path):
    files = baseline(tmp_path)
    source = tmp_path / "adapters/legacy-http/internal/target/target.go"
    source.parent.mkdir(parents=True)
    source.write_text("package target")
    module = tmp_path / "sdk/java/sdk"
    module.mkdir(parents=True)
    (module / "pom.xml").write_text("<project/>")
    generated = module / "target/maven-status/inputFiles.lst"
    generated.parent.mkdir(parents=True)
    generated.write_text("local path")
    entries, failures = PUBLICATION.audit(tmp_path, [*files, source.relative_to(tmp_path).as_posix(),
                                                   generated.relative_to(tmp_path).as_posix()])
    assert source.relative_to(tmp_path).as_posix() in [entry["path"] for entry in entries]
    assert len(failures) == 1 and "Maven build output" in failures[0]


def test_tracked_environment_is_audited_even_if_ignored(tmp_path):
    files = baseline(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("LOCAL_TEST_VALUE=example\n")
    subprocess.run(["git", "add", "-f", ".env"], cwd=tmp_path, check=True, capture_output=True)
    paths = PUBLICATION.candidates(tmp_path)
    assert ".env" in paths and ".env.example" in paths
    _, failures = PUBLICATION.audit(tmp_path, paths)
    assert any(".env: runtime environment file" in failure for failure in failures)


def test_private_and_generated_files_cannot_publish(tmp_path):
    files = baseline(tmp_path)
    dangerous = [".local-secrets/token", ".claude/settings.local.json", "nested/.trae/mcp.json", ".codex/config.toml", ".cursor/settings.json", ".windsurf/settings.json", ".gemini/settings.json", ".tools/private.json", ".vscode/settings.json", ".idea/workspace.xml", "sample.key", "client.pem", "client.p12", "client.pfx", "client.jks", "client.keystore", "client.secret", "browser.har", "library.jar", "exports/business.pgdump", "exports/business.dump", "exports/business.backup", "runtime/data.sqlite3", "runtime/data.db-wal", "runtime/data.sqlite-journal", "runtime/data.sqlite3-shm", "secrets/token", "credentials/account.json", "backups/business.sql", "desktop.ini", "nested/Thumbs.db", "nested/.DS_Store", ".tmp/a", "artifacts/pprof/raw", "cli/agentctl/out/result"]
    for name in dangerous:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("example")
    _, failures = PUBLICATION.audit(tmp_path, [*files, *dangerous])
    assert len(failures) == len(dangerous)


def test_gitignore_blocks_private_artifacts_and_preserves_public_examples(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
    private = [".env", "nested/.env.production", ".local-secrets/account.json",
               ".codex/config.toml", "nested/.cursor/settings.json", ".windsurf/settings.json",
               ".gemini/settings.json", ".tools/state.json", "private.key", "private.pem",
               "client.p12", "client.pfx", "client.jks", "client.keystore", "provider.secret",
               "browser.har", "secrets/account.json", "credentials/account.json",
               "backups/company.sql", "company.pgdump", "company.dump", "company.backup",
               "company.sql.gz", "runtime/data.sqlite3", "runtime/data.db-wal",
               "runtime/data.sqlite-journal", "runtime/data.sqlite3-shm", "desktop.ini",
               "nested/Thumbs.db", "nested/.DS_Store", "docs/新增需求/账号密码.md"]
    public = [".env.example", "deploy/local/platform.env.example",
              "deploy/k8s/production/secret.example.yaml", "platform/migrations/001.sql",
              "adapters/legacy-http/internal/target/target.go", "adapters/process/config/example.env",
              "docs/developer/zh/README.md", "skills/agentplug-business-agent/SKILL.md"]
    for relative in private + public:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic", encoding="utf-8")
    result = subprocess.run(["git", "check-ignore", "-z", "--stdin"], cwd=tmp_path,
                            input=("\0".join(private + public) + "\0").encode("utf-8"),
                            capture_output=True, check=True)
    ignored = {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}
    assert ignored == set(private)
    paths = PUBLICATION.candidates(tmp_path)
    assert not set(private).intersection(paths)
    assert set(public).issubset(paths)

    # Ignore rules alone cannot remove deliberately staged credentials. The
    # publication gate must still refuse them before a commit or upload.
    forced = ["provider.secret", ".codex/config.toml", "runtime/data.db-wal"]
    subprocess.run(["git", "add", "-f", "--", *forced], cwd=tmp_path,
                   capture_output=True, check=True)
    paths = PUBLICATION.candidates(tmp_path)
    assert set(forced).issubset(paths)
    _, failures = PUBLICATION.audit(tmp_path, paths)
    assert all(any(failure.startswith(relative + ":") for failure in failures) for relative in forced)


def test_missing_files_and_path_escape_fail_closed(tmp_path):
    files = baseline(tmp_path)
    _, failures = PUBLICATION.audit(tmp_path, [*files, "missing.go", "../outside.go"])
    assert len(failures) == 2
    assert any("invalid repository path" in failure for failure in failures)
    _, required_failures = PUBLICATION.audit(tmp_path, ["README.md"])
    assert any("LICENSE" in failure for failure in required_failures)


def test_manifest_digest_records_actual_source_changes(tmp_path):
    files = baseline(tmp_path)
    entries, failures = PUBLICATION.audit(tmp_path, files)
    assert not failures
    before = next(entry["sha256"] for entry in entries if entry["path"] == "README.md")
    (tmp_path / "README.md").write_text("changed")
    entries, failures = PUBLICATION.audit(tmp_path, files)
    assert not failures
    assert before != next(entry["sha256"] for entry in entries if entry["path"] == "README.md")


def test_personal_materials_are_rejected_without_losing_engineering_docs_or_test_assets(tmp_path):
    files = baseline(tmp_path)
    private = ['docs/八股文背诵/notes.md', 'docs/面试题/interview.docx',
               'docs/新增需求/用户权限设计/history.md', 'docs/面试冲刺/company.md', '面试冲刺手册/resume.md', 'docs/1、4小时速通Agent面试.docx']
    public = ['docs/开发者指南/architecture.md', 'tests/fixtures/synthetic.txt']
    for name in private + public:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic')
    entries, failures = PUBLICATION.audit(tmp_path, files + private + public)
    assert len(failures) == len(private)
    assert all('outside source release' in failure for failure in failures)
    assert set(public).issubset({entry['path'] for entry in entries})
