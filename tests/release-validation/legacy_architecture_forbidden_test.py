from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_removed_architecture.py"
SPEC = importlib.util.spec_from_file_location("check_removed_architecture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _write_source(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_clean_repository_passes_strict_gate(tmp_path: Path) -> None:
    _write_source(tmp_path, "go-backend/main.go", 'package main\nconst route = "/api/v2"\n')

    findings, errors = MODULE.scan_repository(tmp_path)

    assert findings == []
    assert errors == []


def test_retired_api_cli_and_skip_only_go_e2e_are_not_active() -> None:
    root = Path(__file__).resolve().parents[2]
    assert not (root / "cli" / "main.go").exists()
    assert not (root / "cli" / "client" / "client.go").exists()
    assert not (root / "cli" / "go.mod").exists()
    assert not list((root / "tests" / "e2e").glob("*.go"))
    assert not (root / "tests" / "e2e" / "go.mod").exists()
    assert not (root / "tests" / "e2e" / "Dockerfile").exists()

    workflow = (root / ".github" / "workflows" / "three-project-quality.yml").read_text(encoding="utf-8")
    windows_gate = (root / "scripts" / "unit.ps1").read_text(encoding="utf-8")
    posix_gate = (root / "scripts" / "unit.sh").read_text(encoding="utf-8")
    module_matrix = workflow.split("module:", 1)[1].splitlines()[0]
    assert "tests/e2e" not in module_matrix
    assert "cli," not in module_matrix
    assert '"cli"' not in windows_gate
    assert '"cli"' not in posix_gate
    assert '"tests\\e2e"' not in windows_gate
    assert '"tests/e2e"' not in posix_gate


def test_every_removed_architecture_marker_is_reported(tmp_path: Path) -> None:
    (tmp_path / "py-ai").mkdir()
    _write_source(
        tmp_path,
        "go-harness/main.go",
        '// AGENT_CAPABILITIES=check,qa\n// /internal/orchestrator/ask\n// /internal/runtime/run\n',
    )

    findings, errors = MODULE.scan_repository(tmp_path)

    assert errors == []
    assert {item.code for item in findings} == {
        "FUSED_RUNTIME_DIRECTORY",
        "COMBINED_CAPABILITY_REGISTRATION",
        "LEGACY_ORCHESTRATOR_ASK",
        "LEGACY_RUNTIME_RUN",
    }


def test_old_migration_exclusion_paths_are_scanned(tmp_path: Path) -> None:
    # These paths were previously exempted during migration. Clean-cut mode
    # must scan them like every other production/test source file.
    _write_source(
        tmp_path,
        "go-backend/internal/orchestrator/adapter.go",
        'package orchestrator\nconst removed = "/internal/orchestrator/ask"\n',
    )

    findings, errors = MODULE.scan_repository(tmp_path)

    assert errors == []
    assert any(
        item.path == "go-backend/internal/orchestrator/adapter.go"
        and item.code == "LEGACY_ORCHESTRATOR_ASK"
        for item in findings
    )


def test_unreadable_or_invalid_source_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "go-backend" / "broken.go"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"\xff\xfe\x00")

    findings, errors = MODULE.scan_repository(tmp_path)

    assert findings == []
    assert errors and "go-backend/broken.go" in errors[0]


def test_allowlist_schema_is_strict(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(json.dumps({"findings": ["A:b:1"]}), encoding="utf-8")
    assert MODULE.load_allowlist(allowlist) == {"A:b:1"}

    allowlist.write_text(json.dumps({"findings": [1]}), encoding="utf-8")
    try:
        MODULE.load_allowlist(allowlist)
    except ValueError:
        pass
    else:
        raise AssertionError("numeric allowlist entry must be rejected")
