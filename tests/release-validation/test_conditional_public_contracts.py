"""Dedicated fixtures must cover the published inventory without using providers."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dedicated_pg", ROOT / "scripts/verify_dedicated_postgres_tests.py")
dedicated_pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dedicated_pg)


def inventory():
    return json.loads((ROOT / "docs/developer/zh/github-actions-verification-20261023.json").read_text(encoding="utf-8"))


def test_public_and_private_inventory_formats_select_the_same_71_cases():
    public = inventory()
    private = {"go_json_summary": {"skipped_tests": public["postgres_full"]["skipped_cases"]}}
    assert dedicated_pg.selected_cases(public) == dedicated_pg.selected_cases(private)
    assert len(dedicated_pg.selected_cases(public)) == 71


def test_missing_startup_fixture_and_duplicate_events_cannot_silently_pass():
    original = inventory()
    missing = copy.deepcopy(original)
    missing["postgres_full"]["skipped_cases"] = [c for c in missing["postgres_full"]["skipped_cases"]
                                                if not c["package"].endswith("/cmd/platform")]
    with pytest.raises(ValueError):
        dedicated_pg.selected_cases(missing)
    duplicate = copy.deepcopy(original)
    duplicate["postgres_full"]["skipped_cases"].append(original["postgres_full"]["skipped_cases"][0])
    with pytest.raises(ValueError):
        dedicated_pg.selected_cases(duplicate)


def test_ci_requires_free_dedicated_fixtures_and_python_server_dependency():
    workflow = yaml.load((ROOT / ".github/workflows/three-project-quality.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["conditional-public-contracts"]
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "[grpc,asgi]" in runs
    assert "verify_dedicated_postgres_tests.py" in runs and "--containerized-go" in runs
    assert "verify_isolated_cache_contracts.py" in runs
    assert "--suite interop --race" in runs
    assert "--evaluation-restart" in runs
    assert "--suite models" not in runs and "--live-models" not in runs
    assert all(step.get("continue-on-error", "false") == "false" for step in job["steps"])
    uploads = [s["with"]["path"] for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert uploads and all(".local-secrets" not in path for path in uploads)
