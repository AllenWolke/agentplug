"""Keep CI coverage and report uploads aligned with the publishable source tree."""

from pathlib import Path, PurePosixPath
import re
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[2]


def workflows():
    return [yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
            for path in (ROOT / ".github/workflows").glob("*.yml")]


def test_every_published_go_module_is_race_tested():
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    ).decode("utf-8").split("\0")
    modules = {PurePosixPath(name).parent.as_posix() for name in files if name.endswith("/go.mod")}
    quality = next(workflow for workflow in workflows() if workflow["name"] == "agentplug-quality")
    selected = quality["jobs"]["platform-go"]["strategy"]["matrix"]["module"]
    assert set(selected) == modules
    assert len(selected) == len(set(selected))


def test_sdk_template_sync_is_required_before_live_template_conformance():
    quality = next(workflow for workflow in workflows() if workflow["name"] == "agentplug-quality")
    steps = quality["jobs"]["quality-policy"]["steps"]
    sync = next(step for step in steps if step.get("run") == "python scripts/sync_public_sdks.py --check")
    conformance = next(step for step in steps if step.get("run") == "python scripts/run_agent_create_timing.py")
    assert steps.index(sync) < steps.index(conformance)
    assert sync.get("continue-on-error", "false") == "false"


def test_published_go_images_use_the_same_patch_as_ci():
    definitions = workflows()
    versions = {step["with"]["go-version"] for workflow in definitions
                for job in workflow["jobs"].values() for step in job.get("steps", [])
                if step.get("uses", "").startswith("actions/setup-go@")}
    assert len(versions) == 1
    expected = next(iter(versions))
    assert re.fullmatch(r"\d+\.\d+\.\d+", expected)
    supply = next(workflow for workflow in definitions if workflow["name"] == "supply-chain")
    checked = 0
    for image in supply["jobs"]["image-provenance"]["strategy"]["matrix"]["include"]:
        dockerfile = (ROOT / image["dockerfile"]).read_text(encoding="utf-8")
        for version in re.findall(r"^FROM\s+.*?golang:([0-9.]+)", dockerfile, flags=re.MULTILINE):
            checked += 1
            assert version == expected, image["name"]
    assert checked >= 6


def test_hidden_report_uploads_explicitly_include_only_report_files():
    count = 0
    for workflow in workflows():
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if not step.get("uses", "").startswith("actions/upload-artifact@"):
                    continue
                settings = step.get("with", {})
                paths = settings.get("path", "").splitlines()
                hidden = [path for path in paths if any(part.startswith(".") for part in PurePosixPath(path).parts)]
                if not hidden:
                    continue
                count += 1
                assert settings.get("include-hidden-files") == "true", settings.get("name")
                # Enabling hidden uploads must never publish an entire scratch
                # directory, which may also hold generated test credentials.
                assert all(PurePosixPath(path).suffix in (".json", ".txt", ".log") for path in hidden)
    assert count >= 3
