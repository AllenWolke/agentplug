"""CI must show concrete scan failures without weakening publication gates."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("trivy_summary", ROOT / "scripts/summarize_trivy.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def report(tmp_path, architecture="arm64", findings=None):
    target = tmp_path / "scan.json"
    target.write_text(json.dumps({"SchemaVersion": 2,
        "Metadata": {"ImageConfig": {"os": "linux", "architecture": architecture}},
        "Results": [{"Vulnerabilities": findings or []}]}), encoding="utf-8")
    return target


def test_real_failure_fields_are_visible_and_untrusted_metadata_cannot_inject_log_commands(tmp_path):
    path = report(tmp_path, findings=[{"Severity": "HIGH", "VulnerabilityID": "CVE-2026-112940",
        "PkgName": "filelock\n::error::untrusted|<script>", "InstalledVersion": "3.32.3", "FixedVersion": "4.2.1"}])
    text = summary.render("linux/arm64", path)
    assert "CVE-2026-112940" in text and "3.32.3" in text and "4.2.1" in text
    assert "Reported vulnerabilities: 1" in text
    assert not any(line.startswith("::") for line in text.splitlines())
    assert "<script>" not in text and "untrusted\\|" in text


def test_architecture_mismatch_cannot_be_reported_as_a_clean_scan(tmp_path):
    with pytest.raises(ValueError, match="architecture"):
        summary.render("linux/arm64", report(tmp_path, architecture="amd64"))


def test_clean_report_preserves_trivy_filter_scope(tmp_path):
    text = summary.render("linux/arm64", report(tmp_path))
    assert "Reported vulnerabilities: 0" in text
    assert "configured Trivy filters" in text


def test_missing_report_fails_and_still_renders_the_other_architecture(tmp_path):
    clean = report(tmp_path)
    result = subprocess.run([sys.executable, str(ROOT / "scripts/summarize_trivy.py"),
        "--report", "linux/amd64=" + str(tmp_path / "missing.json"),
        "--report", "linux/arm64=" + str(clean)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Report unavailable or invalid" in result.stdout and "Reported vulnerabilities: 0" in result.stdout


@pytest.mark.parametrize("document", [{}, {"SchemaVersion": 2, "Results": ["invalid"]},
                                    {"SchemaVersion": 2, "Results": [{"Vulnerabilities": 0}]},
                                    {"SchemaVersion": 2, "Results": [{"Vulnerabilities": ["invalid"]}]}])
def test_invalid_report_is_never_clean(tmp_path, document):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        summary.render("source", path)


def test_github_summary_appends_without_erasing_previous_step_output(tmp_path, monkeypatch, capsys):
    path = report(tmp_path)
    step = tmp_path / "summary.md"
    step.write_text("Previous step\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    monkeypatch.setattr(sys, "argv", ["summarize_trivy.py", "--report", "linux/arm64=" + str(path)])
    assert summary.main() == 0
    assert step.read_text(encoding="utf-8") == "Previous step\n" + capsys.readouterr().out


def test_both_architectures_remain_mandatory_before_sbom_and_signing():
    workflow = yaml.load((ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["image-provenance"]["steps"]
    scans = [next(step for step in steps if step.get("id") == name) for name in ("scan-amd64", "scan-arm64")]
    diagnostic = next(step for step in steps if step.get("name") == "Summarize image vulnerabilities")
    sbom = next(step for step in steps if step.get("uses") == "anchore/sbom-action@v0")
    for scan in scans:
        assert scan["with"]["exit-code"] == "1" and scan.get("continue-on-error", "false") == "false"
        assert steps.index(scan) < steps.index(diagnostic) < steps.index(sbom)
        assert f"steps.{scan['id']}.outcome == 'success'" in sbom["if"]
    assert "!cancelled()" in diagnostic["if"] and "success()" in sbom["if"]
    for step in steps[steps.index(sbom):]:
        if "cosign " in step.get("run", ""):
            assert not step.get("if") and step.get("continue-on-error", "false") == "false"
