"""Public docs cannot depend on retained local history or escaped paths."""
from pathlib import Path
import subprocess

from scripts.check_markdown_links import inspect_links, publication_paths
from scripts.check_publication import audit


def test_existing_ignored_history_is_not_a_public_link_target(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".gitignore").write_text("docs/新增需求/\n", encoding="utf-8")
    private = tmp_path / "docs/新增需求/history.md"
    private.parent.mkdir(parents=True)
    private.write_text("local acceptance history", encoding="utf-8")
    (tmp_path / "README.md").write_text("[history](docs/新增需求/history.md)", encoding="utf-8")
    paths = publication_paths(tmp_path)
    assert private.relative_to(tmp_path).as_posix() not in paths
    checked, failures = inspect_links(tmp_path, paths)
    assert checked == 1 and len(failures) == 1 and "non-public" in failures[0]


def test_force_tracking_ignored_history_does_not_bypass_publication(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".gitignore").write_text("docs/新增需求/\n", encoding="utf-8")
    private = tmp_path / "docs/新增需求/history.md"
    private.parent.mkdir(parents=True)
    private.write_text("synthetic history", encoding="utf-8")
    subprocess.run(["git", "add", "-f", "docs/新增需求/history.md"], cwd=tmp_path,
                   check=True, capture_output=True)
    paths = publication_paths(tmp_path)
    assert "docs/新增需求/history.md" in paths
    _, failures = audit(tmp_path, paths)
    assert any("docs/新增需求/history.md:" in failure for failure in failures)


def test_relative_public_links_and_quoted_space_paths(tmp_path: Path):
    guide = tmp_path / "docs/My Guide.md"
    guide.parent.mkdir()
    guide.write_text("guide", encoding="utf-8")
    (tmp_path / "README.md").write_text("[guide](<docs/My Guide.md>)", encoding="utf-8")
    checked, failures = inspect_links(tmp_path, ["README.md", "docs/My Guide.md"])
    assert checked == 1 and not failures


def test_existing_outside_file_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "private.md").write_text("private", encoding="utf-8")
    (root / "README.md").write_text("[outside](../private.md)", encoding="utf-8")
    _, failures = inspect_links(root, ["README.md"])
    assert len(failures) == 1


def test_missing_candidate_source_never_silently_passes(tmp_path: Path):
    _, failures = inspect_links(tmp_path, ["missing.md"])
    assert failures and "unreadable" in failures[0]
