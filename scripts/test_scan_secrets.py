from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("scan_secrets.py")
SPEC = importlib.util.spec_from_file_location("scan_secrets", MODULE_PATH)
assert SPEC and SPEC.loader
scan_secrets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan_secrets)


class SecretScannerFailClosedTest(unittest.TestCase):
    def test_config_build_cache_exclusion_is_exact(self) -> None:
        self.assertIn(".tmp-config-gocache", scan_secrets.SKIP_DIRECTORIES)
        for source_directory in (".tmp-config", ".tmp-config-gocache-source", "config"):
            self.assertNotIn(source_directory, scan_secrets.SKIP_DIRECTORIES)
            self.assertFalse(source_directory.startswith(scan_secrets.SKIP_DIRECTORY_PREFIXES))

    def test_generated_go_build_cache_prefix_is_excluded(self) -> None:
        self.assertTrue(
            any(".gocache-backend".startswith(prefix) for prefix in scan_secrets.SKIP_DIRECTORY_PREFIXES)
        )

    def test_go_module_cache_prefix_is_excluded(self) -> None:
        self.assertTrue(
            any(
                ".tmp-go-modcache".startswith(prefix)
                for prefix in scan_secrets.SKIP_DIRECTORY_PREFIXES
            )
        )

    def test_audit_gocache_prefix_is_excluded(self) -> None:
        self.assertTrue(
            any(".audit-gocache".startswith(prefix) for prefix in scan_secrets.SKIP_DIRECTORY_PREFIXES)
        )

    def test_module_local_build_cache_prefix_is_excluded(self) -> None:
        self.assertTrue(
            any(
                ".tmp-go-build-cache-cancel".startswith(prefix)
                for prefix in scan_secrets.SKIP_DIRECTORY_PREFIXES
            )
        )

    def test_unreadable_file_is_an_explicit_scan_error(self) -> None:
        candidate = scan_secrets.ROOT / "cannot-read.go"
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            findings, errors = scan_secrets.scan(candidate)
        self.assertEqual(findings, [])
        self.assertTrue(errors)
        self.assertIn("cannot-read.go", errors[0])

    def test_walk_error_is_collected(self) -> None:
        def broken_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError(13, "denied", "blocked-dir"))
            return iter(())

        with patch.object(scan_secrets.os, "walk", side_effect=broken_walk):
            files, errors = scan_secrets.iter_files()
        self.assertEqual(files, [])
        self.assertTrue(errors)
        self.assertIn("blocked-dir", errors[0])


class UnifiedGitIgnoreScopeTest(unittest.TestCase):
    def test_private_directory_requires_empty_git_candidate_set(self) -> None:
        for candidate_output, expected in [(b"", True), (b".local-secrets/forced.json\x00", False)]:
            with self.subTest(candidate_output=candidate_output):
                completed = type("Result", (), {"returncode": 0, "stdout": candidate_output})()
                with patch.object(scan_secrets, "is_git_ignored", return_value=True), patch.object(scan_secrets.subprocess, "run", return_value=completed):
                    self.assertEqual(scan_secrets.private_directory_outside_publication(".local-secrets"), expected)

    def test_private_directory_git_failure_does_not_hide_files(self) -> None:
        with patch.object(scan_secrets, "is_git_ignored", return_value=True), patch.object(scan_secrets.subprocess, "run", side_effect=FileNotFoundError("git")):
            self.assertFalse(scan_secrets.private_directory_outside_publication(".local-secrets"))
        with patch.object(scan_secrets, "is_git_ignored", return_value=False):
            self.assertFalse(scan_secrets.private_directory_outside_publication(".local-secrets"))

    def test_private_directory_names_are_exact(self) -> None:
        self.assertIn(".local-secrets", scan_secrets.PRIVATE_DIRECTORIES)
        self.assertNotIn(".local-secrets-source", scan_secrets.PRIVATE_DIRECTORIES)

    def test_environment_example_is_scanned_for_real_provider_tokens(self) -> None:
        token = "ghp_" + "abcdef0123456789" * 3
        candidate = scan_secrets.ROOT / ".env.example"
        with patch.object(Path, "read_text", return_value="GITHUB_TOKEN=" + token):
            findings, errors = scan_secrets.scan(candidate)
        self.assertEqual(errors, [])
        self.assertTrue(any("GitHub token" in message for _, message in findings))

    def test_git_ignored_runtime_env_is_skipped(self) -> None:
        completed = type("Result", (), {"returncode": 0})()
        with patch.object(scan_secrets.subprocess, "run", return_value=completed) as run:
            self.assertTrue(scan_secrets.is_git_ignored(".env"))
        self.assertEqual(run.call_args.args[0][:2], ["git", "check-ignore"])

    def test_untracked_but_not_ignored_env_is_reported(self) -> None:
        completed = type("Result", (), {"returncode": 1})()
        with patch.object(scan_secrets.subprocess, "run", return_value=completed):
            self.assertFalse(scan_secrets.is_git_ignored("committed.env"))

    def test_missing_git_fails_closed(self) -> None:
        with patch.object(
            scan_secrets.subprocess, "run", side_effect=FileNotFoundError("git")
        ):
            self.assertFalse(scan_secrets.is_git_ignored(".env"))

    def test_iter_files_skips_git_ignored_env_and_keeps_others(self) -> None:
        def fake_walk(*args, **kwargs):
            yield str(scan_secrets.ROOT), [], [".env", ".env.e2e-local", "app.go"]

        def fake_ignored(relative: str) -> bool:
            return relative in {".env", ".env.e2e-local"}

        class _Stat:
            st_size = 8

        with patch.object(scan_secrets.os, "walk", side_effect=fake_walk), patch.object(
            scan_secrets, "is_git_ignored", side_effect=fake_ignored
        ), patch.object(Path, "stat", return_value=_Stat()):
            files, errors = scan_secrets.iter_files()
        self.assertEqual(errors, [])
        names = sorted(path.name for path in files)
        self.assertEqual(names, ["app.go"])

    def test_tracked_env_file_still_fails(self) -> None:
        candidate = scan_secrets.ROOT / ".env"
        with patch.object(Path, "read_text", return_value="DB_PASSWORD=ok\n"):
            findings, errors = scan_secrets.scan(candidate)
        self.assertEqual(errors, [])
        self.assertTrue(findings)
        self.assertIn("tracked or copied environment file", findings[0][1])


if __name__ == "__main__":
    unittest.main()
