#!/usr/bin/env python3
"""Remove only individually reviewed, unchanged CodeQL results from an upload copy.

The raw SARIF is never modified. Unknown results, changed flows and changed guard
files remain findings. This module has no network calls or third-party dependencies.
"""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".github/codeql/reviewed-false-positives.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def relative_path(value: str) -> str:
    """Accept literal repository paths, never wildcard or external paths."""
    if not isinstance(value, str) or not value or any(c in value for c in "\\:*?[]\x00"):
        raise ValueError("expected a literal repository-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("path must stay inside the repository")
    return path.as_posix()


def artifact_uri(artifact: dict, run: dict) -> str:
    """Resolve table indices without depending on their SARIF numbering."""
    uri = artifact.get("uri")
    base = artifact.get("uriBaseId")
    if uri is None:
        index = artifact.get("index")
        artifacts = run.get("artifacts", [])
        if type(index) is not int or not 0 <= index < len(artifacts):
            raise ValueError("unresolved SARIF artifact")
        table_location = artifacts[index]["location"]
        uri = table_location["uri"]
        base = base or table_location.get("uriBaseId")
    # Unknown base IDs and absolute URIs must not qualify for an exception.
    if base not in (None, "%SRCROOT%"):
        raise ValueError("unknown SARIF source root")
    if urlsplit(uri).scheme or urlsplit(uri).netloc:
        raise ValueError("external SARIF artifact")
    return relative_path(unquote(uri))


def normalize(value, run: dict):
    if isinstance(value, list):
        return [normalize(item, run) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "artifactLocation":
                result[key] = {"uri": artifact_uri(item, run)}
            elif key == "taxa":
                # Renumbering is transport metadata; source/sink roles are not.
                result[key] = [normalize({k: v for k, v in taxon.items()
                                          if k not in ("index", "toolComponent")}, run)
                               for taxon in item]
            else:
                result[key] = normalize(item, run)
        return result
    return value


def fingerprint(result: dict, run: dict) -> str:
    reviewed = {key: result[key] for key in (
        "ruleId", "message", "locations", "relatedLocations", "codeFlows", "level", "properties"
    ) if key in result}
    encoded = json.dumps(normalize(reviewed, run), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def referenced_files(result: dict, run: dict) -> set[str]:
    files = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "artifactLocation":
                    files.add(artifact_uri(item, run))
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit({key: result[key] for key in ("locations", "relatedLocations", "codeFlows") if key in result})
    return files


def source_hash(root: Path, relative: str) -> str:
    root = root.resolve()
    target = root / relative_path(relative)
    # Do not follow links: replacing a reviewed guard with a link invalidates it.
    for parent in [target, *target.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("reviewed source must not be a symbolic link")
    if not target.resolve().is_relative_to(root):
        raise ValueError("reviewed source escaped the repository")
    # Git's LF/CRLF checkout conversion must not invalidate identical source.
    raw = target.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_manifest(manifest: dict) -> list[dict]:
    if set(manifest) != {"schema_version", "reviewed_on", "documentation", "exceptions"}:
        raise ValueError("unexpected review manifest fields")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported review manifest version")
    relative_path(manifest["documentation"])
    entries = manifest["exceptions"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("explicit reviewed exceptions are required")
    seen = set()
    seen_targets = set()
    fields = {"id", "rule_id", "path", "region", "result_sha256", "source_sha256", "reason", "tests"}
    for entry in entries:
        if set(entry) != fields or not entry["id"] or entry["id"] in seen:
            raise ValueError("invalid or duplicate reviewed exception")
        seen.add(entry["id"])
        if not re.fullmatch(r"go/[a-z0-9-]+", entry["rule_id"]):
            raise ValueError("exception requires one exact Go rule")
        relative_path(entry["path"])
        region = entry["region"]
        if (not isinstance(region, dict) or not {"startLine", "startColumn"} <= set(region)
                or not set(region) <= {"startLine", "startColumn", "endLine", "endColumn"}
                or any(type(n) is not int or n < 1 for n in region.values())):
            raise ValueError("exception requires an exact positive source region")
        if not SHA256.fullmatch(entry["result_sha256"]):
            raise ValueError("invalid reviewed result fingerprint")
        target = (entry["rule_id"], entry["path"], json.dumps(region, sort_keys=True), entry["result_sha256"])
        if target in seen_targets:
            raise ValueError("duplicate reviewed target")
        seen_targets.add(target)
        sources = entry["source_sha256"]
        if not isinstance(sources, dict) or entry["path"] not in sources:
            raise ValueError("reviewed primary source hash is required")
        for path, digest in sources.items():
            relative_path(path)
            if not SHA256.fullmatch(digest):
                raise ValueError("invalid reviewed guard hash")
        if not entry["reason"].strip() or not entry["tests"] or not all(entry["tests"]):
            raise ValueError("review reason and regression evidence are required")
    return entries


def filter_sarif(sarif: dict, manifest: dict, root: Path) -> tuple[dict, dict]:
    entries = validate_manifest(manifest)
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list) or not sarif["runs"]:
        raise ValueError("expected nonempty SARIF 2.1.0 runs")
    output = copy.deepcopy(sarif)
    review = {"input_results": 0, "retained_results": 0, "excluded_results": 0, "exceptions": []}
    active = {}
    for entry in entries:
        changed = []
        for path, digest in entry["source_sha256"].items():
            try:
                matches = source_hash(root, path) == digest
            except (OSError, ValueError, UnicodeError):
                matches = False
            if not matches:
                changed.append(path)
        state = {"id": entry["id"], "reason": entry["reason"], "changed_sources": changed,
                 "status": "invalidated" if changed else "not_observed", "matches": 0}
        review["exceptions"].append(state)
        if not changed:
            active[entry["id"]] = (entry, state)

    candidates = {}
    for run_index, run in enumerate(sarif["runs"]):
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError("SARIF run has no results array; analysis is not an empty successful scan")
        review["input_results"] += len(results)
        if run.get("tool", {}).get("driver", {}).get("name") != "CodeQL":
            continue
        for result_index, result in enumerate(results):
            for entry, state in active.values():
                if result.get("ruleId") != entry["rule_id"]:
                    continue
                try:
                    locations = result["locations"]
                    physical = locations[0]["physicalLocation"]
                    matches = (len(locations) == 1
                               and artifact_uri(physical["artifactLocation"], run) == entry["path"]
                               and physical["region"] == entry["region"]
                               and fingerprint(result, run) == entry["result_sha256"]
                               and referenced_files(result, run) <= set(entry["source_sha256"]))
                except (KeyError, IndexError, TypeError, ValueError):
                    matches = False
                if matches:
                    candidates[(run_index, result_index)] = entry["id"]
    counts = Counter(candidates.values())
    for entry, state in active.values():
        state["matches"] = counts[entry["id"]]
        if counts[entry["id"]] == 1:
            state["status"] = "excluded_reviewed_false_positive"
        elif counts[entry["id"]] > 1:
            state["status"] = "ambiguous_retained"
    for run_index, run in enumerate(output["runs"]):
        run["results"] = [result for result_index, result in enumerate(run["results"])
                          if counts[candidates.get((run_index, result_index))] != 1]
        review["retained_results"] += len(run["results"])
    review["excluded_results"] = review["input_results"] - review["retained_results"]
    return output, review


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="original go.sarif (never overwritten)")
    parser.add_argument("--output", type=Path, required=True, help="separate upload SARIF")
    parser.add_argument("--summary", type=Path, required=True, help="review receipt JSON")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--repo", type=Path, default=ROOT)
    args = parser.parse_args()
    paths = [args.input.resolve(), args.output.resolve(), args.summary.resolve(), args.manifest.resolve()]
    if len(set(paths)) != len(paths):
        parser.error("input, output, summary and manifest must be separate files")
    try:
        original = args.input.read_bytes()
        manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
        sarif, receipt = filter_sarif(json.loads(original.decode("utf-8-sig")), manifest, args.repo)
        filtered = (json.dumps(sarif, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        receipt["original_sha256"] = hashlib.sha256(original).hexdigest()
        receipt["upload_sha256"] = hashlib.sha256(filtered).hexdigest()
        for path in (args.output, args.summary):
            path.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(filtered)
        args.summary.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, ensure_ascii=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"CodeQL review failed; do not upload a partial result: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
