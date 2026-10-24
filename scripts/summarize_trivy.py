"""Expose Trivy JSON findings in CI logs and the GitHub step summary."""
from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path


def cell(value: object) -> str:
    return html.escape(" ".join(str(value or "-").split()), quote=False).replace("|", "\\|").replace("`", "'")


def render(label: str, path: Path) -> str:
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("scan report exceeds 32 MiB")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2 or not isinstance(document.get("Results"), list):
        raise ValueError("invalid Trivy JSON report")
    if label.startswith("linux/"):
        metadata = document.get("Metadata", {})
        configuration = metadata.get("ImageConfig", {})
        if configuration.get("os") != "linux" or configuration.get("architecture") != label.split("/", 1)[1]:
            raise ValueError("scan report architecture differs from requested platform")
    findings = []
    for result in document["Results"]:
        if not isinstance(result, dict):
            raise ValueError("invalid scan result")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ValueError("invalid vulnerabilities list")
        for finding in vulnerabilities or []:
            if not isinstance(finding, dict):
                raise ValueError("invalid vulnerability record")
            findings.append(finding)
    lines = [f"### Trivy: {cell(label)}", "", f"Reported vulnerabilities: {len(findings)}.", ""]
    if findings:
        lines.extend(["| Severity | Vulnerability | Package | Installed | Fixed |",
                      "| --- | --- | --- | --- | --- |"])
        for finding in findings:
            lines.append("| " + " | ".join(cell(finding.get(key)) for key in
                         ("Severity", "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion")) + " |")
    else:
        lines.append("No vulnerabilities matched the configured Trivy filters.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", required=True, metavar="LABEL=PATH")
    arguments = parser.parse_args()
    sections, errors = [], 0
    for entry in arguments.report:
        try:
            label, filename = entry.split("=", 1)
            if not label or not filename:
                raise ValueError("report requires LABEL=PATH")
            sections.append(render(label, Path(filename)))
        except (OSError, ValueError, TypeError, AttributeError) as error:
            errors += 1
            # Keep diagnostics bounded and avoid serializing report contents or
            # parser exceptions that may include untrusted package metadata.
            label = entry.split("=", 1)[0]
            sections.append(f"### Trivy: {cell(label)}\n\nReport unavailable or invalid ({type(error).__name__}); inspect the scanner step and uploaded JSON.\n")
    output = "\n".join(sections)
    print(output, end="")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(output)
    # Vulnerability policy remains enforced by the original Trivy exit code.
    # Missing or invalid evidence is a separate failure, never a clean scan.
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
