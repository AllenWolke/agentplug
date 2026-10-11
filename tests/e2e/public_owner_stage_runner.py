"""Bounded resume runner for the already-prepared public replay owner.

This file contains no credentials. It imports the normal public replay
controller and supplies only exact, owner-bound confirmations for the first
post-runtime stages. Every phase retains its own request/receipt journal and
the runner stops on the first exception; it never retries a failed stage.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_examples_replay as replay


PROJECT = "agentplug-test-public-10123fb7fa47"
RUNNER_JOURNAL = "bounded-stage-confirmations.json"
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
MODEL_STAGES = {
    "provider-create", "provider-safety-test", "provider-approve",
    "definition-create", "version-create", "version-approve",
    "price-create", "price-approve", "deployment-create",
}
AGENT_AUTHORS = {
    "example-go-operations": ("go", "demo.go.user", "0.2.3"),
    "example-python-documents": ("python", "demo.python.user", "0.2.2"),
    "example-java-tickets": ("java", "demo.java.user", "0.2.2"),
}
IMAGE_DIGESTS = {
    "example-go-operations": "sha256:e0e3cac91fe21aaaf7d94b4007447c428763cc67ce5172a6a5e75dc489c9f6ce",
    "example-python-documents": "sha256:b1cb208e70d1a726529b2a506e25b12792d4728d857668e611d79d391c7ead0f",
    "example-java-tickets": "sha256:9469b3c554c5ae111b8ab56af884a412ad8accf4d21c973040abd59fb8dd79d6",
}


class OwnerConfirmations:
    """Persist exact approved confirmation phrases in this owner's private state."""

    def __init__(self, project: str, directory: Path):
        if project != PROJECT:
            raise ValueError("bounded runner is pinned to the one already-prepared isolated owner")
        self.project = project
        self.directory = directory.resolve(strict=True)
        self.path = self.directory / RUNNER_JOURNAL
        if self.path.exists():
            replay.bootstrap.verify_private_file(self.path)
            if replay.bootstrap.is_reparse_point(self.path):
                raise RuntimeError("owner confirmation journal must be a regular private file")
            try:
                journal = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                raise RuntimeError("owner confirmation journal is unreadable") from None
        else:
            journal = {"schema": "public-owner-stage-confirmations/v1", "owner_project": project,
                       "confirmations": [], "phases": {}}
        if (not isinstance(journal, dict) or journal.get("schema") != "public-owner-stage-confirmations/v1"
                or journal.get("owner_project") != project or not isinstance(journal.get("confirmations"), list)
                or not isinstance(journal.get("phases"), dict)):
            raise RuntimeError("owner confirmation journal schema or project pin differs")
        self.journal = journal

    def _persist(self) -> None:
        replay.write_json_private(self.path, self.journal)

    def _confirm(self, phase: str, phrase: str, digest: str) -> bool:
        if not SHA256.fullmatch(digest):
            raise RuntimeError("normal phase did not supply a SHA-256 confirmation digest")
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        item = {"phase": phase, "digest": digest, "confirmation": phrase, "confirmed_at": now}
        # The exact phrase is a digest and resource identifier only; secrets,
        # provider URLs and passwords are never accepted by these callbacks.
        if not any(row.get("phase") == phase and row.get("confirmation") == phrase
                   for row in self.journal["confirmations"] if isinstance(row, dict)):
            self.journal["confirmations"].append(item)
        self._persist()
        print(json.dumps({"runner": "owner-bound-confirmation", "phase": phase,
                          "digest": digest, "confirmation": phrase,
                          "credentials_or_provider_urls_printed": False}, ensure_ascii=False))
        return True

    def model_governance(self, project: str, provider_key: str, stage: str, digest: str) -> bool:
        if (project != self.project or provider_key not in {"public-example-chat", "public-example-embedding"}
                or stage not in MODEL_STAGES):
            return False
        phrase = f"{project} model {provider_key} {stage} {digest}"
        return self._confirm("model-governance:" + stage, phrase, digest)

    def phrase(self, phrase: str) -> bool:
        """Confirm only the exact first-batch provider/health/source phrases."""
        project = re.escape(self.project)
        patterns = (
            ("provider-probe", re.compile(rf"{project} provider-probe (chat|embedding) [A-Za-z0-9_.:-]{{1,128}} ([a-f0-9]{{64}})\Z")),
            ("model-health", re.compile(rf"{project} apply model-health [A-Za-z0-9_.:-]{{1,128}} revision:[1-9][0-9]* ([a-f0-9]{{64}})\Z")),
            ("knowledge-source", re.compile(rf"{project} knowledge (go|python|java) source-create ([a-f0-9]{{64}})\Z")),
            ("model-access-policy", re.compile(rf"{project} Model AccessPolicy ([A-Za-z0-9_.:-]{{1,128}}) (create|approve) ([a-f0-9]{{64}})\Z")),
            ("temporary-author-role", re.compile(rf"{project} grant (demo\.(go|python|java)\.user) ([A-Za-z0-9_.:-]{{1,128}}) ([a-f0-9]{{64}})\Z")),
        )
        for phase, pattern in patterns:
            match = pattern.fullmatch(phrase) if isinstance(phrase, str) else None
            if match:
                groups = match.groups()
                if phase == "model-access-policy" and groups[0] not in replay.example_authorization.SUBJECTS:
                    return False
                if phase == "temporary-author-role":
                    _subject, language, binding_id, _digest = groups
                    row = next((agent for agent, (row_language, author, _version) in AGENT_AUTHORS.items()
                                if row_language == language and author == _subject), None)
                    if row is None or binding_id != replay.role_binding_id(self.project, row):
                        return False
                return self._confirm(phase, phrase, groups[-1])
        snapshot = re.fullmatch(rf"{project} publish snapshot (example-(?:go-operations|python-documents|java-tickets))@([A-Za-z0-9_.:-]{{1,128}}) rev([1-9][0-9]*)", phrase) if isinstance(phrase, str) else None
        if snapshot:
            digest = hashlib.sha256(phrase.encode("utf-8")).hexdigest()
            return self._confirm("policy-snapshot", phrase, digest)
        return False

    def start_phase(self, phase: str) -> None:
        prior = self.journal["phases"].get(phase)
        if prior:
            raise RuntimeError("bounded phase already has a runner receipt; inspect live API state before any continuation")
        self.journal["phases"][phase] = {"status": "started", "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        self._persist()

    def finish_phase(self, phase: str) -> None:
        self.journal["phases"][phase] = {"status": "complete", "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        self._persist()

    def fail_phase(self, phase: str, exc: Exception) -> None:
        # Do not copy exception text into console or journal: lower-level HTTP
        # errors can contain provider or infrastructure response details.
        self.journal["phases"][phase] = {"status": "failed", "error_type": type(exc).__name__,
                                         "failed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        self._persist()


def run_release_catalog(project: str, raw_cidrs: list[str]) -> dict:
    project = replay.project_name(project)
    if project != PROJECT:
        raise ValueError("bounded runner is pinned to the already-prepared isolated owner")
    directory, owner, _passwords = replay.read_manifest(project)
    if (owner.get("identity_complete") is not True or owner.get("services_ready") is not True
            or owner.get("runtime_prepared") is not True or owner.get("runtime_process_started") is not True
            or owner.get("model_governance", {}).get("model_deployment_readiness_proven") is not True
            or owner.get("model_governance", {}).get("provider_connectivity_proven") is not True):
        raise RuntimeError("release stages require the verified owner identity, Runtime and both observed Model Deployments")
    replay.bootstrap.parse_agent_cidrs(raw_cidrs)
    replay.verify_example_container_health(project, directory)
    suffix = project.removeprefix("agentplug-test-public-")
    expected_agents = {row[1] for row in replay.bootstrap.MACHINES}
    if set(owner.get("knowledge_replay_journal", {}).get("languages", {})) != {"go", "python", "java"}:
        raise RuntimeError("all three exact published Knowledge source receipts are required before release preparation")
    confirm = OwnerConfirmations(project, directory)
    outcomes = {}

    def run(phase: str, action):
        prior = confirm.journal["phases"].get(phase)
        if prior and prior.get("status") == "complete":
            outcomes[phase] = "already-complete"
            return None
        confirm.start_phase(phase)
        try:
            result = action()
        except Exception as exc:
            confirm.fail_phase(phase, exc)
            raise
        confirm.finish_phase(phase)
        outcomes[phase] = "verified"
        return result

    semantics = {"example-go-operations": "0.2.3", "example-python-documents": "0.2.2",
                 "example-java-tickets": "0.2.2"}
    version_ids = {agent: f"{agent}-v{version.replace('.', '-')}-{suffix}" for agent, version in semantics.items()}
    deployment_ids = {agent: f"replay-deployment-{suffix}-{agent.removeprefix('example-')}"
                      for agent in semantics}
    plans = {}

    def check_release(agent_id: str, plan: dict) -> dict:
        language = AGENT_AUTHORS[agent_id][0]
        machine = next(row for row in replay.bootstrap.MACHINES if row[1] == agent_id)
        if (plan.get("version", {}).get("id") != version_ids[agent_id]
                or plan.get("version", {}).get("semantic_version") != semantics[agent_id]
                or plan.get("version", {}).get("artifact_digest") != IMAGE_DIGESTS[agent_id]
                or plan.get("installation", {}).get("id") != machine[2]
                or plan.get("deployment", {}).get("id") != deployment_ids[agent_id]):
            raise RuntimeError("owner-pinned release plan differs from the exact example image/version/installation recipe")
        return plan

    # Complete all offline release construction first so no author role or
    # Catalog mutation begins until all three exact images and source receipts
    # have produced valid six-policy/Skill bundles.
    for agent_id in sorted(expected_agents):
        language, author, _semantic = AGENT_AUTHORS[agent_id]
        _current_directory, current_owner, _passwords = replay.read_manifest(project)
        pinned = current_owner.get("release_plans", {}).get(agent_id)
        phase = "release-plan:" + agent_id
        if pinned:
            plan = replay.load_release_bundle(directory, Path(pinned["path"]), agent_id)
            plans[agent_id] = check_release(agent_id, plan)
            outcomes[phase] = "already-pinned-and-verified"
            continue

        output = Path(f"release-{language}.json")
        policy_input = Path(f"policy-input-{language}.json")
        orphan = directory / output
        if orphan.exists():
            # A process may have stopped after private file creation but before
            # the owner pin. Do not rebuild or overwrite; validate and pin only
            # the exact recipe if the companion input is also present.
            replay.bootstrap.verify_private_file(orphan)
            if not (directory / policy_input).is_file():
                raise RuntimeError("un-pinned release bundle lacks its policy input; inspect owner-private files before continuing")
            plan = replay.load_release_bundle(directory, output, agent_id)
            check_release(agent_id, plan)
            replay.remember_release_plan(project, directory, plan, output)
            plans[agent_id] = plan
            outcomes[phase] = "reconciled-private-plan"
            continue

        result = run(phase, lambda agent_id=agent_id, author=author, language=language,
                            output=output, policy_input=policy_input: replay.prepare_release_plan(
            project, directory, agent_id, author, IMAGE_DIGESTS[agent_id], version_ids[agent_id],
            next(row[2] for row in replay.bootstrap.MACHINES if row[1] == agent_id),
            deployment_ids[agent_id], 16000, 1600000, True, policy_input, output))
        if result is None:
            raise RuntimeError("release-plan phase was marked complete without a pinned plan")
        plans[agent_id] = check_release(agent_id, result["plan"])

    if set(plans) != expected_agents:
        raise RuntimeError("all three complete release plans must be verified before Catalog submission")

    for agent_id in sorted(expected_agents):
        _language, author, _semantic = AGENT_AUTHORS[agent_id]
        confirm_resource = "grant:" + agent_id + ":" + author
        _current_directory, current_owner, _passwords = replay.read_manifest(project)
        saved_role = current_owner.get("temporary_author_roles", {}).get(agent_id)
        if isinstance(saved_role, dict) and saved_role.get("status") == "active":
            replay.require_temporary_author_role(project, directory, agent_id, author)
            outcomes["author-role:" + agent_id] = "already-active-and-verified"
        else:
            run("author-role:" + agent_id, lambda agent_id=agent_id, author=author,
                confirm_resource=confirm_resource: replay.temporary_author_role_phase(
                    project, directory, agent_id, "system.admin", author, confirm_resource,
                    confirm=confirm.phrase))
        run("catalog-submit:" + agent_id, lambda agent_id=agent_id, author=author: replay.catalog_submit_phase(
            project, directory, plans[agent_id], author, plans[agent_id]["version"]["id"]))

    # Evaluate and approve as the independently authenticated system.admin;
    # the three demo authors remain different identities throughout.
    for agent_id in sorted(expected_agents):
        plan = plans[agent_id]
        version_id = plan["version"]["id"]
        run("catalog-evaluate:" + agent_id, lambda plan=plan, version_id=version_id: replay.catalog_evaluate_phase(
            project, directory, plan, "system.admin", version_id))
        run("catalog-publish:" + agent_id, lambda plan=plan, version_id=version_id: replay.catalog_publish_phase(
            project, directory, plan, "system.admin", version_id))
        installation_id = plan["installation"]["id"]
        deployment_id = plan["deployment"]["id"]
        run("catalog-install:" + agent_id, lambda plan=plan, installation_id=installation_id: replay.catalog_install_phase(
            project, directory, plan, "system.admin", installation_id))
        run("catalog-deploy:" + agent_id, lambda plan=plan, deployment_id=deployment_id: replay.catalog_deploy_phase(
            project, directory, plan, "system.admin", deployment_id))
        run("catalog-observe:" + agent_id, lambda plan=plan, deployment_id=deployment_id: replay.catalog_observe_phase(
            project, directory, plan, "system.admin", deployment_id, include_runtime=True))
        run("catalog-activate:" + agent_id, lambda plan=plan, installation_id=installation_id: replay.catalog_activate_phase(
            project, directory, plan, "system.admin", installation_id))

    _current_directory, current_owner, _passwords = replay.read_manifest(project)
    if current_owner.get("machines_complete") is not True:
        run("machine-identities-and-bindings", lambda: replay.machines_phase(
            project, project, "http://127.0.0.1:" + str(current_owner["ports"]["FRONTEND_HOST_PORT"]), raw_cidrs))
    else:
        outcomes["machine-identities-and-bindings"] = "already-complete"

    run("six-model-access-policies", lambda: replay.model_access_policies_phase(
        project, directory, confirm=confirm.phrase))

    for agent_id in sorted(expected_agents):
        plan = plans[agent_id]
        author = AGENT_AUTHORS[agent_id][1]
        skill = replay.skill_plan(plan)
        skill_target = skill["skill_id"] + "/" + skill["version_id"]
        run("skill-register:" + agent_id, lambda plan=plan, author=author,
            skill_target=skill_target: replay.skill_register_phase(project, directory, plan, author, skill_target))
        run("skill-review:" + agent_id, lambda plan=plan, skill_target=skill_target: replay.skill_review_phase(
            project, directory, plan, "system.admin", skill_target))
        run("skill-publish:" + agent_id, lambda plan=plan, skill_target=skill_target: replay.skill_publish_phase(
            project, directory, plan, "system.admin", skill_target))
        policy_target = agent_id + "@" + plan["version"]["id"]
        run("policy-draft:" + agent_id, lambda plan=plan, author=author, policy_target=policy_target:
            replay.policy_draft_phase(project, directory, plan, author, policy_target, confirm=confirm_for_policy(confirm, project, agent_id, plan)))
        run("policy-publish:" + agent_id, lambda plan=plan, policy_target=policy_target:
            replay.policy_publish_phase(project, directory, plan, "system.admin", policy_target,
                                        confirm=confirm_for_policy(confirm, project, agent_id, plan)))

    return {"project": project, "outcomes": outcomes,
            "next": "run business-roles, prepare and review the exact six-subject Grant plan, then submit and observe Knowledge indexes"}


def confirm_for_policy(journal: OwnerConfirmations, project: str, agent_id: str, plan: dict):
    version_id = plan["version"]["id"]
    target = agent_id + "@" + version_id
    def confirm(phrase: str) -> bool:
        allowed = {"create drafts " + target, "publish six policies " + target}
        if phrase in allowed:
            digest = hashlib.sha256(phrase.encode("utf-8")).hexdigest()
            return journal._confirm("policy-release", phrase, digest)
        snapshot = re.fullmatch(r"publish snapshot " + re.escape(target) + r" rev([0-9]+)", phrase)
        if snapshot:
            digest = hashlib.sha256(phrase.encode("utf-8")).hexdigest()
            return journal._confirm("policy-snapshot", phrase, digest)
        return False
    return confirm


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--confirm-project", required=True)
    parser.add_argument("--agent-cidr", action="append", required=True,
                        help="exact machine source CIDR as MACHINE_ID=NETWORK; repeat once for each machine")
    args = parser.parse_args()
    if args.confirm_project != args.project:
        parser.error("--confirm-project must exactly match the isolated owner")
    try:
        result = run_release_catalog(args.project, args.agent_cidr)
    except Exception as exc:
        print(json.dumps({"result": "stopped_at_first_phase_failure", "project": args.project,
                          "error_type": type(exc).__name__, "exception_details_printed": False}, ensure_ascii=False))
        return 1
    print(json.dumps({"result": "bounded_release_catalog_machine_skill_policy_batch_verified", **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
