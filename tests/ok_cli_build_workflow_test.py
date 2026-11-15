#!/usr/bin/env python3
"""OK-228: policy checks for .github/workflows/ok-cli-build.yaml.

Static: dispatch-only trigger from main, least-privilege permissions, SHA-pinned
actions, inputs never interpolated into shell, and attestation only for
approved official builds behind the protected environment. Behavioural: the
workflow's own input validation and environment gate scripts are executed
against accept/refuse matrices. Needs PyYAML; touches no network."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "ok-cli-build.yaml").read_text())
JOBS = WORKFLOW["jobs"]
GATED = "inputs.release && inputs.attest"
ENVIRONMENT = "ok-cli-release-attestation"


def step(job, name_prefix):
    return next(s for s in JOBS[job]["steps"] if s.get("name", "").startswith(name_prefix))


def run_step(script, env, *args):
    return subprocess.run(["bash", "-c", script, "step", *args], capture_output=True, text=True,
                          env={"PATH": os.environ["PATH"], **env})


class WorkflowPolicyTest(unittest.TestCase):
    def test_trigger_and_default_permissions(self):
        self.assertEqual(set(WORKFLOW["on"]), {"workflow_dispatch"}, "only manual dispatch; never pull_request")
        self.assertEqual(WORKFLOW["permissions"], {})
        inputs = WORKFLOW["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual((inputs["release"]["default"], inputs["attest"]["default"]), (False, False))
        self.assertEqual(JOBS["bind"]["if"], "github.ref == 'refs/heads/main'")

    def test_every_job_depends_on_bind(self):
        def needs(job):
            value = JOBS[job].get("needs", [])
            return [value] if isinstance(value, str) else value

        def reaches_bind(job):
            return job == "bind" or any(reaches_bind(parent) for parent in needs(job))

        for job in JOBS:
            self.assertTrue(reaches_bind(job), job)

    def test_least_privilege(self):
        for job, spec in JOBS.items():
            self.assertIn("permissions", spec, f"{job} must declare its permissions")
            write = {k for k, v in spec["permissions"].items() if v == "write"}
            if job == "attest":
                self.assertEqual(write, {"id-token", "attestations"})
            else:
                self.assertEqual(write, set(), f"{job} must not have write permissions")
        self.assertEqual(JOBS["build"]["permissions"], {"contents": "read"})
        self.assertEqual(JOBS["attest-gate"]["permissions"], {"actions": "read"})
        for spec in JOBS.values():
            for s in spec["steps"]:
                if s.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(s["with"]["persist-credentials"], False)

    def test_actions_pinned_and_inputs_never_in_shell(self):
        for job, spec in JOBS.items():
            for s in spec["steps"]:
                if "uses" in s:
                    self.assertRegex(s["uses"], r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", f"{job}: unpinned {s['uses']}")
                if "run" in s:
                    self.assertNotRegex(s["run"], r"\$\{\{\s*(inputs|github\.event)", f"{job}: input interpolated into shell")

    def test_attestation_only_for_approved_official_builds(self):
        for job in ("attest-gate", "attest"):
            self.assertEqual(JOBS[job]["if"], GATED, job)
        attest = JOBS["attest"]
        self.assertEqual(attest["environment"], ENVIRONMENT)
        self.assertEqual(set(attest["needs"]), {"build", "attest-gate"})
        uses = [s.get("uses", "") for s in attest["steps"]]
        self.assertFalse(any(u.startswith("actions/checkout@") for u in uses), "attest must not run repository code")
        self.assertTrue(any(u.startswith("actions/attest@") for u in uses))
        for job in ("bind", "build", "attest-gate"):
            self.assertNotIn("environment", JOBS[job])
            self.assertFalse(any(s.get("uses", "").startswith("actions/attest") for s in JOBS[job]["steps"]), job)

    def test_input_validation_matrix(self):
        script = step("bind", "Validate inputs")["run"]
        commit = "a" * 40
        cases = [
            ("v1.0.1-rc3", "false", "false", True),
            ("v1.0.1", "true", "false", True),
            ("v1.0.1", "true", "true", True),
            ("v1.0.1-rc3", "false", "true", False),   # RC builds can never attest
            ("v1.0.1", "false", "true", False),
            ("v1.0.1", "false", "false", False),      # official version needs release=true
            ("v1.0.1-rc3", "true", "false", False),   # release=true needs an official version
            ("v1.0.1-rc3", "true", "true", False),
        ]
        for version, release, attest, accepted in cases:
            with self.subTest(version=version, release=release, attest=attest):
                result = run_step(script, {"INPUT_VERSION": version, "INPUT_COMMIT": commit,
                                           "INPUT_RELEASE": release, "INPUT_ATTEST": attest})
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if attest == "true" and release == "false":
                    self.assertIn("only allowed for official builds", result.stderr)
        result = run_step(script, {"INPUT_VERSION": "v1.0.1-rc3", "INPUT_COMMIT": "abc",
                                   "INPUT_RELEASE": "false", "INPUT_ATTEST": "false"})
        self.assertNotEqual(result.returncode, 0)

    def test_environment_gate_fails_closed(self):
        script = step("attest-gate", "Require reviewers")["run"]
        protected = {"name": ENVIRONMENT, "protection_rules": [
            {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"login": "maintainer"}}]}],
            "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}
        cases = {
            "protected": (protected, True),
            "no rules": ({**protected, "protection_rules": []}, False),
            "wait timer only": ({**protected, "protection_rules": [{"type": "wait_timer", "wait_timer": 5}]}, False),
            "reviewer rule without reviewers": ({**protected, "protection_rules": [{"type": "required_reviewers", "reviewers": []}]}, False),
            "any branch may deploy": ({**protected, "deployment_branch_policy": None}, False),
            "selected branches": ({**protected, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}, True),
        }
        with tempfile.TemporaryDirectory() as temp:
            for label, (document, accepted) in cases.items():
                with self.subTest(label):
                    Path(temp, "environment.json").write_text(json.dumps(document))
                    result = run_step(script, {"RUNNER_TEMP": temp})
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                    if not accepted:
                        self.assertIn("is not protected", result.stderr)

    def test_build_reuses_make_targets_with_pinned_go(self):
        build = JOBS["build"]
        self.assertEqual({(i["runner"], i["target"]) for i in build["strategy"]["matrix"]["include"]},
                         {("macos-15", "darwin-arm64"), ("macos-15-intel", "darwin-amd64"), ("ubuntu-24.04", "linux-amd64")})
        go = next(s for s in build["steps"] if s.get("uses", "").startswith("actions/setup-go@"))
        self.assertEqual((go["with"]["go-version"], go["with"]["cache"]), ("1.24.13", False))
        accept = step("build", "Source, tests")["run"]
        self.assertIn("make ok-rc-acceptance", accept)
        self.assertIn("make ok-release-acceptance", accept)
        self.assertNotRegex(accept, r"go build|build_release_bundle|git tag|gh release")


if __name__ == "__main__":
    unittest.main(verbosity=2)
