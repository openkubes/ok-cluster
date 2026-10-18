#!/usr/bin/env python3
"""Hermetic candidate experiment, not a deployed UID/exec security proof.

The only substituted script token is the absolute health executable: a local
fixture records argv instead of contacting Cilium. No kubectl/client/credentials,
image execution, package download or production adapter is used by this suite.
Optional Helm rendering requires an explicitly supplied, digest-verified chart.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
BODY = ROOT / "tests/fixtures/ok147_cilium_uid_guard_candidate.sh"
VALUES = ROOT / "tests/fixtures/ok147_cilium_uid_guard_values.yaml"
UID = "11111111-2222-4333-8444-555555555555"
HEADER = f"ok147-uid-guard-candidate/v1:{UID}\n"


class GuardCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ok147-probe-guard-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.trace = self.base / "health-argv"
        self.fake = self.base / "fixture health"
        # -p also keeps the shell-based fixture independent of BASH_ENV; the
        # real Cilium health executable is not a shell script.
        self.fake.write_text(
            '#!/bin/bash -p\n'
            'printf "%s\\n" "$@" > "$OK147_GUARD_TEST_TRACE"\n'
            'printf \'{"nodes":[]}\\n\'\n'
            'exit "${OK147_GUARD_TEST_EXIT:-0}"\n',
            encoding="utf-8",
        )
        self.fake.chmod(0o700)
        body = BODY.read_text(encoding="utf-8")
        self.assertEqual(body.count("exec /usr/bin/cilium-health"), 1)
        self.body = body.replace(
            "exec /usr/bin/cilium-health", f"exec {shlex.quote(str(self.fake))}"
        )

    def invoke(self, args: list[str], actual: str | None, **extra: str):
        env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "OK147_GUARD_TEST_TRACE": str(self.trace),
            **extra,
        }
        if actual is not None:
            env["OK147_PROBE_POD_UID"] = actual
        return subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-p", "-c", self.body,
             "ok147-uid-guard", *args],
            env=env, capture_output=True, text=True, timeout=5, check=False,
        )

    def assert_no_health(self, result) -> None:
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.trace.exists())

    def test_same_uid_runs_only_fixed_health_action(self) -> None:
        result = self.invoke([UID], UID)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.startswith(HEADER))
        self.assertEqual(json.loads(result.stdout[len(HEADER):]), {"nodes": []})
        self.assertEqual(self.trace.read_text().splitlines(),
                         ["status", "--probe", "--output", "json"])

    def test_replacement_between_external_read_and_exec_blocks_health(self) -> None:
        # API selected UID; actual models the identity in a replacement Pod.
        self.assert_no_health(self.invoke([UID], "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"))

    def test_guard_alone_cannot_authenticate_a_supplied_environment(self) -> None:
        # A fabricated replacement could lie with a literal old UID. The
        # candidate cannot distinguish that from a real fieldRef. This positive
        # counterexample requires a reviewed trusted-template/writer boundary;
        # checking only the original Pod before exec is still insufficient.
        result = self.invoke([UID], UID)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(self.trace.exists())

    def test_missing_or_empty_actual_identity_blocks_health(self) -> None:
        for actual in (None, ""):
            with self.subTest(actual=actual):
                self.assert_no_health(self.invoke([UID], actual))

    def test_missing_or_extra_arguments_block_health(self) -> None:
        for args in ([], [UID, "sh"], [""], [UID, "--output", "json"]):
            with self.subTest(args=args):
                self.assert_no_health(self.invoke(args, UID))

    def test_invalid_equal_identities_cannot_inject_shell_or_header(self) -> None:
        for value in (" ", "x\ny", "x;id", "$(id)", "-uid", "a" * 129):
            with self.subTest(value=value):
                self.assert_no_health(self.invoke([value], value))

    def test_child_exit_42_is_distinguishable_from_guard_rejection(self) -> None:
        result = self.invoke([UID], UID, OK147_GUARD_TEST_EXIT="42")
        self.assertEqual(result.returncode, 42)
        self.assertTrue(result.stdout.startswith(HEADER))
        self.assertTrue(self.trace.exists())
        # A future task adapter must validate framing/identity before applying
        # existing health warmup semantics; exit status alone is ambiguous.

    def test_shell_startup_file_is_not_evaluated(self) -> None:
        startup = self.base / "untrusted startup"
        marker = self.base / "unexpected startup"
        startup.write_text(f"printf injected > {shlex.quote(str(marker))}\n")
        result = self.invoke([UID], UID, BASH_ENV=str(startup), ENV=str(startup))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(HEADER))
        self.assertFalse(marker.exists())

    def test_values_use_fieldref_not_literal_identity(self) -> None:
        values = yaml.safe_load(VALUES.read_text())
        self.assertEqual(values, {"extraEnv": [{
            "name": "OK147_PROBE_POD_UID",
            "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}},
        }]})

    def test_explicit_pinned_chart_preserves_baseline_except_uid_env(self) -> None:
        chart = os.environ.get("OK147_GUARD_TEST_CILIUM_CHART")
        if not chart:
            self.skipTest("explicit pinned local chart not supplied; no download/fallback")
        if not shutil.which("helm"):
            self.fail("explicit chart supplied but helm is unavailable")
        sys.path.insert(0, str(ROOT / "scripts"))
        from prepare_cilium_chart import verify
        verify(Path(chart))

        def render(extra: list[str]):
            result = subprocess.run(
                ["helm", "template", "cilium", chart, "--namespace", "kube-system",
                 "--show-only", "templates/cilium-agent/daemonset.yaml", *extra],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
            self.assertEqual(len(docs), 1)
            return docs[0]

        baseline = render([])
        candidate = render(["--values", str(VALUES)])
        agent = next(c for c in candidate["spec"]["template"]["spec"]["containers"]
                     if c["name"] == "cilium-agent")
        entries = [e for e in agent["env"] if e["name"] == "OK147_PROBE_POD_UID"]
        self.assertEqual(entries, yaml.safe_load(VALUES.read_text())["extraEnv"])
        # extraEnv is also used by existing init/optional containers. Strip
        # just this exact addition everywhere and require all other fields,
        # privileges, mounts, images and service-account routing unchanged.
        pod = candidate["spec"]["template"]["spec"]
        for container in [*pod["containers"], *pod.get("initContainers", [])]:
            if "env" in container:
                container["env"] = [e for e in container["env"]
                                    if e["name"] != "OK147_PROBE_POD_UID"]
        self.assertEqual(candidate, baseline)


if __name__ == "__main__":
    unittest.main(verbosity=2)
