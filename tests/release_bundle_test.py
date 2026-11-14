#!/usr/bin/env python3
"""OK-228: build the release bundle for this platform, then install it into an
isolated prefix and run it. Read-only: no cluster or global ok is touched."""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import prepare_cilium_chart  # noqa: E402

GOOS = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
GOARCH = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
VERSION = "v0.0.0-bundle-test"
NAME = f"ok-{VERSION}-{GOOS}-{GOARCH}"


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


class ReleaseBundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = Path(tempfile.mkdtemp(prefix="ok-bundle-test-")).resolve()
        cls.commit = git("-C", str(ROOT), "rev-parse", "HEAD")
        command = ["bash", str(ROOT / "scripts" / "build_release_bundle.sh"), "--out", str(cls.temp / "dist"),
                   "--goos", GOOS, "--goarch", GOARCH, "--ok-linux", os.environ["OK_LINUX_PATH"], "--version", VERSION]
        if os.environ.get("CILIUM_CHART") and Path(os.environ["CILIUM_CHART"]).is_file():
            command += ["--chart-source", os.environ["CILIUM_CHART"]]
        build = subprocess.run(command, capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError(build.stdout + build.stderr)
        cls.tarball = cls.temp / "dist" / f"{NAME}.tar.gz"
        # Install as an operator would: verify, extract into an isolated prefix,
        # link the binary from a separate bin directory.
        cls.prefix = cls.temp / "prefix"
        cls.bundle = cls.prefix / "share" / "ok" / NAME
        (cls.prefix / "share" / "ok").mkdir(parents=True)
        subprocess.run(["tar", "-xzf", str(cls.tarball), "-C", str(cls.prefix / "share" / "ok")], check=True)
        (cls.prefix / "bin").mkdir()
        cls.ok = cls.prefix / "bin" / "ok"
        cls.ok.symlink_to(cls.bundle / "ok-cluster" / ".tools" / "bin" / "ok")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def release(self):
        return dict(re.match(r"([^:]+): (\S+)", line).groups()
                    for line in (self.bundle / "release.txt").read_text().splitlines())

    def test_checksum_and_release_record_bind_binary_sources_and_chart(self):
        line = (self.temp / "dist" / f"{NAME}.tar.gz.sha256").read_text().split()
        self.assertEqual(line, [hashlib.sha256(self.tarball.read_bytes()).hexdigest(), f"{NAME}.tar.gz"])
        record = self.release()
        pinned = re.search(r'clusterProvisionReviewedOKLinux\s*= "([0-9a-f]{40})"',
                           (ROOT / "cmd" / "ok" / "cluster_provision.go").read_text()).group(1)
        binary = self.bundle / "ok-cluster" / ".tools" / "bin" / "ok"
        chart = self.bundle / "ok-cluster" / ".tools" / "cilium-1.19.6.tgz"
        self.assertEqual(record["version"], VERSION)
        self.assertEqual(record["platform"], f"{GOOS}/{GOARCH}")
        self.assertEqual(record["ok-cluster commit"], self.commit)
        self.assertEqual(record["ok-linux commit"], pinned)
        self.assertEqual(record["bin/ok sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertEqual(record["cilium-1.19.6.tgz sha256"], prepare_cilium_chart.EXPECTED_SHA256)
        self.assertEqual(hashlib.sha256(chart.read_bytes()).hexdigest(), prepare_cilium_chart.EXPECTED_SHA256)
        for tree, commit in (("ok-cluster", self.commit), ("ok-linux", pinned)):
            self.assertEqual(git("-C", str(self.bundle / tree), "rev-parse", "HEAD"), commit)
            self.assertEqual(git("-C", str(self.bundle / tree), "status", "--porcelain", "--untracked-files=all"), "")
            self.assertEqual(git("-C", str(self.bundle / tree), "remote"), "")

    def test_official_version_requires_its_tag_on_this_commit(self):
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / "build_release_bundle.sh"), "--out", str(self.temp / "official"),
             "--goos", GOOS, "--goarch", GOARCH, "--ok-linux", os.environ["OK_LINUX_PATH"], "--version", "v99.0.0"],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tag v99.0.0 does not point at", result.stderr)
        self.assertFalse((self.temp / "official").exists())

    def test_extracted_binary_runs_and_reports_its_revision(self):
        result = subprocess.run([str(self.ok), "version"], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), f"{VERSION} {self.commit}")

    def destroy_probe(self):
        """ok destroy for an unknown name, through the symlink, on a terminal.
        It locates the bundle, runs the full source-integrity checks, then stops
        because no cluster exists: no cluster access, nothing deleted."""
        home, state = self.temp / "home", self.temp / "state"
        home.mkdir(exist_ok=True)
        management = self.temp / "management.yaml"
        management.write_text("# never read: the probe stops before cluster access\n")
        stubs = self.temp / "stubs"
        stubs.mkdir(exist_ok=True)
        for tool in ("kubectl", "clusterctl", "helm"):
            if not shutil.which(tool):
                (stubs / tool).write_text("#!/bin/sh\nexit 1\n")
                (stubs / tool).chmod(0o755)
        path = ":".join([str(stubs)] + [p for p in os.environ["PATH"].split(":") if os.path.isabs(p)])
        env = {"HOME": str(home), "XDG_STATE_HOME": str(state), "XDG_CONFIG_HOME": str(home / ".config"), "PATH": path}
        master, slave = os.openpty()
        try:
            return subprocess.run([str(self.ok), "destroy", "no-such-cluster", "--management", str(management)],
                                  stdin=slave, capture_output=True, text=True, env=env, timeout=120)
        finally:
            os.close(slave)
            os.close(master)

    def test_installed_bundle_passes_the_cli_source_checks(self):
        result = self.destroy_probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no cluster provisioned by ok up named no-such-cluster in "
                      f"{self.temp / 'state' / 'ok' / 'clusters'} or {self.bundle / 'ok-cluster'}", result.stderr)

    def test_modified_bundle_is_refused(self):
        for tree, file, message in (("ok-cluster", "Makefile", "Make checkout is not the reviewed source"),
                                    ("ok-linux", "profiles/kubevirt/profile.yaml", "ok-linux checkout is not the reviewed source")):
            target = self.bundle / tree / file
            original = target.read_bytes()
            try:
                target.write_bytes(original + b"\n# modified\n")
                result = self.destroy_probe()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
            finally:
                target.write_bytes(original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
