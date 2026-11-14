#!/usr/bin/env python3
"""OK-228: scripts/ok-rc-acceptance.sh builds, verifies and smoke-tests a
release candidate for an explicit version and commit, writes a JSON report,
and refuses anything it cannot prove. Needs a clean checkout at HEAD, the
pinned ok-linux (OK_LINUX_PATH) and the pinned chart (CILIUM_CHART); touches no
cluster, no PATH and no user configuration (HOME is isolated)."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ok-rc-acceptance.sh"
VERSION = "v0.0.0-rc1"


def head():
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


@unittest.skipIf(os.geteuid() == 0, "the acceptance run refuses root")
class RCAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="ok-rc-acceptance-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.home = self.temp / "home"
        (self.home / ".local" / "bin").mkdir(parents=True)
        # A pre-existing user ok that must never be touched.
        self.user_ok = self.home / ".local" / "bin" / "ok"
        self.user_ok.write_text("#!/bin/sh\necho user-ok\n")

    def run_script(self, *args, out=None):
        command = ["bash", str(SCRIPT), "--version", VERSION, "--ok-linux", os.environ["OK_LINUX_PATH"],
                   "--chart", os.environ["CILIUM_CHART"], "--out", str(out or self.temp / "out"), *args]
        env = {**os.environ, "HOME": str(self.home), "TMPDIR": str(self.temp), "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("XDG_CONFIG_HOME", None)
        return subprocess.run(command, capture_output=True, text=True, env=env)

    def reports(self, out):
        return [json.loads(p.read_text()) for p in sorted(Path(out).glob("acceptance-*.json"))]

    def assertSetupRefusal(self, result, message, out):
        """Before the report location is accepted: exit 2, said on stderr, no report anywhere."""
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(message, result.stderr)
        self.assertIn("no report written", result.stderr)
        self.assertEqual(list(Path(out).glob("acceptance-*.json")) if Path(out).exists() else [], [])

    def test_refusals(self):
        commit = head()
        missing_chart = str(self.temp / "no-chart.tgz")
        cases = {
            "short commit": (["--commit", commit[:12]], "full 40-character", {}),
            "official version without --release": (["--commit", commit], "need --release", {"--version": "v0.0.1"}),
            "--release with an rc version": (["--release", "--commit", commit], "no -rc suffix", {}),
            "missing chart": (["--commit", commit], "--chart must be", {"--chart": missing_chart}),
            "missing ok-linux": (["--commit", commit], "ok-linux checkout not found", {"--ok-linux": str(self.temp / "no-ok-linux")}),
            "out inside the checkout": (["--commit", commit], "outside ok-cluster", {"--out": str(ROOT / "rc-test-out")}),
            "unknown argument": (["--commit", commit, "--bogus"], "unknown argument", {}),
            "unknown target": (["--commit", commit, "--targets", "windows-amd64"], "--targets accepts", {}),
            "duplicate target": (["--commit", commit, "--targets", "linux-amd64 linux-amd64"], "twice", {}),
        }
        for label, (args, message, override) in cases.items():
            with self.subTest(label):
                out = override.get("--out", str(self.temp / label.replace(" ", "-")))
                command = ["bash", str(SCRIPT), "--version", override.get("--version", VERSION), *args,
                           "--ok-linux", override.get("--ok-linux", os.environ["OK_LINUX_PATH"]),
                           "--chart", override.get("--chart", os.environ["CILIUM_CHART"]), "--out", out]
                result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, "HOME": str(self.home)})
                self.assertSetupRefusal(result, message, out)
        self.assertFalse((ROOT / "rc-test-out").exists(), "created a directory inside the checkout")
        # A non-empty output directory and an existing --work directory are setup refusals too.
        busy = self.temp / "busy"
        busy.mkdir()
        (busy / "keep").write_text("x")
        self.assertSetupRefusal(self.run_script("--commit", commit, out=busy), "new or empty directory", busy)
        self.assertEqual([p.name for p in busy.iterdir()], ["keep"])
        work = self.temp / "existing-work"
        work.mkdir()
        self.assertSetupRefusal(self.run_script("--commit", commit, "--work", str(work), out=self.temp / "with-work"),
                                "--work must not exist", self.temp / "with-work")
        # An unexpected command failure during setup (set -e) is reported the same way.
        locked = self.temp / "locked"
        locked.mkdir(mode=0o500)
        self.addCleanup(locked.chmod, 0o700)
        result = self.run_script("--commit", commit, out=locked / "out")
        self.assertSetupRefusal(result, "setup failed (exit 1)", locked / "out")
        # From the source step on, every failure exits 1 and is in the report.
        other = "0" * 40
        result = self.run_script("--commit", other, out=self.temp / "wrong-commit")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"not --commit {other}", result.stderr)
        self.assertNotIn("no report written", result.stderr)
        (report,) = self.reports(self.temp / "wrong-commit")
        self.assertEqual((report["result"], report["failedStep"]), ("FAIL", "source"))
        self.assertEqual(report["steps"][-1], {"name": "source", "status": "FAIL", "detail": "exit 1"})

    def test_release_requires_tag_on_the_exact_commit(self):
        """In a throwaway local clone (never pushed): a missing tag and a tag on
        another commit fail at the source step; the right tag passes it."""
        clone = self.temp / "clone"
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(clone)], check=True)
        git = ["git", "-C", str(clone), "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
        base = head()
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "later"], check=True)
        later = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        script = clone / "scripts" / "ok-rc-acceptance.sh"

        def release(out, commit):
            return subprocess.run(["bash", str(script), "--release", "--version", "v0.0.1", "--commit", commit, "--smoke-only",
                                   "--ok-linux", os.environ["OK_LINUX_PATH"], "--chart", os.environ["CILIUM_CHART"], "--out", str(out)],
                                  capture_output=True, text=True, env={**os.environ, "HOME": str(self.home), "TMPDIR": str(self.temp)})

        result = release(self.temp / "no-tag", later)
        self.assertIn("does not exist locally", result.stderr)
        self.assertEqual((result.returncode, self.reports(self.temp / "no-tag")[0]["failedStep"]), (1, "source"))
        subprocess.run(git + ["tag", "v0.0.1", base], check=True)
        result = release(self.temp / "other-commit", later)
        self.assertIn(f"points at {base}, not the approved commit {later}", result.stderr)
        subprocess.run(git + ["tag", "-d", "v0.0.1"], check=True, capture_output=True)
        subprocess.run(git + ["tag", "-a", "-m", "v0.0.1", "v0.0.1", later], check=True)
        result = release(self.temp / "tagged", later)  # passes source, then no artifacts to verify
        (report,) = self.reports(self.temp / "tagged")
        self.assertEqual((report["kind"], report["failedStep"]), ("release", "verify"), result.stderr)
        self.assertEqual(report["steps"][0]["status"], "PASS")
        self.assertIn("tag v0.0.1 -> commit", report["steps"][0]["detail"])
        self.assertTrue(str(self.temp / "tagged").endswith("tagged"))
        tags = subprocess.run(["git", "-C", str(ROOT), "tag", "-l", "v0.0.1"], capture_output=True, text=True).stdout
        self.assertEqual(tags, "", "a tag leaked into the real checkout")

    def test_full_run_then_smoke_only_and_tamper(self):
        commit = head()
        out = self.temp / "rc"
        result = self.run_script("--commit", commit, out=out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        (report,) = self.reports(out)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual((report["commit"], report["kind"]), (commit, "release-candidate"))
        self.assertEqual([s["name"] for s in report["steps"]], ["source", "tests", "build", "verify", "smoke", "final"])
        names = {a["platform"]: a for a in report["artifacts"]}
        self.assertEqual(set(names), {"darwin-arm64", "linux-amd64"})
        for platform, artifact in names.items():
            archive = out / artifact["file"]
            self.assertTrue(archive.is_file())
            self.assertEqual((out / f"{artifact['file']}.sha256").read_text().split()[0], artifact["sha256"])
        self.assertEqual(sum(a["nativeSmoke"] == "yes" for a in names.values()), 1)
        self.assertEqual(self.user_ok.read_text(), "#!/bin/sh\necho user-ok\n")
        self.assertFalse((self.home / ".config" / "ok").exists())
        # Go may create its build cache under ~/Library/Caches; the ok config must not appear.
        self.assertFalse((self.home / "Library" / "Application Support" / "ok").exists())
        clean = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True)
        self.assertEqual(clean.stdout, "")

        result = self.run_script("--commit", commit, "--smoke-only", out=out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([r["result"] for r in self.reports(out)], ["PASS", "PASS"])

        # One native target only, as each CI runner does it.
        native = next(a for a in names.values() if a["nativeSmoke"] == "yes")
        result = self.run_script("--commit", commit, "--smoke-only", "--targets", native["platform"], out=out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        last = self.reports(out)[-1]
        self.assertEqual((last["targets"], [a["platform"] for a in last["artifacts"]]), ([native["platform"]], [native["platform"]]))
        self.assertEqual([s["status"] for s in last["steps"] if s["name"] == "smoke"], ["PASS"])

        with open(out / native["file"], "ab") as archive:
            archive.write(b"x")
        result = self.run_script("--commit", commit, "--smoke-only", out=out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its .sha256", result.stderr)
        self.assertIn(("FAIL", "verify"), [(r["result"], r["failedStep"]) for r in self.reports(out)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
