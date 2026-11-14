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

    def test_refusals(self):
        commit = head()
        cases = {
            "short commit": (["--commit", commit[:12]], "full 40-character", {}),
            "out inside the checkout": (["--commit", commit], "outside ok-cluster", {"--out": str(ROOT / "rc-test-out")}),
            "official version without --release": (["--commit", commit], "need --release", {"--version": "v0.0.1"}),
            "--release with an rc version": (["--release", "--commit", commit], "no -rc suffix", {}),
        }
        for label, (args, message, override) in cases.items():
            with self.subTest(label):
                command = ["bash", str(SCRIPT), "--version", override.get("--version", VERSION), *args,
                           "--ok-linux", os.environ["OK_LINUX_PATH"], "--chart", os.environ["CILIUM_CHART"],
                           "--out", override.get("--out", str(self.temp / label.replace(" ", "-")))]
                result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, "HOME": str(self.home)})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertFalse((ROOT / "rc-test-out").exists(), "created a directory inside the checkout")
        # A commit that is not HEAD fails at the source step and says so in the report.
        other = "0" * 40
        result = self.run_script("--commit", other, out=self.temp / "wrong-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"not --commit {other}", result.stderr)
        (report,) = self.reports(self.temp / "wrong-commit")
        self.assertEqual((report["result"], report["failedStep"]), ("FAIL", "source"))
        # A non-empty output directory is never reused for a build.
        busy = self.temp / "busy"
        busy.mkdir()
        (busy / "keep").write_text("x")
        result = self.run_script("--commit", head(), out=busy)
        self.assertIn("new or empty directory", result.stderr)
        self.assertEqual([p.name for p in busy.iterdir()], ["keep"])

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
        self.assertFalse((self.home / "Library").exists())
        clean = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True)
        self.assertEqual(clean.stdout, "")

        result = self.run_script("--commit", commit, "--smoke-only", out=out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([r["result"] for r in self.reports(out)], ["PASS", "PASS"])

        native = next(a for a in names.values() if a["nativeSmoke"] == "yes")
        with open(out / native["file"], "ab") as archive:
            archive.write(b"x")
        result = self.run_script("--commit", commit, "--smoke-only", out=out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its .sha256", result.stderr)
        self.assertIn(("FAIL", "verify"), [(r["result"], r["failedStep"]) for r in self.reports(out)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
