#!/usr/bin/env python3
"""OK-228: install-ok.sh installs a verified release bundle for an unprivileged
user, never overwrites anything and refuses unsafe or mismatched archives.
Builds one bundle for this platform; touches no cluster and no global ok."""

import hashlib
import io
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-ok.sh"
GOOS = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
GOARCH = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
VERSION = "v0.0.0-install-test"
NAME = f"ok-{VERSION}-{GOOS}-{GOARCH}"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipIf(os.geteuid() == 0, "install-ok.sh refuses root; run as an unprivileged user")
class InstallOkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = Path(tempfile.mkdtemp(prefix="ok-install-test-")).resolve()
        command = ["bash", str(ROOT / "scripts" / "build_release_bundle.sh"), "--out", str(cls.temp / "dist"),
                   "--goos", GOOS, "--goarch", GOARCH, "--ok-linux", os.environ["OK_LINUX_PATH"], "--version", VERSION]
        if os.environ.get("CILIUM_CHART") and Path(os.environ["CILIUM_CHART"]).is_file():
            command += ["--chart-source", os.environ["CILIUM_CHART"]]
        build = subprocess.run(command, capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError(build.stdout + build.stderr)
        cls.archive = cls.temp / "dist" / f"{NAME}.tar.gz"
        cls.digest = sha256(cls.archive)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=self.temp)).resolve()
        self.home = self.case / "home"
        self.home.mkdir()

    def install(self, *args, archive=None, digest=None, path=None):
        env = {"HOME": str(self.home), "PATH": path or os.environ["PATH"], "LC_ALL": "C"}
        command = ["sh", str(INSTALLER), "--archive", str(archive or self.archive), "--sha256", digest or self.digest, *args]
        return subprocess.run(command, capture_output=True, text=True, env=env)

    def assertNothingInstalled(self, result, prefix=None, reason=None):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        if reason:
            self.assertIn(reason, result.stderr)
        prefix = prefix or self.home / ".local" / "share" / "ok"
        leftovers = list(prefix.iterdir()) if prefix.exists() else []
        self.assertEqual(leftovers, [], f"staging or install left behind: {leftovers}\n{result.stderr}")
        self.assertFalse((self.home / ".local" / "bin" / "ok").exists())

    def test_fresh_install_link_and_bundle_discovery(self):
        before = self.archive.stat()
        result = self.install("--link")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundle = self.home / ".local" / "share" / "ok" / NAME
        link = self.home / ".local" / "bin" / "ok"
        self.assertTrue(link.is_symlink())
        self.assertEqual(Path(os.readlink(link)), bundle / "ok-cluster" / ".tools" / "bin" / "ok")
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        version = subprocess.run([str(link), "version"], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(version, f"{VERSION} {commit}")
        for item in ("ok-cluster/.tools/cilium-1.19.6.tgz", "ok-linux/profiles/kubevirt/profile.yaml", "release.txt"):
            self.assertTrue((bundle / item).is_file(), item)
        after = self.archive.stat()
        self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))
        self.assertEqual(sha256(self.archive), self.digest)
        self.assertIn("is not on your PATH", result.stdout)
        self.assertFalse(any(p.name.startswith(".install-") for p in bundle.parent.iterdir()))
        # ok config init through the ~/.local/bin/ok symlink finds and verifies this bundle.
        config = self.home / "cfg" / "config.json"
        init = subprocess.run([str(link), "config", "init", "--config", str(config)], capture_output=True, text=True,
                              env={"HOME": str(self.home), "PATH": os.environ["PATH"], "XDG_STATE_HOME": str(self.home / "state")},
                              stdin=subprocess.DEVNULL)
        self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
        self.assertIn("release bundle (release.txt matches)", init.stderr)
        self.assertIn(f'"lifecycleRoot": "{bundle / "ok-cluster"}"', config.read_text())
        self.assertNotIn("providerKubeconfig", config.read_text())
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)

    def test_alternative_prefix_and_bin_dir_without_link(self):
        prefix, bindir = self.case / "opt" / "ok", self.case / "bin"
        result = self.install("--prefix", str(prefix), "--bin-dir", str(bindir))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((prefix / NAME / "ok-cluster" / ".tools" / "bin" / "ok").is_file())
        self.assertFalse((bindir / "ok").exists(), "linked without --link")
        self.assertIn(f"ln -s {prefix / NAME}/ok-cluster/.tools/bin/ok {bindir}/ok", result.stdout)

    def test_existing_installation_and_existing_ok_are_never_overwritten(self):
        bindir = self.home / ".local" / "bin"
        bindir.mkdir(parents=True)
        (bindir / "ok").write_text("#!/bin/sh\necho existing\n")
        self.assertEqual(self.install("--link").returncode, 0)
        self.assertEqual((bindir / "ok").read_text(), "#!/bin/sh\necho existing\n")
        marker = self.home / ".local" / "share" / "ok" / NAME / "marker"
        marker.write_text("keep")
        again = self.install("--link")
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("never overwritten", again.stderr)
        self.assertEqual(marker.read_text(), "keep")

    def test_wrong_or_malformed_checksum_extracts_nothing(self):
        for digest in ("0" * 64, "abc", "z" * 64, self.digest[:-1]):
            result = self.install(digest=digest)
            self.assertNothingInstalled(result)
        self.assertIn("nothing was extracted", self.install(digest="0" * 64).stderr)

    def test_refuses_root_relative_or_unsafe_paths_and_missing_flags(self):
        for args in (("--prefix", "relative/ok"), ("--prefix", str(self.case / "bad dir")), ("--bin-dir", str(self.case / "a/../b"))):
            self.assertNothingInstalled(self.install(*args))
        missing = subprocess.run(["sh", str(INSTALLER), "--archive", str(self.archive)], capture_output=True, text=True,
                                 env={"HOME": str(self.home), "PATH": os.environ["PATH"]})
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("--sha256 is required", missing.stderr)

    def crafted(self, mutate, name=NAME, archive_name=None):
        """Repack the real bundle with one change; returns (archive, digest)."""
        source = self.case / "src"
        if not source.exists():
            source.mkdir()
            with tarfile.open(self.archive) as tar:
                tar.extractall(source, filter="tar") if sys.version_info >= (3, 12) else tar.extractall(source)
        archive = self.case / (archive_name or f"{NAME}.tar.gz")
        with tarfile.open(archive, "w:gz") as out:
            out.add(source / NAME, arcname=name)
            mutate(out, source / NAME)
        return archive, sha256(archive)

    @staticmethod
    def member(name, kind=tarfile.REGTYPE, data=b"x", mode=0o644, link=""):
        info = tarfile.TarInfo(name)
        info.type, info.mode, info.linkname, info.size = kind, mode, link, len(data) if kind == tarfile.REGTYPE else 0
        return info, io.BytesIO(data) if kind == tarfile.REGTYPE else None

    def test_refuses_unsafe_archive_entries(self):
        special, outside = "links, special files or privileged modes", "outside"
        cases = {
            "symlink": (lambda out, _: out.addfile(*self.member(f"{NAME}/link", tarfile.SYMTYPE, link="/etc/passwd")), special),
            "hard link": (lambda out, _: out.addfile(*self.member(f"{NAME}/hard", tarfile.LNKTYPE, link=f"{NAME}/release.txt")), special),
            "parent reference": (lambda out, _: out.addfile(*self.member(f"{NAME}/../escape")), "'..'"),
            "absolute path": (lambda out, _: out.addfile(*self.member("/tmp/ok-install-test-escape")), outside),
            "second top-level directory": (lambda out, _: out.addfile(*self.member("other/file")), outside),
            "setuid": (lambda out, _: out.addfile(*self.member(f"{NAME}/suid", mode=0o4755)), special),
            "fifo": (lambda out, _: out.addfile(*self.member(f"{NAME}/fifo", tarfile.FIFOTYPE)), special),
        }
        for label, (mutate, reason) in cases.items():
            with self.subTest(label):
                self.setUp()
                archive, digest = self.crafted(mutate)
                self.assertNothingInstalled(self.install(archive=archive, digest=digest), reason=reason)
        self.assertFalse(Path("/tmp/ok-install-test-escape").exists())

    def test_refuses_wrong_platform_or_name(self):
        other = "linux-amd64" if f"{GOOS}-{GOARCH}" != "linux-amd64" else "darwin-arm64"
        for archive_name, reason in ((f"ok-{VERSION}-{other}.tar.gz", "not for this machine"), ("bundle.tar.gz", "must be named"),
                                     (f"ok-{VERSION} x-{GOOS}-{GOARCH}.tar.gz", "unsupported archive name")):
            with self.subTest(archive_name):
                self.setUp()
                archive = self.case / archive_name
                shutil.copyfile(self.archive, archive)
                self.assertNothingInstalled(self.install(archive=archive, digest=sha256(archive)), reason=reason)

    def test_refuses_corrupted_mismatched_or_dirty_bundles(self):
        # Each archive carries its own matching digest: the checksum passes and
        # the bundle verification inside staging must refuse it.
        mutations = {
            "binary differs from release.txt": ("ok-cluster/.tools/bin/ok", b"#!/bin/sh\necho v\n", "ok binary does not match"),
            "chart differs from release.txt": ("ok-cluster/.tools/cilium-1.19.6.tgz", b"tampered", "Cilium chart does not match"),
            "dirty ok-cluster": ("ok-cluster/Makefile", b"changed\n", "ok-cluster has changes"),
            "untracked file in ok-linux": ("ok-linux/extra.txt", b"x", "ok-linux has changes"),
            "release.txt for another commit": ("release.txt", None, "ok version reports"),
        }
        for label, (path, data, reason) in mutations.items():
            with self.subTest(label):
                self.setUp()
                self.crafted(lambda out, root: None)  # extract the real bundle into this case
                target = self.case / "src" / NAME / path
                if data is None:
                    text = target.read_text()
                    commit = next(line.split()[2] for line in text.splitlines() if line.startswith("ok-cluster commit:"))
                    data = text.replace(commit, "f" * 40).encode()
                target.write_bytes(data)
                archive, digest = self.crafted(lambda out, root: None)
                self.assertNothingInstalled(self.install(archive=archive, digest=digest), reason=reason)
        with self.subTest("truncated archive"):
            self.setUp()
            truncated = self.case / f"{NAME}.tar.gz"
            truncated.write_bytes(self.archive.read_bytes()[: self.archive.stat().st_size // 2])
            self.assertNothingInstalled(self.install(archive=truncated, digest=sha256(truncated)), reason="cannot list")

    def test_missing_runtime_tool_stops_before_extraction(self):
        tools = self.case / "tools"
        tools.mkdir()
        for tool in ("sh", "uname", "mktemp", "find", "awk", "id", "tr", "basename", "pwd", "sha256sum", "shasum", "tar"):
            found = shutil.which(tool)
            if found:
                (tools / tool).symlink_to(found)
        result = self.install(path=str(tools))  # no git
        self.assertNothingInstalled(result)
        self.assertIn("required tool missing: git", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
