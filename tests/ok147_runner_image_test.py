import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_ok147_runner", ROOT / "scripts" / "build_ok147_runner.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class RunnerImageTest(unittest.TestCase):
    def test_containerfile_binds_supply_chain_and_nonroot_runtime(self):
        raw = (ROOT / "Containerfile.ok147").read_text()
        manifest = json.loads((ROOT / "build" / "ok147-runner-image.json").read_text())
        for image in (
            manifest["dockerfileFrontend"],
            manifest["builderImage"],
            manifest["runtimeImage"],
        ):
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
            self.assertIn(image, raw)
        self.assertIn("CGO_ENABLED=0", raw)
        self.assertIn("-trimpath", raw)
        self.assertIn("-buildid=", raw)
        self.assertIn("USER 65532:65532", raw)
        self.assertIn('ENTRYPOINT ["/ok"]', raw)
        self.assertNotIn("COPY .", raw)

    def test_dockerignore_is_allowlist(self):
        lines = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertEqual(lines[0], "**")
        self.assertIn("!go.mod", lines)
        self.assertIn("!cmd/ok/**", lines)
        self.assertIn("!internal/**", lines)
        self.assertFalse(any("kube" in line.lower() for line in lines[1:]))

    def test_plan_is_nonpublishing_and_digest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "runner.oci.tar"
            args = type("Args", (), {
                "version": "0.1.0-dev",
                "revision": "a" * 40,
                "created": "2026-08-16T08:00:00Z",
                "output": str(output),
                "execute": False,
            })()
            resolved, created = MODULE.validate(args, ROOT)
            command = MODULE.build_command(ROOT, args, resolved, created)
            contract, contract_digest = MODULE.supply_chain_contract(ROOT)
            self.assertIn("--provenance=mode=max", command)
            self.assertIn("linux/amd64,linux/arm64", command)
            self.assertIn(f"type=oci,dest={resolved}", command)
            self.assertNotIn("--push", command)
            self.assertEqual(contract["networkPublication"], "disabled")
            self.assertRegex(contract_digest, r"^sha256:[0-9a-f]{64}$")

    def test_invalid_build_inputs_fail_closed(self):
        invalid = [
            ("version", "latest"),
            ("revision", "abc"),
            ("created", "now"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            for field, value in invalid:
                args = type("Args", (), {
                    "version": "0.1.0-dev",
                    "revision": "a" * 40,
                    "created": "2026-08-16T08:00:00Z",
                    "output": str(Path(temporary) / f"{field}.tar"),
                    "execute": False,
                })()
                setattr(args, field, value)
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        MODULE.validate(args, ROOT)

    def test_archive_without_index_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.tar"
            with tarfile.open(path, "w"):
                pass
            with self.assertRaisesRegex(ValueError, "has no index.json"):
                MODULE.inspect_oci_archive(path)


if __name__ == "__main__":
    unittest.main()
