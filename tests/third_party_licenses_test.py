#!/usr/bin/env python3
"""Offline attribution completeness and fail-closed collection checks."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_third_party_licenses as licenses  # noqa: E402


class ThirdPartyLicensesTest(unittest.TestCase):
    def test_all_platforms_match_pinned_dependencies_and_upstream_bytes(self):
        manifest = licenses.verify()
        env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="")
        result = subprocess.run(["go", "list", "-mod=readonly", "-m", "-f", "{{.Path}} {{.Dir}}",
                                 *manifest["modules"]], cwd=ROOT, env=env,
                                capture_output=True, text=True, check=True)
        directories = dict(line.split() for line in result.stdout.splitlines())
        directories["github.com/openkubes/ok-cluster"] = str(ROOT)
        for name, record in manifest["files"].items():
            with self.subTest(file=name):
                upstream = Path(directories[record["module"]]) / record["source"]
                self.assertEqual((ROOT / "THIRD_PARTY_LICENSES" / name).read_bytes(), upstream.read_bytes())

    def test_missing_notice_modified_license_and_unrecorded_file_fail_closed(self):
        for mutation, message in (("missing", "inventory mismatch"), ("modified", "checksum mismatch"),
                                  ("extra", "inventory mismatch")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                collection = root / "THIRD_PARTY_LICENSES"
                shutil.copytree(ROOT / "THIRD_PARTY_LICENSES", collection)
                if mutation == "missing":
                    (collection / "gopkg.in/yaml.v3/NOTICE").unlink()
                elif mutation == "modified":
                    path = collection / "github.com/moby/spdystream/LICENSE"
                    path.write_bytes(path.read_bytes() + b"\nchanged\n")
                else:
                    (collection / "UNREVIEWED").write_text("extra")
                with self.assertRaisesRegex(ValueError, message):
                    licenses.verify(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
