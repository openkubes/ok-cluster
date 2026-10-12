#!/usr/bin/env python3
"""Offline create-only checks for the OK-147 projection renderer."""

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile

import yaml

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import render  # noqa: E402
from profile_resolvers.talos import resolve_talos_config  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT, prefix=".ok147-projection-") as temporary:
        root = Path(temporary)
        original_clusters = render.CLUSTERS_DIR
        render.CLUSTERS_DIR = root
        try:
            source = yaml.safe_load(
                (ROOT / "tests/fixtures/ok130-talos/cluster-config.yaml").read_text()
            )
            source["name"] = "ok-cli-mvp"
            source["network"]["endpoint"] = "192.168.100.213"
            source["infraClusterSecretRef"] = {
                "name": "external-infra-kubeconfig-ok-cli-mvp",
                "namespace": "ok-cli-mvp",
            }
            resolved = resolve_talos_config(source, ROOT.parent / "ok-linux")
            cluster_dir = root / "ok-cli-mvp"
            render.render_cluster("ok-cli-mvp", cluster_dir, resolved)
            revision = "sha256:" + "1" * 64
            output = cluster_dir / "projection"
            arguments = SimpleNamespace(
                cluster="ok-cli-mvp", intent_revision=revision, output=str(output)
            )
            render.cmd_projection(arguments)

            manifest = json.loads((output / "manifest.json").read_text())
            authority = json.loads((output / "authority-map.json").read_text())
            infra = list(yaml.safe_load_all((output / "ok-infra-prerequisites.yaml").read_text()))
            management = list(yaml.safe_load_all((output / "ok-mgmt-lifecycle.yaml").read_text()))
            assert manifest["authorizationState"] == "NO-GO"
            assert manifest["R"] == revision
            assert len(infra) == 3 and len(management) == 8
            assert authority["contractIdentity"] == {
                "name": "ok-cli-mvp", "namespace": "ok-cli-mvp"
            }
            for document in [*infra, *management]:
                annotations = document["metadata"]["annotations"]
                assert annotations["openkubes.io/intent-revision"] == revision
                assert annotations["openkubes.io/contract-name"] == "ok-cli-mvp"
            assert all(path.stat().st_mode & 0o077 == 0 for path in output.iterdir())

            try:
                render.cmd_projection(arguments)
            except SystemExit as error:
                assert "already exists" in str(error)
            else:
                raise AssertionError("projection renderer overwrote an existing output")
        finally:
            render.CLUSTERS_DIR = original_clusters
    print("OK-147 projection renderer tests: PASS")


if __name__ == "__main__":
    main()
