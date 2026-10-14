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


def worker_config_patches(documents: list[dict]) -> list[dict]:
    worker = next(
        document
        for document in documents
        if document.get("kind") == "TalosConfigTemplate"
        and document.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("generateType")
        == "worker"
    )
    return worker["spec"]["template"]["spec"]["configPatches"]


def verify_workload_user_namespace_projection(root: Path, revision: str) -> None:
    name = "ok-cli-userns"
    base_path = "/var/openebs/ok-cli-userns"
    source = yaml.safe_load(
        (ROOT / "tests/fixtures/ok130-talos/cluster-config.yaml").read_text()
    )
    source["name"] = name
    source["network"]["endpoint"] = "192.168.100.214"
    source["infraClusterSecretRef"] = {
        "name": f"external-infra-kubeconfig-{name}",
        "namespace": name,
    }
    source["workloadUserNamespaces"] = {
        "enabled": True,
        "maxUserNamespaces": 11255,
        "provisionerBasePath": base_path,
    }
    resolved = resolve_talos_config(source, ROOT.parent / "ok-linux")
    cluster_dir = root / name
    render.render_cluster(name, cluster_dir, resolved)
    rendered = [
        item
        for item in yaml.safe_load_all((cluster_dir / "cluster-base.yaml").read_text())
        if item
    ]
    output = cluster_dir / "projection"
    render.cmd_projection(
        SimpleNamespace(cluster=name, intent_revision=revision, output=str(output))
    )
    projected = [
        item
        for item in yaml.safe_load_all((output / "ok-mgmt-lifecycle.yaml").read_text())
        if item
    ]
    expected = [
        {
            "op": "add",
            "path": "/machine/sysctls",
            "value": {"user.max_user_namespaces": "11255"},
        },
        {
            "op": "add",
            "path": "/machine/kubelet/extraMounts",
            "value": [
                {
                    "destination": base_path,
                    "type": "bind",
                    "source": base_path,
                    "options": ["bind", "rshared", "rw"],
                }
            ],
        },
    ]
    rendered_patches = worker_config_patches(rendered)
    projected_patches = worker_config_patches(projected)
    assert rendered_patches[-2:] == expected
    assert projected_patches == rendered_patches


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
            assert len(infra) == 5 and len(management) == 8
            lifecycle_role, lifecycle_binding = infra[-2:]
            assert lifecycle_role["kind"] == "Role"
            assert lifecycle_role["metadata"]["namespace"] == "ok-cli-mvp"
            assert lifecycle_role["metadata"]["name"] == "ok147-ok-cli-mvp-provider-lifecycle"
            assert lifecycle_binding["kind"] == "RoleBinding"
            assert lifecycle_binding["roleRef"]["name"] == lifecycle_role["metadata"]["name"]
            assert lifecycle_binding["subjects"] == [{
                "kind": "ServiceAccount",
                "name": "ok147-ok-cli-mvp-provider-writer",
                "namespace": "openkubes-execution-system",
            }]
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

            verify_workload_user_namespace_projection(root, revision)
        finally:
            render.CLUSTERS_DIR = original_clusters
    print("OK-147 projection renderer tests: PASS")


if __name__ == "__main__":
    main()
