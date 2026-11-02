#!/usr/bin/env python3
"""Offline positive and negative tests for the promoted Flatcar profile."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import render as renderer  # noqa: E402
from profile_resolvers.flatcar import (  # noqa: E402
    FlatcarProfileError,
    resolve_flatcar_config,
)
import scripts.flatcar_lifecycle as lifecycle  # noqa: E402
from scripts.flatcar_lifecycle import workload_kubeconfig_owned  # noqa: E402


OK_LINUX = Path(
    os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
).resolve()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def base_config() -> dict:
    return {
        "name": "flatcar-production-test",
        "type": "flatcar",
        "provider": "kubevirt",
        "controlPlane": {
            "replicas": 1,
            "cores": 2,
            "memory": "4Gi",
            "disk": "50Gi",
        },
        "workers": {
            "replicas": 1,
            "cores": 2,
            "memory": "4Gi",
            "disk": "50Gi",
        },
        "versions": {"kubernetes": "v1.34.1"},
        "network": {
            "endpoint": "192.168.100.248",
            "podCIDR": "10.48.0.0/16",
            "serviceCIDR": "10.112.0.0/20",
        },
        "nodeSelector": "ok-infra",
        "providerProfile": {"goldenImageStorageClass": "ok-storage-block"},
        "os": {
            "profile": "flatcar-kubevirt",
            "architecture": "amd64",
        },
        "upgrade": {"strategy": "blue-green"},
    }


def objects(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [item for item in yaml.safe_load_all(stream) if item]


def expect_rejected(cfg: dict, label: str) -> None:
    try:
        resolve_flatcar_config(cfg, OK_LINUX)
    except FlatcarProfileError:
        print(f"PASS rejected {label}")
        return
    raise AssertionError(f"resolver accepted unsupported {label}")


def rejection_message(cfg: dict) -> str:
    try:
        resolve_flatcar_config(cfg, OK_LINUX)
    except FlatcarProfileError as error:
        return str(error)
    raise AssertionError("resolver accepted an invalid config")


def diagnostics_cases() -> None:
    """OK-132: a wrong target must read as one, with every violation listed."""
    cfg = base_config()
    cfg["name"] = "ok-kagent"
    cfg["type"] = "talos"
    message = rejection_message(cfg)
    check(
        "ok-kagent is type 'talos', not a Flatcar cluster" in message,
        "resolver names the cluster and its type when type is not flatcar",
    )

    cfg = base_config()
    cfg["workers"]["disk"] = "20Gi"
    cfg["workers"]["replicas"] = 2
    cfg["nodeSelector"] = "ok-gpu"
    message = rejection_message(cfg)
    check(
        all(
            item in message
            for item in (
                "workers.disk must be '50Gi', observed '20Gi'",
                "workers.replicas must be 1, observed 2",
                "nodeSelector must be 'ok-infra', observed 'ok-gpu'",
            )
        )
        and "3 violation(s)" in message,
        "resolver reports every envelope violation, not only the first",
    )
    check(
        message.startswith("flatcar-production-test ")
        and "ADR-009" in message
        and "not configurable" in message,
        "envelope rejection names the cluster and the fixed ADR-009 envelope",
    )

    cfg = base_config()
    cfg["workers"] = "big"
    cfg["bootstrap"] = None
    message = rejection_message(cfg)
    check(
        "workers must be a mapping, observed 'big'" in message
        and "bootstrap must be a mapping, observed None" in message,
        "a section that is not a mapping is a violation, not a TypeError",
    )

    cfg = base_config()
    cfg["extra"] = True
    try:
        resolve_flatcar_config(cfg, Path("/nonexistent-ok-linux"))
    except FlatcarProfileError as error:
        message = str(error)
    else:
        raise AssertionError("resolver accepted a missing ok-linux profile")
    check(
        "unsupported fields: ['extra']" in message
        and "ok-linux profile is absent" in message,
        "a missing ok-linux profile keeps the violations found before it",
    )

    with tempfile.TemporaryDirectory() as directory:
        original_root = lifecycle.ROOT
        lifecycle.ROOT = Path(directory)
        try:
            (Path(directory) / "talos-test").mkdir()
            (Path(directory) / "talos-test" / "cluster-config.yaml").write_text(
                "name: talos-test\ntype: talos\n", encoding="utf-8"
            )
            try:
                lifecycle.require_flatcar_type("talos-test")
            except lifecycle.FlatcarLifecycleError as error:
                message = str(error)
            else:
                raise AssertionError("lifecycle accepted a Talos cluster")
        finally:
            lifecycle.ROOT = original_root
    check(
        "talos-test is type 'talos', not a Flatcar cluster" in message,
        "the lifecycle script itself rejects a non-Flatcar cluster first",
    )


def make_guard(target: str, clusters_dir: Path, cluster: str):
    return subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-s",
            target,
            f"CLUSTERS_DIR={clusters_dir}",
            f"CLUSTER={cluster}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def flatcar_targets_guarded() -> None:
    """OK-132: Flatcar-only targets reject other cluster types up front."""
    with tempfile.TemporaryDirectory() as directory:
        clusters = Path(directory)
        (clusters / "talos-test").mkdir()
        (clusters / "talos-test" / "cluster-config.yaml").write_text(
            "name: talos-test\ntype: talos\n", encoding="utf-8"
        )
        (clusters / "broken-test").mkdir()
        (clusters / "broken-test" / "cluster-config.yaml").write_text(
            "- not\n- a mapping\n", encoding="utf-8"
        )
        (clusters / "flatcar-test").mkdir()
        (clusters / "flatcar-test" / "cluster-config.yaml").write_text(
            "name: flatcar-test\ntype: flatcar\n", encoding="utf-8"
        )
        for target in ("flatcar-preflight", "install-flatcar", "teardown-flatcar"):
            result = make_guard(target, clusters, "talos-test")
            output = result.stdout + result.stderr
            check(
                result.returncode != 0
                and "talos-test is type 'talos', not a Flatcar cluster"
                in output
                and "[require-flatcar] Error" in output,
                f"{target} rejects a non-Flatcar cluster before the lifecycle",
            )
        missing = make_guard("flatcar-preflight", clusters, "absent")
        check(
            missing.returncode != 0
            and "absent has no cluster-config.yaml"
            in missing.stdout + missing.stderr,
            "flatcar-preflight rejects a cluster without cluster-config.yaml",
        )
        broken = make_guard("flatcar-preflight", clusters, "broken-test")
        check(
            broken.returncode != 0
            and "cannot read the type of broken-test"
            in broken.stdout + broken.stderr
            and "<unset>" not in broken.stdout + broken.stderr,
            "a malformed cluster-config.yaml is reported as malformed",
        )
        accepted = make_guard("require-flatcar", clusters, "flatcar-test")
        check(
            accepted.returncode == 0,
            "require-flatcar accepts a type: flatcar cluster",
        )


def negative_cases() -> None:
    cases = []
    cfg = base_config()
    cfg["os"]["architecture"] = "arm64"
    cases.append(("ARM64", cfg))

    cfg = base_config()
    cfg["provider"] = "openstack"
    cases.append(("provider override", cfg))

    cfg = base_config()
    cfg["versions"]["kubernetes"] = "v1.35.0"
    cases.append(("Kubernetes version override", cfg))

    cfg = base_config()
    cfg["controlPlane"]["replicas"] = 3
    cases.append(("HA topology", cfg))

    cfg = base_config()
    cfg["workers"]["replicas"] = 2
    cases.append(("scaled worker topology", cfg))

    cfg = base_config()
    cfg["nodeSelector"] = "ok-gpu"
    cases.append(("KubeVirt scheduling override", cfg))

    cfg = base_config()
    cfg["providerProfile"]["goldenImageStorageClass"] = "local-path"
    cases.append(("target storage override", cfg))

    cfg = base_config()
    cfg["os"]["imageDigest"] = "sha256:" + ("0" * 64)
    cases.append(("image identity override", cfg))

    cfg = base_config()
    cfg["bootstrap"] = {"format": "cloud-config"}
    cases.append(("bootstrap override", cfg))

    cfg = base_config()
    cfg["os"]["sshLifecycleAuthority"] = True
    cases.append(("unsupported OS field", cfg))

    cfg = base_config()
    cfg["name"] = "../ok-infra"
    cases.append(("unsafe cluster name", cfg))

    cfg = base_config()
    cfg["ssh"] = {"enabled": True}
    cases.append(("unsupported top-level field", cfg))

    for label, candidate in cases:
        expect_rejected(candidate, label)


def main() -> int:
    generated_kubeconfig_shape = {
        "current-context": (
            "flatcar-production-test-admin@flatcar-production-test"
        ),
        "contexts": [
            {
                "name": (
                    "flatcar-production-test-admin@"
                    "flatcar-production-test"
                ),
                "context": {"cluster": "flatcar-production-test"},
            }
        ],
        "clusters": [{"name": "flatcar-production-test"}],
    }
    check(
        workload_kubeconfig_owned(
            generated_kubeconfig_shape, "flatcar-production-test"
        )
        and not workload_kubeconfig_owned(
            generated_kubeconfig_shape, "another-cluster"
        ),
        "teardown accepts clusterctl context names but remains cluster-bound",
    )
    source = subprocess.run(
        ["make", "--no-print-directory", "-s", "ok125-static"],
        cwd=OK_LINUX,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        source.returncode == 0,
        "ok-linux production profile passes its owning validator",
    )

    resolved = resolve_flatcar_config(base_config(), OK_LINUX)
    check(
        resolved["os"]["status"] == "production-constrained"
        and resolved["os"]["deployable"] is True
        and resolved["os"]["architecture"] == "amd64"
        and resolved["provider"] == "kubevirt",
        "ordinary config materializes the exact promoted profile",
    )
    check(
        resolved["bootstrap"]
        == {
            "format": "ignition",
            "virtualMachineBootstrapCheck": "none",
        }
        and resolved["os"]["goldenImage"]
        == {
            "namespace": "ok-images",
            "claim": "flatcar-stable-4593-2-4-amd64-kubevirt",
            "published": True,
            "storageClass": "ok-storage-block",
        },
        "bootstrap and KubeVirt image transport remain profile-bound",
    )

    with tempfile.TemporaryDirectory(
        prefix=".flatcar-promotion-a-", dir=ROOT
    ) as first_name, tempfile.TemporaryDirectory(
        prefix=".flatcar-promotion-b-", dir=ROOT
    ) as second_name:
        first = Path(first_name)
        second = Path(second_name)
        renderer.render_cluster(resolved["name"], first, resolved)
        renderer.render_cluster(resolved["name"], second, resolved)
        first_files = {
            item.name: item.read_bytes()
            for item in sorted(first.iterdir())
            if item.is_file()
        }
        second_files = {
            item.name: item.read_bytes()
            for item in sorted(second.iterdir())
            if item.is_file()
        }
        check(
            first_files == second_files,
            "promoted profile renders byte-identically",
        )
        docs = objects(first / "cluster-v2.yaml")
        labelled = [
            item
            for item in docs
            if "labels" in item.get("metadata", {})
        ]
        check(
            labelled
            and all(
                item["metadata"]["labels"].get("openkubes.io/deployable")
                == "true"
                and item["metadata"]["labels"].get(
                    "openkubes.io/adoption-status"
                )
                == "production-constrained"
                for item in labelled
            ),
            "all promoted lifecycle objects expose the constrained status",
        )
        rendered = (first / "cluster-v2.yaml").read_text(encoding="utf-8")
        check(
            "${" not in rendered
            and "kind: Secret" not in rendered
            and "sshAuthorizedKeys" not in rendered
            and "http://" not in rendered
            and "https://" not in rendered,
            "promoted render contains no secret, SSH, or public fetch input",
        )
        revision_suffix = (
            resolved["os"]["identity"].removeprefix("sha256:")[:12]
            + f"-r{resolved['os']['profileRevision']}"
        )
        machine_templates = [
            item for item in docs if item.get("kind") == "KubevirtMachineTemplate"
        ]
        data_volume_templates = [
            data_volume
            for item in machine_templates
            for data_volume in item["spec"]["template"]["spec"][
                "virtualMachineTemplate"
            ]["spec"]["dataVolumeTemplates"]
        ]
        check(
            len(machine_templates) == 2
            and all(
                item["metadata"]["name"].endswith(revision_suffix)
                for item in machine_templates
            )
            and all(
                item["spec"]["storage"]["storageClassName"]
                == "ok-storage-block"
                and item["spec"]["storage"]["resources"]["requests"][
                    "storage"
                ]
                == "50Gi"
                and item["metadata"]["name"].endswith(
                    f"{revision_suffix}-boot"
                )
                for item in data_volume_templates
            ),
            "templates and 50Gi boot clones bind profile revision 5 to Longhorn",
        )

    lifecycle_source = (
        ROOT / "scripts" / "flatcar_lifecycle.py"
    ).read_text(encoding="utf-8")
    scaffold_source = (ROOT / "new-cluster.sh").read_text(encoding="utf-8")
    check(
        '"$TYPE" == "flatcar" || "$TYPE" == "talos"' in scaffold_source
        and 'CP_DISK="${CP_DISK:-50Gi}"' in scaffold_source
        and 'WORKER_DISK="50Gi"' in scaffold_source,
        "scaffold materializes explicit 50Gi Flatcar and Talos benchmark disks",
    )
    check(
        all(
            term in lifecycle_source
            for term in (
                '"ExpandDisks"',
                '"ok-storage-block-snapshot"',
                '"cloneStrategy") != "snapshot"',
                '"volumes.longhorn.io"',
                '"cdi.kubevirt.io/OwnedByUID"',
                '"refusing cleanup: non-profile PVs are cluster-bound',
                '"refusing cleanup: Longhorn ownership mismatch',
            )
        ),
        "preflight and teardown guard Longhorn snapshot-clone lifecycle",
    )

    allowlist = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-s",
            "require-type",
            "CLUSTER=flatcar-production-test",
            "TYPE=flatcar",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        allowlist.returncode == 0,
        "ordinary make type allowlist accepts Flatcar",
    )
    generic_guard = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-s",
            "require-not-flatcar",
            "CLUSTER=tests/fixtures/ok125-flatcar",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        generic_guard.returncode != 0
        and "not a supported Flatcar lifecycle authority"
        in (generic_guard.stdout + generic_guard.stderr),
        "generic lifecycle targets reject Flatcar",
    )
    flatcar_targets_guarded()
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    check(
        "teardown-all cannot own constrained Flatcar lifecycle" in makefile
        and "Run teardown-flatcar explicitly" in makefile,
        "bulk teardown rejects constrained Flatcar clusters",
    )

    lifecycle = subprocess.run(
        ["python3", "scripts/flatcar_lifecycle.py", "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        lifecycle.returncode == 0
        and "PASS constrained Flatcar lifecycle constants are pinned"
        in lifecycle.stdout,
        "guarded install lifecycle is pinned and offline-testable",
    )

    negative_cases()
    diagnostics_cases()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
