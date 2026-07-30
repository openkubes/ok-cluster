#!/usr/bin/env python3
"""Offline acceptance tests for the OK-130 Talos Golden-Image consumer."""

from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
OK_LINUX = Path(
    __import__("os").environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
).resolve()
FIXTURE = ROOT / "tests" / "fixtures" / "ok130-talos" / "cluster-config.yaml"
sys.path.insert(0, str(ROOT))

import render  # noqa: E402
from profile_resolvers.talos import (  # noqa: E402
    TalosProfileError,
    golden_claim,
    identity_material,
    resolve_talos_config,
)
from scripts.talos_golden_lifecycle import validate_manifest  # noqa: E402
from scripts.talos_replacement_runtime import verify_timeline  # noqa: E402


CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((condition, message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def docs(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [item for item in yaml.safe_load_all(stream) if item]


def nested(value, key: str):
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key == key:
                yield child
            yield from nested(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from nested(child, key)


def expect_failure(config: dict, message: str) -> None:
    try:
        resolve_talos_config(config, OK_LINUX)
    except TalosProfileError:
        check(True, message)
    else:
        check(False, message)


def main() -> int:
    raw = load(FIXTURE)
    resolved = resolve_talos_config(raw, OK_LINUX)
    identity = (
        "sha256:"
        "7f5dd4276432f522727a50e604538b6befc0cac51ee2b90d4b1ccbfcac774a2d"
    )
    check(
        resolved["os"]["identity"] == identity
        and resolved["os"]["imageDigest"]
        == "sha256:"
        "461d72d30750b9e18cf0656239e0274764b1e391bde5bbc41084a887b8a55ed5"
        and resolved["os"]["goldenImage"]
        == {
            "namespace": "ok-images",
            "claim": "talos-v1-9-6-ce4c980550dd-461d72d30750-amd64",
            "published": True,
            "storageClass": "ok-storage-block",
        },
        "resolver consumes the exact ok-linux Talos artifact identity",
    )
    profile = load(OK_LINUX / "profiles" / "kubevirt" / "profile.yaml")
    current_talos = profile["talos"]
    current_artifact = current_talos["boot_artifact"]
    future_talos = copy.deepcopy(current_talos)
    future_talos["version"] = "v1.9.7"
    check(
        golden_claim(current_talos, current_artifact)
        == current_artifact["golden_image"]["claim"]
        and golden_claim(future_talos, current_artifact)
        != golden_claim(current_talos, current_artifact)
        and identity_material(future_talos, current_artifact)
        != identity_material(current_talos, current_artifact),
        "version changes derive a new immutable identity and PVC name",
    )

    bad_version = copy.deepcopy(raw)
    bad_version["versions"]["talos"] = "v1.9.7"
    expect_failure(
        bad_version,
        "unreviewed Talos version fails closed",
    )
    bad_schematic = copy.deepcopy(raw)
    bad_schematic["os"]["schematic_id"] = "0" * 64
    expect_failure(
        bad_schematic,
        "unreviewed schematic fails closed",
    )
    openstack = copy.deepcopy(raw)
    openstack["provider"] = "openstack"
    check(
        resolve_talos_config(openstack, OK_LINUX) == openstack,
        "non-KubeVirt Talos provider semantics are unchanged",
    )

    management = load(ROOT / "ok-mgmt" / "cluster-config.yaml")
    with tempfile.TemporaryDirectory(
        prefix=".ok130-mgmt-boundary-", dir=ROOT
    ) as temp:
        output = Path(temp)
        render.render_cluster(
            management["name"], output, management
        )
        management_base = (output / "cluster-base.yaml").read_text(
            encoding="utf-8"
        )
        check(
            "kind: Role\n" not in management_base
            and "-talos-golden-image-cloner" not in management_base
            and "source:\n                http:" in management_base,
            "talos-mgmt keeps its existing unbroadened template contract",
        )

    with tempfile.TemporaryDirectory(
        prefix=".ok130-render-", dir=ROOT
    ) as temp:
        output = Path(temp)
        render.render_cluster(raw["name"], output, resolved)
        base = output / "cluster-base.yaml"
        legacy = output / "cluster-v2.yaml"
        rendered = base.read_text(encoding="utf-8")
        rendered_legacy = legacy.read_text(encoding="utf-8")
        resources = docs(base)
        roles = [item for item in resources if item["kind"] == "Role"]
        bindings = [
            item for item in resources if item["kind"] == "RoleBinding"
        ]
        check(
            len(roles) == 1
            and roles[0]["metadata"]["namespace"] == "ok-images"
            and roles[0]["rules"]
            == [
                {
                    "apiGroups": ["cdi.kubevirt.io"],
                    "resources": ["datavolumes/source"],
                    "verbs": ["create"],
                }
            ]
            and bindings[0]["subjects"]
            == [
                {
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": "ok130-talos",
                }
            ],
            "cross-namespace CDI authorization is least privilege",
        )
        pvc_sources = [
            value
            for value in nested(resources, "pvc")
            if isinstance(value, dict)
            and set(value) == {"namespace", "name"}
        ]
        check(
            pvc_sources
            == [
                {
                    "namespace": "ok-images",
                    "name": (
                        "talos-v1-9-6-ce4c980550dd-461d72d30750-amd64"
                    ),
                },
                {
                    "namespace": "ok-images",
                    "name": (
                        "talos-v1-9-6-ce4c980550dd-461d72d30750-amd64"
                    ),
                },
            ],
            "control-plane and worker clone the same Golden PVC",
        )
        machine_templates = [
            item
            for item in resources
            if item["kind"] == "KubevirtMachineTemplate"
        ]
        short = identity.removeprefix("sha256:")[:12]
        check(
            len(machine_templates) == 2
            and all(
                item["metadata"]["name"].endswith(short)
                and item["metadata"]["annotations"][
                    "openkubes.io/os-identity-full"
                ]
                == identity
                for item in machine_templates
            ),
            "KubeVirt machine templates are identity-bound",
        )
        check(
            all(
                storage == "ok-storage-block"
                for storage in nested(resources, "storageClassName")
            ),
            "Golden clones use ok-storage-block",
        )
        check(
            "factory.talos.dev" not in rendered
            and "factory.talos.dev" not in rendered_legacy
            and "\n                http:" not in rendered
            and "\n                      registry:" not in rendered_legacy,
            "rendered Talos KubeVirt manifests contain no public VM image source",
        )
        control_plane = [
            item for item in resources if item["kind"] == "TalosControlPlane"
        ][0]
        worker = [
            item for item in resources if item["kind"] == "TalosConfigTemplate"
        ][0]
        check(
            control_plane["spec"]["controlPlaneConfig"]["controlplane"][
                "generateType"
            ]
            == "controlplane"
            and worker["spec"]["template"]["spec"]["generateType"] == "worker"
            and not list(nested(resources, "stringData"))
            and not [item for item in resources if item["kind"] == "Secret"],
            "Talos machine configuration and secrets remain dynamic",
        )
        check(
            worker["metadata"]["name"].endswith("v1-9-6")
            and [
                item
                for item in resources
                if item["kind"] == "MachineDeployment"
            ][0]["spec"]["template"]["spec"]["bootstrap"]["configRef"][
                "name"
            ].endswith("v1-9-6"),
            "worker bootstrap template is immutable and Talos-version-bound",
        )
        validate_manifest(resolved, base)
        check(True, "lifecycle local manifest guard accepts the render")

    profile_test = subprocess.run(
        ["make", "--no-print-directory", "-s", "ok130-profile-test"],
        cwd=OK_LINUX,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        profile_test.returncode == 0,
        "owning ok-linux profile validator passes",
    )

    replacement_timeline = [
        {
            "nodes": [
                {
                    "uid": "old-cp",
                    "name": "cluster-cp-old",
                    "role": "control-plane",
                    "ready": True,
                    "os_image": "Talos (v1.9.5)",
                },
                {
                    "uid": "old-worker",
                    "name": "cluster-worker-old",
                    "role": "worker",
                    "ready": True,
                    "os_image": "Talos (v1.9.5)",
                },
            ]
        },
        {
            "nodes": [
                {
                    "uid": "old-cp",
                    "name": "cluster-cp-old",
                    "role": "control-plane",
                    "ready": True,
                    "os_image": "Talos (v1.9.5)",
                },
                {
                    "uid": "new-cp",
                    "name": "cluster-cp-7f5dd4276432",
                    "role": "control-plane",
                    "ready": True,
                    "os_image": "Talos (v1.9.6)",
                },
                {
                    "uid": "old-worker",
                    "name": "cluster-worker-old",
                    "role": "worker",
                    "ready": True,
                    "os_image": "Talos (v1.9.5)",
                },
                {
                    "uid": "new-worker",
                    "name": "cluster-worker-7f5dd4276432",
                    "role": "worker",
                    "ready": True,
                    "os_image": "Talos (v1.9.6)",
                },
            ]
        },
        {
            "nodes": [
                {
                    "uid": "new-cp",
                    "name": "cluster-cp-7f5dd4276432",
                    "role": "control-plane",
                    "ready": True,
                    "os_image": "Talos (v1.9.6)",
                },
                {
                    "uid": "new-worker",
                    "name": "cluster-worker-7f5dd4276432",
                    "role": "worker",
                    "ready": True,
                    "os_image": "Talos (v1.9.6)",
                },
            ]
        },
    ]
    replacement_proof = verify_timeline(
        replacement_timeline, "v1.9.5", "v1.9.6", "7f5dd4276432"
    )
    check(
        replacement_proof["control_plane_ready_in_every_observation"]
        and replacement_proof["role_replacement_ready_before_old_absent"],
        "replacement observer proves role-safe Talos blue-green convergence",
    )
    replacement_source = (
        ROOT / "scripts" / "talos_replacement_runtime.py"
    ).read_text(encoding="utf-8")
    check(
        "PASS_WITH_TRANSIENT_API_INTERRUPTION" in replacement_source
        and '"api_continuity"' in replacement_source
        and "max-api-unavailable-seconds" in replacement_source
        and "transient_workload_api_error" in replacement_source,
        "replacement evidence records bounded workload API interruptions",
    )

    lifecycle_source = (
        ROOT / "scripts" / "talos_golden_lifecycle.py"
    ).read_text(encoding="utf-8")
    check(
        '"rolebinding", "role"' in lifecycle_source
        and "shared Talos Golden PVC changed on cleanup" in lifecycle_source
        and '"delete",\n                kind,\n                authorization' in lifecycle_source,
        "cleanup targets exact clone RBAC and re-verifies the Golden PVC",
    )
    check(
        '"cdi.kubevirt.io/OwnedByUID"' in lifecycle_source
        and "cluster-owned CDI snapshot source is invalid" in lifecycle_source
        and '--data-volume-uids "$$DV_UIDS"' in (
            ROOT / "Makefile"
        ).read_text(encoding="utf-8"),
        "cleanup binds temporary CDI snapshots to exact DataVolume UIDs",
    )
    check(
        '"mode": "warm-provisioning"' in lifecycle_source
        and '"public_import_count": 0' in lifecycle_source
        and '"mutation_attempted": False' in lifecycle_source,
        "runtime evidence separates warm clone timing from publication",
    )
    check(
        '"capi_available"' in lifecycle_source
        and '"nodes_ready"' in lifecycle_source
        and '"end_to_end_cilium_ready"' in lifecycle_source
        and '"cilium-1.19.6"' in lifecycle_source
        and 'provider_id.startswith("kubevirt://")' in lifecycle_source,
        "warm evidence uses comparable CAPI, Node, Cilium milestones",
    )
    check(
        '["get", "node", "ok-infra"]' in lifecycle_source
        and "ok-infra is not Ready and schedulable" in lifecycle_source,
        "management preflight verifies the reviewed scheduling target",
    )
    check(
        '"ExpandDisks" not in gates' in lifecycle_source
        and "KubeVirt v1.8.1 must be Deployed with ExpandDisks"
        in lifecycle_source,
        "management preflight fails closed without KubeVirt disk expansion",
    )
    expand_disks_test = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts" / "configure_kubevirt_expand_disks.py"),
            "--self-test",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    provider_infra = (
        ROOT
        / "templates"
        / "talos-mgmt"
        / "providers"
        / "kubevirt"
        / "provider-infra.sh.tpl"
    ).read_text(encoding="utf-8")
    check(
        expand_disks_test.returncode == 0
        and '--kubeconfig "$$INFRA_KUBECONFIG"' in provider_infra
        and "configure_kubevirt_expand_disks.py" in provider_infra,
        "management bootstrap converges ExpandDisks with a bounded helper",
    )

    secret_terms = (
        "BEGIN PRIVATE KEY",
        "client-certificate-data:",
        "client-key-data:",
        "talosconfig:",
        "token:",
        "password:",
    )
    changed_sources = [
        ROOT / "profile_resolvers" / "talos.py",
        ROOT / "scripts" / "talos_golden_lifecycle.py",
        ROOT
        / "templates"
        / "talos"
        / "providers"
        / "kubevirt"
        / "cluster-base.yaml.tpl",
        OK_LINUX
        / "scripts"
        / "adoption"
        / "OK-130"
        / "talos_golden_image.py",
    ]
    check(
        not any(
            term in path.read_text(encoding="utf-8")
            for path in changed_sources
            for term in secret_terms
        ),
        "OK-130 implementation contains no credential material",
    )

    failed = [message for condition, message in CHECKS if not condition]
    if failed:
        print(f"FAIL {len(failed)} OK-130 checks failed", file=sys.stderr)
        return 1
    print(f"PASS all {len(CHECKS)} OK-130 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
