#!/usr/bin/env python3
"""Offline acceptance tests for the OK-130 Talos Golden-Image consumer."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

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
from scripts.talos_golden_lifecycle import (  # noqa: E402
    TalosLifecycleError,
    replacement_data_volume_state,
    validate_manifest,
)
from scripts import talos_replacement_runtime  # noqa: E402
from scripts.talos_replacement_runtime import (  # noqa: E402
    ReplacementError,
    verify_timeline,
)


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
    demo_raw = copy.deepcopy(raw)
    demo_raw["demoProfile"] = "gpu-single-replica"
    demo_raw["nodeSelector"] = "ok-gpu"
    demo_raw["providerProfile"] = {
        "cloneTargetStorageClass": "ok-storage-block-gpu-test"
    }
    demo_raw["controlPlane"]["disk"] = "20Gi"
    demo_raw["workers"]["disk"] = "30Gi"
    demo_resolved = resolve_talos_config(demo_raw, OK_LINUX)
    wrong_demo_node = copy.deepcopy(demo_raw)
    wrong_demo_node["nodeSelector"] = "ok-infra"
    expect_failure(
        wrong_demo_node,
        "Talos GPU demo rejects a non-GPU scheduling target",
    )
    wrong_demo_disk = copy.deepcopy(demo_raw)
    wrong_demo_disk["workers"]["disk"] = "50Gi"
    expect_failure(
        wrong_demo_disk,
        "Talos GPU demo rejects a non-profile disk size",
    )
    unscoped_storage = copy.deepcopy(raw)
    unscoped_storage["providerProfile"] = {
        "cloneTargetStorageClass": "ok-storage-block-gpu-test"
    }
    expect_failure(
        unscoped_storage,
        "Talos GPU test storage requires an explicit demo profile",
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

        templates = {
            item["kind"]: (
                item["spec"]["infrastructureTemplate"]["name"]
                if item["kind"] == "TalosControlPlane"
                else item["spec"]["template"]["spec"]["infrastructureRef"][
                    "name"
                ]
            )
            for item in resources
            if item["kind"] in {"TalosControlPlane", "MachineDeployment"}
        }
        infrastructure_machines = [
            {
                "metadata": {
                    "name": "current-cp",
                    "uid": "current-cp-infra-uid",
                    "annotations": {
                        "cluster.x-k8s.io/cloned-from-name": templates[
                            "TalosControlPlane"
                        ]
                    },
                }
            },
            {
                "metadata": {
                    "name": "current-worker",
                    "uid": "current-worker-infra-uid",
                    "annotations": {
                        "cluster.x-k8s.io/cloned-from-name": templates[
                            "MachineDeployment"
                        ]
                    },
                }
            },
        ]
        expected_source = {
            "pvc": {
                "namespace": resolved["os"]["goldenImage"]["namespace"],
                "name": resolved["os"]["goldenImage"]["claim"],
            }
        }
        replacement_virtual_machines = [
            {
                "metadata": {
                    "name": owner,
                    "uid": f"{owner}-vm-uid",
                }
            }
            for owner in ("current-cp", "current-worker")
        ]
        replacement_data_volumes = [
            {
                "metadata": {
                    "name": f"{owner}-disk",
                    "uid": f"{owner}-uid",
                    "ownerReferences": [
                        {
                            "kind": "VirtualMachine",
                            "name": owner,
                            "uid": f"{owner}-vm-uid",
                        }
                    ],
                },
                "spec": {"source": expected_source},
                "status": {"phase": "Succeeded"},
            }
            for owner in ("current-cp", "current-worker")
        ]
        replacement_data_volumes.append(
            {
                "metadata": {
                    "name": "stale-disk",
                    "uid": "stale-uid",
                    "ownerReferences": [
                        {
                            "kind": "VirtualMachine",
                            "name": "deleted-machine",
                            "uid": "deleted-machine-vm-uid",
                        }
                    ],
                },
                "spec": {"source": expected_source},
                "status": {"phase": "Succeeded"},
            }
        )
        volume_state = replacement_data_volume_state(
            resolved,
            base,
            infrastructure_machines,
            replacement_virtual_machines,
            replacement_data_volumes,
        )
        check(
            volume_state["ready"]
            and volume_state["data_volume_uids"]
            == ["current-cp-uid", "current-worker-uid"],
            "replacement wait ignores stale DVs and binds exact VM owners",
        )
        try:
            replacement_data_volume_state(
                resolved,
                base,
                [
                    *infrastructure_machines,
                    copy.deepcopy(infrastructure_machines[0]),
                ],
                replacement_virtual_machines,
                replacement_data_volumes,
            )
        except TalosLifecycleError:
            check(
                True,
                "replacement wait rejects excess current-template machines",
            )
        else:
            check(
                False,
                "replacement wait rejects excess current-template machines",
            )

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
    with tempfile.TemporaryDirectory(
        prefix=".ok130-gpu-demo-", dir=ROOT
    ) as temp:
        output = Path(temp)
        render.render_cluster(demo_resolved["name"], output, demo_resolved)
        manifest = output / "cluster-base.yaml"
        validate_manifest(demo_resolved, manifest)
        resources = docs(manifest)
        machine_templates = [
            item
            for item in resources
            if item["kind"] == "KubevirtMachineTemplate"
        ]
        clone_storage = [
            data_volume["spec"]["pvc"]["storageClassName"]
            for item in machine_templates
            for data_volume in item["spec"]["template"]["spec"][
                "virtualMachineTemplate"
            ]["spec"]["dataVolumeTemplates"]
        ]
        clone_sizes = [
            data_volume["spec"]["pvc"]["resources"]["requests"]["storage"]
            for item in machine_templates
            for data_volume in item["spec"]["template"]["spec"][
                "virtualMachineTemplate"
            ]["spec"]["dataVolumeTemplates"]
        ]
        scheduling = [
            item["spec"]["template"]["spec"]["virtualMachineTemplate"][
                "spec"
            ]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"]
            for item in machine_templates
        ]
        check(
            demo_resolved["os"]["goldenImage"]["storageClass"]
            == "ok-storage-block"
            and clone_storage
            == ["ok-storage-block-gpu-test", "ok-storage-block-gpu-test"]
            and clone_sizes == ["20Gi", "30Gi"]
            and scheduling == ["ok-gpu", "ok-gpu"],
            "Talos GPU demo renders isolated 20Gi CP and 30Gi worker clones",
        )

    replacement_proof = verify_timeline(
        replacement_timeline, "v1.9.5", "v1.9.6", "7f5dd4276432"
    )
    check(
        replacement_proof["control_plane_ready_in_every_observation"]
        and replacement_proof["role_replacement_ready_before_old_absent"],
        "replacement observer proves role-safe Talos blue-green convergence",
    )
    interrupted_proof = verify_timeline(
        replacement_timeline,
        "v1.9.5",
        "v1.9.6",
        "7f5dd4276432",
        [{"duration_seconds": 2.0}],
    )
    check(
        interrupted_proof["workload_api_continuously_observed"] is False
        and interrupted_proof[
            "role_replacement_ready_before_old_absent"
        ]
        is None,
        "API-blind windows make role-safe replacement ordering unknown",
    )

    class FakeProcess:
        returncode = None
        terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    with tempfile.TemporaryDirectory(prefix=".ok130-failure-", dir=ROOT) as temp:
        temp_path = Path(temp)
        management = temp_path / "management.yaml"
        workload = temp_path / "workload.yaml"
        output = temp_path / "failure.json"
        management.write_text("management", encoding="utf-8")
        workload.write_text("workload", encoding="utf-8")
        fake_process = FakeProcess()
        initial = copy.deepcopy(replacement_timeline[0])
        initial["machines"] = []
        initial["observed_at"] = "2026-07-30T00:00:00Z"
        argv = [
            "talos_replacement_runtime.py",
            "--cluster",
            "ok130-test",
            "--management-kubeconfig",
            str(management),
            "--workload-kubeconfig",
            str(workload),
            "--old-version",
            "v1.9.5",
            "--new-version",
            "v1.9.6",
            "--new-identity-short",
            "7f5dd4276432",
            "--output",
            str(output),
            "--",
            "fake-lifecycle",
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(
                talos_replacement_runtime,
                "snapshot",
                side_effect=[
                    initial,
                    ReplacementError("management API read failed: boom"),
                ],
            ),
            mock.patch.object(
                talos_replacement_runtime.subprocess,
                "Popen",
                return_value=fake_process,
            ),
        ):
            try:
                talos_replacement_runtime.main()
            except ReplacementError:
                pass
            else:
                check(False, "replacement failure propagates to the caller")
        failed_evidence = json.loads(output.read_text(encoding="utf-8"))
        check(
            fake_process.terminated
            and failed_evidence["status"] == "FAIL"
            and failed_evidence["lifecycle_terminated"] is True
            and "management API read failed" in failed_evidence["failure"],
            "replacement failures terminate lifecycle and persist evidence",
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
    makefile_source = (ROOT / "Makefile").read_text(encoding="utf-8")
    replacement_target = makefile_source.split(
        "talos-golden-replacement-apply:", 1
    )[1].split("\n# ", 1)[0]
    check(
        'kubectl --kubeconfig "$(TALOS_INFRA_KUBECONFIG)" apply'
        in replacement_target
        and "$(OKB)" not in replacement_target
        and "--replacement-wait" in replacement_target,
        "replacement mutation is bound to the preflighted kubeconfig",
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
        'expected_node = config.get("nodeSelector") or "ok-infra"'
        in lifecycle_source
        and "verify_clone_storage(config, kubeconfig)" in lifecycle_source,
        "management preflight verifies the profile-bound node and clone storage",
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
