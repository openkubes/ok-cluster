#!/usr/bin/env python3
"""Offline acceptance tests for the OK-130 Talos Golden-Image consumer."""

from __future__ import annotations

import copy
import json
import os
import shutil
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
    EXPECTED_PROVIDER_PROFILES,
    TalosProfileError,
    golden_claim,
    identity_material,
    provider_identity,
    resolve_talos_config,
)
from scripts.talos_golden_lifecycle import (  # noqa: E402
    TalosLifecycleError,
    cpu_millis,
    endpoint_collisions,
    longhorn_disk_schedulable_bytes,
    longhorn_runtime_state,
    pod_requests,
    quantity_bytes,
    requested_resources,
    replacement_data_volume_state,
    runtime_infrastructure_state,
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
    default_provider = EXPECTED_PROVIDER_PROFILES["profiles"]["ok-infra"]
    check(
        resolved["nodeSelector"] == "ok-infra"
        and resolved["providerProfile"]
        == {
            "name": "ok-infra",
            "identity": provider_identity("ok-infra", default_provider),
            "nodeSelector": "ok-infra",
            "cloneTargetStorageClass": "ok-storage-block",
            "replicaCount": 2,
            "snapshotClass": "ok-storage-block-snapshot",
        },
        "ordinary Talos defaults to the reviewed ok-infra provider profile",
    )
    single_raw = copy.deepcopy(raw)
    single_raw["providerProfile"] = {"name": "ok-gpu-single-replica"}
    single_raw["nodeSelector"] = "ok-gpu"
    single_raw["workers"]["replicas"] = 3
    single_raw["workers"]["disk"] = "30Gi"
    single = resolve_talos_config(single_raw, OK_LINUX)
    check(
        single["providerProfile"]["name"] == "ok-gpu-single-replica"
        and single["providerProfile"]["nodeSelector"] == "ok-gpu"
        and single["providerProfile"]["cloneTargetStorageClass"]
        == "ok-storage-block-gpu-test"
        and single["providerProfile"]["replicaCount"] == 1
        and single["os"]["identity"] == resolved["os"]["identity"],
        "development profile isolates single-replica GPU clones from the Golden identity",
    )
    unreviewed_node = copy.deepcopy(raw)
    unreviewed_node["nodeSelector"] = "another-node"
    expect_failure(
        unreviewed_node,
        "free-form Talos KubeVirt scheduling fails closed",
    )
    mismatched_gpu = copy.deepcopy(raw)
    mismatched_gpu["providerProfile"] = {"name": "ok-gpu"}
    expect_failure(
        mismatched_gpu,
        "provider profile and node selector must match",
    )
    storage_override = copy.deepcopy(raw)
    storage_override["providerProfile"] = {
        "name": "ok-infra",
        "cloneTargetStorageClass": "local-path",
    }
    expect_failure(
        storage_override,
        "consumer-side Talos storage overrides fail closed",
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

    gpu_raw = copy.deepcopy(raw)
    gpu_raw["providerProfile"] = {"name": "ok-gpu"}
    gpu_raw["nodeSelector"] = "ok-gpu"
    gpu_raw["controlPlane"].update(
        {"cores": 3, "memory": "6Gi", "disk": "20Gi"}
    )
    gpu_raw["workers"].update(
        {"cores": 4, "memory": "8Gi", "disk": "30Gi"}
    )
    gpu = resolve_talos_config(gpu_raw, OK_LINUX)
    with tempfile.TemporaryDirectory(prefix=".ok136-gpu-", dir=ROOT) as temp:
        output = Path(temp)
        render.render_cluster(gpu["name"], output, gpu)
        gpu_base = output / "cluster-base.yaml"
        gpu_docs = docs(gpu_base)
        gpu_templates = [
            item
            for item in gpu_docs
            if item.get("kind") == "KubevirtMachineTemplate"
        ]
        gpu_production_templates = [
            item
            for item in gpu_templates
            if "-v2-" not in item["metadata"]["name"]
        ]
        check(
            len(gpu_production_templates) == 2
            and all(
                item["metadata"]["annotations"][
                    "openkubes.io/provider-profile"
                ]
                == "ok-gpu"
                and item["metadata"]["name"].endswith(
                    gpu["providerProfile"]["identity"]
                    .removeprefix("sha256:")[:8]
                )
                for item in gpu_production_templates
            )
            and set(nested(gpu_docs, "storageClassName"))
            == {"ok-storage-block"}
            and set(nested(gpu_docs, "kubernetes.io/hostname"))
            == {"ok-gpu"},
            "ok-gpu renders provider-bound templates on production storage",
        )
        check(
            set(nested(gpu_docs, "cores")) >= {3, 4}
            and {"6Gi", "8Gi"}.issubset(set(nested(gpu_docs, "guest")))
            and {"20Gi", "30Gi"}.issubset(set(nested(gpu_docs, "storage"))),
            "ok-gpu preserves independent CP and worker resources",
        )
        validate_manifest(gpu, gpu_base)
        check(True, "ok-gpu lifecycle manifest guard accepts the render")

    with tempfile.TemporaryDirectory(
        prefix=".ok136-gpu-single-", dir=ROOT
    ) as temp:
        output = Path(temp)
        render.render_cluster(single["name"], output, single)
        single_base = output / "cluster-base.yaml"
        single_docs = docs(single_base)
        check(
            set(nested(single_docs, "storageClassName"))
            == {"ok-storage-block-gpu-test"}
            and set(nested(single_docs, "kubernetes.io/hostname"))
            == {"ok-gpu"}
            and {item["spec"]["replicas"] for item in single_docs if item.get("kind") == "MachineDeployment"}
            == {3},
            "single-replica GPU profile renders one CP and three workers on isolated storage",
        )
        validate_manifest(single, single_base)
        check(True, "single-replica GPU lifecycle manifest guard accepts the render")

    resource_bound = requested_resources(gpu)
    used_cpu, used_memory = pod_requests(
        [
            {
                "spec": {
                    "containers": [
                        {
                            "resources": {
                                "requests": {"cpu": "250m", "memory": "256Mi"}
                            }
                        }
                    ],
                    "overhead": {"cpu": "10m", "memory": "16Mi"},
                }
            }
        ]
    )
    check(
        resource_bound["cpu_millis"] == 7000
        and resource_bound["memory_bytes"] == 15 * 1024**3
        and resource_bound["storage_bytes_per_replica"] == 55 * 1024**3
        and used_cpu == 260
        and used_memory == 272 * 1024**2,
        "management capacity calculations are deterministic and bounded",
    )
    check(
        quantity_bytes("2048M") == 2_048_000_000
        and quantity_bytes("2Gi") == 2 * 1024**3
        and cpu_millis("250m") == 250
        and cpu_millis("500000u") == 500,
        "management capacity parser accepts Kubernetes decimal and binary quantities",
    )
    check(
        longhorn_disk_schedulable_bytes(
            {"storageReserved": 149_171_559_628},
            {
                "storageAvailable": 337_536_614_400,
                "storageMaximum": 497_238_532_096,
                "storageScheduled": 342_523_641_856,
            },
            15,
            100,
        )
        == 5_543_330_612,
        "management preflight honors Longhorn reserved and scheduled capacity",
    )
    check(
        endpoint_collisions(
            gpu,
            [
                {
                    "metadata": {"namespace": "ai-services", "name": "ollama"},
                    "status": {
                        "loadBalancer": {
                            "ingress": [{"ip": gpu["network"]["endpoint"]}]
                        }
                    },
                }
            ],
            [],
        )
        == ["Service ai-services/ollama"]
        and endpoint_collisions(gpu, [], []) == [],
        "management preflight detects live endpoint collisions",
    )
    golden_source = {
        "pvc": {
            "namespace": gpu["os"]["goldenImage"]["namespace"],
            "name": gpu["os"]["goldenImage"]["claim"],
        }
    }
    runtime_data_volumes = [
        {
            "metadata": {"name": f"gpu-{role}-disk", "uid": f"dv-{role}"},
            "spec": {
                "source": golden_source,
                "pvc": {"storageClassName": "ok-storage-block"},
            },
            "status": {"phase": "Succeeded"},
        }
        for role in ("cp", "worker")
    ]
    runtime_vmis = [
        {
            "metadata": {"name": f"gpu-{role}", "uid": f"vmi-{role}"},
            "status": {"phase": "Running", "nodeName": "ok-gpu"},
        }
        for role in ("cp", "worker")
    ]
    runtime_pvcs = [
        {
            "metadata": {"name": "gpu-cp-disk", "uid": "pvc-cp"},
            "spec": {
                "storageClassName": "ok-storage-block",
                "resources": {"requests": {"storage": "21Gi"}},
            },
            "status": {"phase": "Bound"},
        },
        {
            "metadata": {"name": "gpu-worker-disk", "uid": "pvc-worker"},
            "spec": {
                "storageClassName": "ok-storage-block",
                "resources": {"requests": {"storage": "32Gi"}},
            },
            "status": {"phase": "Bound"},
        },
    ]
    runtime_state = runtime_infrastructure_state(
        gpu, runtime_data_volumes, runtime_vmis, runtime_pvcs
    )
    check(
        {item["node"] for item in runtime_state["virtual_machine_instances"]}
        == {"ok-gpu"}
        and {item["role"] for item in runtime_state["persistent_volume_claims"]}
        == {"control-plane", "worker"},
        "runtime evidence binds VM placement and role-sized boot clones",
    )
    wrong_runtime_vmis = copy.deepcopy(runtime_vmis)
    wrong_runtime_vmis[0]["status"]["nodeName"] = "ok-infra"
    try:
        runtime_infrastructure_state(
            gpu, runtime_data_volumes, wrong_runtime_vmis, runtime_pvcs
        )
    except TalosLifecycleError:
        check(True, "runtime evidence rejects cross-profile VMI placement")
    else:
        check(False, "runtime evidence rejects cross-profile VMI placement")

    for index, item in enumerate(runtime_pvcs):
        item["spec"]["volumeName"] = f"pv-{index}"
    healthy_volumes = [
        {
            "metadata": {"name": f"pv-{index}"},
            "spec": {"numberOfReplicas": 2},
            "status": {"state": "attached", "robustness": "healthy"},
        }
        for index in range(2)
    ]
    healthy_replicas = [
        {
            "metadata": {
                "name": f"pv-{volume}-{node}",
                "labels": {"longhornvolume": f"pv-{volume}"},
            },
            "spec": {"nodeID": node, "desireState": "running"},
            "status": {"started": True},
        }
        for volume in range(2)
        for node in ("ok-gpu", "ok-infra")
    ]
    check(
        len(
            longhorn_runtime_state(
                gpu, runtime_pvcs, healthy_volumes, healthy_replicas
            )
        )
        == 2,
        "runtime evidence proves healthy replicas on distinct Longhorn nodes",
    )
    degraded_volumes = copy.deepcopy(healthy_volumes)
    degraded_volumes[0]["status"]["robustness"] = "degraded"
    try:
        longhorn_runtime_state(
            gpu, runtime_pvcs, degraded_volumes, healthy_replicas
        )
    except TalosLifecycleError:
        check(True, "runtime evidence rejects degraded Longhorn boot volumes")
    else:
        check(False, "runtime evidence rejects degraded Longhorn boot volumes")

    scaffold_name = "ok136-scaffold-test"
    scaffold_dir = ROOT / scaffold_name
    shutil.rmtree(scaffold_dir, ignore_errors=True)
    scaffold_env = {
        **os.environ,
        "INFRA_KUBECONFIG": "/private/tmp/ok136-no-management-kubeconfig",
        "OKB_KUBECONFIG": "/private/tmp/ok136-no-management-kubeconfig",
    }
    unsafe_scaffold = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "new",
            f"CLUSTER={scaffold_name}",
            "TYPE=talos",
            "NODE_SELECTOR=ok-gpu",
        ],
        cwd=ROOT,
        env=scaffold_env,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        unsafe_scaffold.returncode != 0
        and "SCHEDULING_PROFILE=ok-gpu"
        in (unsafe_scaffold.stdout + unsafe_scaffold.stderr),
        "ordinary scaffold rejects free-form ok-gpu placement",
    )
    try:
        reviewed_scaffold = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "new",
                f"CLUSTER={scaffold_name}",
                "TYPE=talos",
                "SCHEDULING_PROFILE=ok-gpu",
                "CP_CORES=3",
                "CP_MEMORY=6Gi",
                "CP_DISK=20Gi",
                "WORKER_CORES=4",
                "WORKER_MEMORY=8Gi",
                "WORKER_DISK=30Gi",
                "START_IP=192.168.100.254",
            ],
            cwd=ROOT,
            env=scaffold_env,
            capture_output=True,
            text=True,
            check=False,
        )
        scaffold = (
            load(scaffold_dir / "cluster-config.yaml")
            if reviewed_scaffold.returncode == 0
            else {}
        )
        check(
            reviewed_scaffold.returncode == 0
            and scaffold.get("providerProfile", {}).get("name") == "ok-gpu"
            and scaffold.get("nodeSelector") == "ok-gpu"
            and scaffold.get("controlPlane", {}).get("cores") == 3
            and scaffold.get("workers", {}).get("disk") == "30Gi",
            "reviewed ok-gpu scaffold materializes exact role resources",
        )
        shutil.rmtree(scaffold_dir, ignore_errors=True)
        single_scaffold = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "new",
                f"CLUSTER={scaffold_name}",
                "TYPE=talos",
                "SCHEDULING_PROFILE=ok-gpu-single-replica",
                "WORKERS=3",
                "CP_DISK=20Gi",
                "WORKER_DISK=30Gi",
                "START_IP=192.168.100.254",
            ],
            cwd=ROOT,
            env=scaffold_env,
            capture_output=True,
            text=True,
            check=False,
        )
        single_scaffold_config = (
            load(scaffold_dir / "cluster-config.yaml")
            if single_scaffold.returncode == 0
            else {}
        )
        check(
            single_scaffold.returncode == 0
            and single_scaffold_config.get("providerProfile", {}).get("name")
            == "ok-gpu-single-replica"
            and single_scaffold_config.get("nodeSelector") == "ok-gpu"
            and single_scaffold_config.get("workers", {}).get("replicas") == 3
            and single_scaffold_config.get("providerProfile", {}).get(
                "cloneTargetStorageClass"
            )
            == "ok-storage-block-gpu-test",
            "single-replica GPU scaffold materializes one CP and three workers",
        )
    finally:
        shutil.rmtree(scaffold_dir, ignore_errors=True)

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
        'config["providerProfile"]["nodeSelector"]' in lifecycle_source
        and "capacity is insufficient" in lifecycle_source
        and "Longhorn capacity/placement is insufficient" in lifecycle_source,
        "management preflight verifies profile-bound compute and storage",
    )
    check(
        "require_create_capacity: bool = True" in lifecycle_source
        and "require_create_capacity=False" in lifecycle_source,
        "runtime evidence does not require capacity for a duplicate cluster",
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
