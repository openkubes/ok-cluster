#!/usr/bin/env python3
"""Guard the OK-130 Talos Golden-Image consumer lifecycle."""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "adoption" / "OK-130" / ".evidence"
TEARDOWN_LEDGER_NAMESPACE = "kube-system"
TEARDOWN_LEDGER_PREFIX = "ok-cluster-teardown-"
TEARDOWN_LEDGER_SCHEMA = 1
SPLIT_TEARDOWN_LEDGER_SCHEMA = 2
sys.path.insert(0, str(ROOT))

from profile_resolvers.talos import (  # noqa: E402
    EXPECTED_PROVIDER_PROFILES,
    TalosProfileError,
    resolve_talos_config,
)
from scripts.prepare_cilium_chart import (  # noqa: E402
    ChartAcquisitionError,
    EXPECTED_SHA256 as CILIUM_CHART_SHA256,
    verify as verify_cilium_chart,
)


class TalosLifecycleError(RuntimeError):
    """A Talos Golden-Image lifecycle precondition is not satisfied."""


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise TalosLifecycleError(f"expected YAML mapping: {path}")
    return value


def objects(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [value for value in yaml.safe_load_all(stream) if value]


def run(
    command: list[str],
    expected: tuple[int, ...] = (0,),
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        input=input_text,
    )
    if result.returncode not in expected:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TalosLifecycleError(
            f"{' '.join(command[:5])} exited {result.returncode}: {detail}"
        )
    return result


def kubectl(
    kubeconfig: Path,
    arguments: list[str],
    expected: tuple[int, ...] = (0,),
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["kubectl", "--kubeconfig", str(kubeconfig), *arguments],
        expected,
        input_text,
    )


def kubectl_not_found(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0:
        return False
    lines = {line.strip() for line in result.stderr.splitlines() if line.strip()}
    return "NotFound" in lines or any(
        line.startswith("Error from server (NotFound):") for line in lines
    )


def kubectl_json(kubeconfig: Path, arguments: list[str]) -> dict:
    return json.loads(
        kubectl(kubeconfig, [*arguments, "-o", "json"]).stdout
    )


def inputs(args: argparse.Namespace) -> tuple[dict, Path, Path]:
    if not args.cluster:
        raise TalosLifecycleError("--cluster is required")
    cluster_dir = cluster_directory(args)
    config_path = cluster_dir / "cluster-config.yaml"
    manifest_path = cluster_dir / "cluster-base.yaml"
    if not config_path.is_file() or not manifest_path.is_file():
        raise TalosLifecycleError("rendered Talos config/manifest is absent")
    ok_linux = Path(args.ok_linux_path).expanduser().resolve()
    config = load_yaml(config_path)
    resolved = resolve_talos_config(config, ok_linux)
    if resolved != config:
        raise TalosLifecycleError(
            "cluster config is not fully materialized; run make render"
        )
    kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    if not kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit management kubeconfig is absent: {kubeconfig}"
        )
    return config, manifest_path, kubeconfig


def cluster_directory(args: argparse.Namespace) -> Path:
    value = getattr(args, "cluster_dir", None)
    if value:
        cluster_dir = Path(value).expanduser().resolve()
        if cluster_dir.name != args.cluster:
            raise TalosLifecycleError(
                "--cluster-dir basename must match --cluster"
            )
        return cluster_dir
    clusters_dir = Path(getattr(args, "clusters_dir", ROOT)).expanduser().resolve()
    return clusters_dir / args.cluster


def contains_secret_resource(document: dict) -> bool:
    """Inspect Kubernetes objects, not nested references such as SecretRef.kind."""
    if not isinstance(document, dict):
        raise TalosLifecycleError("Talos manifest resource must be a mapping")
    if document.get("kind") in ("Secret", "SecretList"):
        return True
    if document.get("kind") == "List":
        items = document.get("items", [])
        if not isinstance(items, list):
            raise TalosLifecycleError("Talos manifest List.items must be a list")
        return any(contains_secret_resource(item) for item in items)
    return False


def validate_manifest(config: dict, manifest_path: Path) -> None:
    docs = objects(manifest_path)
    text = manifest_path.read_text(encoding="utf-8")
    if (
        "${" in text
        or "source:\n                http:" in text
        or "source:\n                      registry:" in text
        or "factory.talos.dev/image/" in text
        or any(contains_secret_resource(document) for document in docs)
        or "PRIVATE KEY" in text
    ):
        raise TalosLifecycleError(
            "Talos manifest contains unresolved, remote, or secret input"
        )
    role = [item for item in docs if item.get("kind") == "Role"]
    binding = [item for item in docs if item.get("kind") == "RoleBinding"]
    golden = config["os"]["goldenImage"]
    expected_name = f"{config['name']}-talos-golden-image-cloner"
    if (
        len(role) != 1
        or role[0]["metadata"]["name"] != expected_name
        or role[0]["metadata"]["namespace"] != golden["namespace"]
        or role[0]["rules"]
        != [
            {
                "apiGroups": ["cdi.kubevirt.io"],
                "resources": ["datavolumes/source"],
                "verbs": ["create"],
            }
        ]
        or len(binding) != 1
        or binding[0]["subjects"]
        != [
            {
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": config["name"],
            }
        ]
    ):
        raise TalosLifecycleError("clone authorization is not least privilege")
    provider = config["providerProfile"]
    machine_templates = [
        item for item in docs if item.get("kind") == "KubevirtMachineTemplate"
    ]
    node_selectors = [
        item.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("virtualMachineTemplate", {})
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("nodeSelector", {})
        .get("kubernetes.io/hostname")
        for item in machine_templates
        if "-v2-" not in item.get("metadata", {}).get("name", "")
    ]
    storage_classes = [
        data_volume.get("spec", {})
        .get("pvc", {})
        .get("storageClassName")
        for item in machine_templates
        if "-v2-" not in item.get("metadata", {}).get("name", "")
        for data_volume in item.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("virtualMachineTemplate", {})
        .get("spec", {})
        .get("dataVolumeTemplates", [])
    ]
    if (
        len(node_selectors) != 2
        or set(node_selectors) != {provider["nodeSelector"]}
        or len(storage_classes) != 2
        or set(storage_classes) != {provider["cloneTargetStorageClass"]}
        or any(
            item.get("metadata", {}).get("annotations", {}).get(
                "openkubes.io/provider-profile"
            )
            != provider["name"]
            or item.get("metadata", {}).get("annotations", {}).get(
                "openkubes.io/provider-profile-identity"
            )
            != provider["identity"]
            for item in machine_templates
            if "-v2-" not in item.get("metadata", {}).get("name", "")
        )
    ):
        raise TalosLifecycleError(
            "Talos machine templates differ from the reviewed provider profile"
        )


def verify_golden(config: dict, kubeconfig: Path) -> dict:
    golden = config["os"]["goldenImage"]
    pvc = kubectl_json(
        kubeconfig,
        ["-n", golden["namespace"], "get", "pvc", golden["claim"]],
    )
    annotations = pvc["metadata"].get("annotations", {})
    if (
        pvc.get("status", {}).get("phase") != "Bound"
        or pvc.get("spec", {}).get("storageClassName") != "ok-storage-block"
        or annotations.get("ok-linux.openkubes.io/image-sha256")
        != config["os"]["imageDigest"]
        or annotations.get("ok-linux.openkubes.io/os-identity")
        != config["os"]["identity"]
    ):
        raise TalosLifecycleError("Talos Golden PVC identity is invalid")
    return {
        "uid": pvc["metadata"]["uid"],
        "digest": annotations["ok-linux.openkubes.io/image-sha256"],
        "identity": annotations["ok-linux.openkubes.io/os-identity"],
    }


def quantity_bytes(value: str) -> int:
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|Ti|Pi|Ei|k|K|M|G|T|P|E)?",
        str(value),
    )
    if not match:
        raise TalosLifecycleError(f"unsupported storage/memory quantity: {value}")
    try:
        number = Decimal(match.group(1))
    except InvalidOperation as error:
        raise TalosLifecycleError(
            f"unsupported storage/memory quantity: {value}"
        ) from error
    suffix = match.group(2)
    binary_power = {
        "Ki": 1,
        "Mi": 2,
        "Gi": 3,
        "Ti": 4,
        "Pi": 5,
        "Ei": 6,
    }.get(suffix)
    if binary_power is not None:
        return int(number * (1024**binary_power))
    decimal_power = {
        None: 0,
        "k": 1,
        "K": 1,
        "M": 2,
        "G": 3,
        "T": 4,
        "P": 5,
        "E": 6,
    }[suffix]
    return int(number * (1000**decimal_power))


def cpu_millis(value: str | int | float) -> int:
    text = str(value)
    suffix_scale = {"n": Decimal("0.000001"), "u": Decimal("0.001"), "m": Decimal(1)}
    if text[-1:] in suffix_scale:
        return int(Decimal(text[:-1]) * suffix_scale[text[-1]])
    return int(Decimal(text) * 1000)


def requested_resources(config: dict) -> dict:
    cp = config["controlPlane"]
    workers = config["workers"]
    machines = int(cp["replicas"]) + int(workers["replicas"])
    return {
        "cpu_millis": (
            int(cp["replicas"]) * int(cp["cores"])
            + int(workers["replicas"]) * int(workers["cores"])
        )
        * 1000,
        "memory_bytes": (
            int(cp["replicas"]) * quantity_bytes(cp["memory"])
            + int(workers["replicas"]) * quantity_bytes(workers["memory"])
            + machines * quantity_bytes("512Mi")
        ),
        "storage_bytes_per_replica": (
            (
                int(cp["replicas"]) * quantity_bytes(cp["disk"])
                + int(workers["replicas"]) * quantity_bytes(workers["disk"])
            )
            * 110
            + 99
        )
        // 100,
    }


def longhorn_disk_schedulable_bytes(
    disk_spec: dict,
    disk_status: dict,
    minimum_available_percentage: int,
    over_provisioning_percentage: int,
) -> int:
    """Return the conservative Longhorn scheduler budget for one disk."""
    maximum = int(disk_status.get("storageMaximum", 0))
    available = int(disk_status.get("storageAvailable", 0))
    scheduled = int(disk_status.get("storageScheduled", 0))
    reserved = int(disk_spec.get("storageReserved", 0))
    physical_budget = available - (
        maximum * minimum_available_percentage // 100
    )
    scheduled_budget = (
        (maximum - reserved) * over_provisioning_percentage // 100
    ) - scheduled
    return max(0, min(physical_budget, scheduled_budget))


def pod_requests(pods: list[dict]) -> tuple[int, int]:
    cpu = 0
    memory = 0
    for pod in pods:
        containers = pod.get("spec", {}).get("containers", [])
        init_containers = pod.get("spec", {}).get("initContainers", [])
        regular_cpu = sum(
            cpu_millis(item.get("resources", {}).get("requests", {}).get("cpu", 0))
            for item in containers
        )
        regular_memory = sum(
            quantity_bytes(
                item.get("resources", {}).get("requests", {}).get("memory", "0")
            )
            for item in containers
        )
        init_cpu = max(
            [
                cpu_millis(item.get("resources", {}).get("requests", {}).get("cpu", 0))
                for item in init_containers
            ]
            or [0]
        )
        init_memory = max(
            [
                quantity_bytes(
                    item.get("resources", {}).get("requests", {}).get("memory", "0")
                )
                for item in init_containers
            ]
            or [0]
        )
        overhead = pod.get("spec", {}).get("overhead", {})
        cpu += max(regular_cpu, init_cpu) + cpu_millis(overhead.get("cpu", 0))
        memory += max(regular_memory, init_memory) + quantity_bytes(
            overhead.get("memory", "0")
        )
    return cpu, memory


def verify_scheduling(
    config: dict, kubeconfig: Path, *, require_create_capacity: bool = True
) -> dict:
    expected_node = config["providerProfile"]["nodeSelector"]
    node = kubectl_json(kubeconfig, ["get", "node", expected_node])
    ready = next(
        (
            condition
            for condition in node.get("status", {}).get("conditions", [])
            if condition.get("type") == "Ready"
        ),
        None,
    )
    if (
        node.get("spec", {}).get("unschedulable", False)
        or ready is None
        or ready.get("status") != "True"
    ):
        raise TalosLifecycleError(
            f"{expected_node} is not Ready and schedulable"
        )
    requests = requested_resources(config)
    pods = kubectl_json(
        kubeconfig,
        ["get", "pods", "-A", "--field-selector", f"spec.nodeName={expected_node}"],
    ).get("items", [])
    used_cpu, used_memory = pod_requests(pods)
    allocatable = node.get("status", {}).get("allocatable", {})
    available_cpu = cpu_millis(allocatable.get("cpu", 0)) - used_cpu
    available_memory = quantity_bytes(allocatable.get("memory", "0")) - used_memory
    if require_create_capacity and (
        available_cpu < requests["cpu_millis"]
        or available_memory < requests["memory_bytes"]
    ):
        raise TalosLifecycleError(
            f"{expected_node} capacity is insufficient: "
            f"cpu requested={requests['cpu_millis']}m available={available_cpu}m, "
            f"memory requested={requests['memory_bytes']}B "
            f"available={available_memory}B"
        )
    return {
        "name": node["metadata"]["name"],
        "uid": node["metadata"]["uid"],
        "ready": True,
        "schedulable": True,
        "available_cpu_millis": available_cpu,
        "requested_cpu_millis": requests["cpu_millis"],
        "available_memory_bytes": available_memory,
        "requested_memory_bytes": requests["memory_bytes"],
        "create_capacity_required": require_create_capacity,
    }


def verify_clone_storage(config: dict, kubeconfig: Path) -> dict:
    provider = config["providerProfile"]
    expected = EXPECTED_PROVIDER_PROFILES["profiles"][provider["name"]][
        "clone_target"
    ]
    storage = kubectl_json(
        kubeconfig, ["get", "storageclass", provider["cloneTargetStorageClass"]]
    )
    parameters = storage.get("parameters", {})
    observed = {
        "provisioner": storage.get("provisioner"),
        "replica_count": int(parameters.get("numberOfReplicas", "0")),
        "reclaim_policy": storage.get("reclaimPolicy"),
        "volume_binding_mode": storage.get("volumeBindingMode"),
        "allow_volume_expansion": storage.get("allowVolumeExpansion"),
    }
    required = {key: expected[key] for key in observed}
    if (
        observed != required
        or parameters.get("nodeSelector", "")
        != expected.get("node_tag", "")
    ):
        raise TalosLifecycleError(
            f"clone-target StorageClass contract mismatch: {observed}"
        )
    snapshot = kubectl_json(
        kubeconfig,
        ["get", "volumesnapshotclass", expected["snapshot_class"]],
    )
    if (
        snapshot.get("driver") != expected["provisioner"]
        or snapshot.get("deletionPolicy") != "Delete"
        or snapshot.get("parameters") != {"type": expected["snapshot_type"]}
    ):
        raise TalosLifecycleError("Longhorn snapshot clone class is invalid")
    storage_profile = kubectl_json(
        kubeconfig,
        [
            "get",
            "storageprofile.cdi.kubevirt.io",
            expected["storage_class"],
        ],
    ).get("status", {})
    if (
        storage_profile.get("provisioner") != expected["provisioner"]
        or storage_profile.get("storageClass") != expected["storage_class"]
        or storage_profile.get("snapshotClass") != expected["snapshot_class"]
        or storage_profile.get("cloneStrategy") != "snapshot"
    ):
        raise TalosLifecycleError("CDI clone strategy differs from the contract")
    longhorn_nodes = kubectl_json(
        kubeconfig, ["-n", "longhorn-system", "get", "nodes.longhorn.io"]
    ).get("items", [])
    minimum_available_percentage = int(
        kubectl_json(
            kubeconfig,
            [
                "-n",
                "longhorn-system",
                "get",
                "settings.longhorn.io",
                "storage-minimal-available-percentage",
            ],
        ).get("value", "")
    )
    over_provisioning_percentage = int(
        kubectl_json(
            kubeconfig,
            [
                "-n",
                "longhorn-system",
                "get",
                "settings.longhorn.io",
                "storage-over-provisioning-percentage",
            ],
        ).get("value", "")
    )
    needed = requested_resources(config)["storage_bytes_per_replica"]
    eligible = []
    for item in longhorn_nodes:
        ready = next(
            (
                condition
                for condition in item.get("status", {}).get("conditions", [])
                if condition.get("type") == "Ready"
            ),
            None,
        )
        schedulable = sum(
            longhorn_disk_schedulable_bytes(
                item.get("spec", {}).get("disks", {}).get(disk_name, {}),
                status,
                minimum_available_percentage,
                over_provisioning_percentage,
            )
            for disk_name, status in item.get("status", {}).get("diskStatus", {}).items()
            if item.get("spec", {}).get("disks", {}).get(disk_name, {}).get(
                "allowScheduling"
            )
            is True
        )
        if (
            item.get("spec", {}).get("allowScheduling") is True
            and ready is not None
            and ready.get("status") == "True"
            and schedulable >= needed
        ):
            eligible.append(
                {
                    "name": item["metadata"]["name"],
                    "schedulable_bytes": schedulable,
                }
            )
    if (
        len(eligible) < expected["replica_count"]
        or provider["nodeSelector"] not in {item["name"] for item in eligible}
    ):
        raise TalosLifecycleError(
            "Longhorn capacity/placement is insufficient: "
            f"requested_per_replica={needed}B eligible={eligible}"
        )
    return {
        "storage_class": expected["storage_class"],
        "replica_count": expected["replica_count"],
        "requested_bytes_per_replica": needed,
        "eligible_nodes": eligible,
        "minimum_available_percentage": minimum_available_percentage,
        "over_provisioning_percentage": over_provisioning_percentage,
        "snapshot_clone": True,
    }


def verify_kubevirt(kubeconfig: Path) -> dict:
    items = kubectl_json(
        kubeconfig, ["get", "kubevirt.kubevirt.io", "-A"]
    ).get("items", [])
    if len(items) != 1:
        raise TalosLifecycleError(
            f"expected one KubeVirt installation, observed {len(items)}"
        )
    item = items[0]
    status = item.get("status", {})
    gates = (
        item.get("spec", {})
        .get("configuration", {})
        .get("developerConfiguration", {})
        .get("featureGates")
        or []
    )
    if not isinstance(gates, list):
        raise TalosLifecycleError(
            "infrastructure KubeVirt featureGates must be a list"
        )
    if (
        status.get("phase") != "Deployed"
        or status.get("observedKubeVirtVersion") != "v1.8.1"
        or status.get("targetKubeVirtVersion") != "v1.8.1"
        or "ExpandDisks" not in gates
    ):
        raise TalosLifecycleError(
            "infrastructure KubeVirt v1.8.1 must be Deployed with ExpandDisks"
        )
    return {
        "namespace": item["metadata"]["namespace"],
        "name": item["metadata"]["name"],
        "version": "v1.8.1",
        "expand_disks": True,
    }


def endpoint_collisions(
    config: dict, services: list[dict], clusters: list[dict]
) -> list[str]:
    endpoint = config["network"]["endpoint"]
    collisions = []
    for item in services:
        metadata = item.get("metadata", {})
        if metadata.get("namespace") == config["name"]:
            continue
        addresses = {
            item.get("spec", {}).get("loadBalancerIP"),
            *[
                ingress.get("ip")
                for ingress in (
                    item.get("status", {})
                    .get("loadBalancer", {})
                    .get("ingress", [])
                    or []
                )
            ],
        }
        if endpoint in addresses:
            collisions.append(
                f"Service {metadata.get('namespace')}/{metadata.get('name')}"
            )
    for item in clusters:
        metadata = item.get("metadata", {})
        if metadata.get("name") == config["name"]:
            continue
        observed = (
            item.get("spec", {}).get("controlPlaneEndpoint", {}).get("host")
        )
        if observed == endpoint:
            collisions.append(
                f"Cluster {metadata.get('namespace')}/{metadata.get('name')}"
            )
    return sorted(collisions)


def verify_endpoint_available(config: dict, kubeconfig: Path) -> dict:
    services = kubectl_json(kubeconfig, ["get", "services", "-A"]).get(
        "items", []
    )
    clusters = kubectl_json(kubeconfig, ["get", "clusters", "-A"]).get(
        "items", []
    )
    collisions = endpoint_collisions(config, services, clusters)
    if collisions:
        raise TalosLifecycleError(
            f"endpoint {config['network']['endpoint']} is already used by "
            + ", ".join(collisions)
        )
    return {"endpoint": config["network"]["endpoint"], "available": True}


def true_condition(resource: dict, *types: str) -> dict | None:
    status = resource.get("status", {})
    condition_sets = [status.get("conditions", [])]
    if isinstance(status.get("v1beta2"), dict):
        condition_sets.append(status["v1beta2"].get("conditions", []))
    return next(
        (
            condition
            for conditions in condition_sets
            for condition in conditions
            if condition.get("type") in types
            and condition.get("status") == "True"
        ),
        None,
    )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _replicas(resource: dict, description: str, *, positive: bool) -> int:
    value = resource.get("spec", {}).get("replicas")
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < (1 if positive else 0)
    ):
        qualifier = "positive" if positive else "non-negative"
        raise TalosLifecycleError(
            f"rendered {description} spec.replicas must be a {qualifier} integer"
        )
    return value


def expected_node_roles(
    manifest_path: Path, cluster_name: str
) -> tuple[str, list[dict]]:
    """Return the exact rendered CAPI namespace and expected node roles."""
    docs = objects(manifest_path)
    clusters = [
        item
        for item in docs
        if item.get("kind") == "Cluster"
        and item.get("metadata", {}).get("name") == cluster_name
    ]
    if len(clusters) != 1:
        raise TalosLifecycleError(
            f"expected one rendered Cluster named {cluster_name}, observed {len(clusters)}"
        )
    cluster = clusters[0]
    namespace = cluster.get("metadata", {}).get("namespace")
    if not isinstance(namespace, str) or not namespace:
        raise TalosLifecycleError(
            f"rendered Cluster {cluster_name} has no namespace"
        )

    reference = cluster.get("spec", {}).get("controlPlaneRef")
    if not isinstance(reference, dict):
        raise TalosLifecycleError(
            f"rendered Cluster {namespace}/{cluster_name} has no controlPlaneRef"
        )
    reference_namespace = reference.get("namespace", namespace)
    if (
        reference.get("apiGroup") != "controlplane.cluster.x-k8s.io"
        or reference.get("kind") != "TalosControlPlane"
        or not isinstance(reference.get("name"), str)
        or not reference["name"]
        or reference_namespace != namespace
    ):
        raise TalosLifecycleError(
            f"rendered Cluster {namespace}/{cluster_name} has an invalid "
            "TalosControlPlane reference"
        )
    control_planes = [
        item
        for item in docs
        if item.get("kind") == "TalosControlPlane"
        and item.get("metadata", {}).get("name") == reference["name"]
        and item.get("metadata", {}).get("namespace") == namespace
    ]
    if len(control_planes) != 1:
        raise TalosLifecycleError(
            "rendered Cluster controlPlaneRef does not resolve to exactly one "
            f"TalosControlPlane in namespace {namespace}"
        )

    matching_deployments = [
        item
        for item in docs
        if item.get("kind") == "MachineDeployment"
        and item.get("spec", {}).get("clusterName") == cluster_name
    ]
    wrong_namespaces = sorted(
        f"{item.get('metadata', {}).get('namespace', '<missing>')}/"
        f"{item.get('metadata', {}).get('name', '<missing>')}"
        for item in matching_deployments
        if item.get("metadata", {}).get("namespace") != namespace
    )
    if wrong_namespaces:
        raise TalosLifecycleError(
            "rendered MachineDeployments matching the Cluster have invalid "
            f"namespaces: {wrong_namespaces}"
        )

    roles = [
        {
            "name": "control-plane",
            "expected": _replicas(
                control_planes[0],
                f"TalosControlPlane {namespace}/{reference['name']}",
                positive=True,
            ),
            "machine_deployment": None,
        }
    ]
    deployment_names: set[str] = set()
    for deployment in matching_deployments:
        name = deployment.get("metadata", {}).get("name")
        if not isinstance(name, str) or not name or name in deployment_names:
            raise TalosLifecycleError(
                "rendered MachineDeployment names must be present and unique"
            )
        deployment_names.add(name)
        roles.append(
            {
                "name": f"worker/{name}",
                "expected": _replicas(
                    deployment,
                    f"MachineDeployment {namespace}/{name}",
                    positive=False,
                ),
                "machine_deployment": name,
            }
        )
    return namespace, roles


def _machine_exclusion(machine: dict) -> str | None:
    metadata = machine.get("metadata", {})
    status = machine.get("status", {})
    if not isinstance(metadata, dict) or not isinstance(status, dict):
        return "invalid"
    if metadata.get("deletionTimestamp"):
        return "deleting"
    deprecated = status.get("deprecated")
    if not isinstance(deprecated, dict):
        deprecated = {}
    v1beta1 = deprecated.get("v1beta1")
    if not isinstance(v1beta1, dict):
        v1beta1 = {}
    if (
        status.get("phase") == "Failed"
        or status.get("failureReason")
        or status.get("failureMessage")
        or v1beta1.get("failureReason")
        or v1beta1.get("failureMessage")
    ):
        return "failed"
    return None


def _ready_node(node: dict) -> bool:
    metadata = node.get("metadata", {})
    status = node.get("status", {})
    if not isinstance(metadata, dict) or not isinstance(status, dict):
        return False
    if metadata.get("deletionTimestamp"):
        return False
    conditions = status.get("conditions", [])
    if not isinstance(conditions, list):
        return False
    return any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") == "True"
        for condition in conditions
    )


def _diagnostic_list(values: list[str]) -> str:
    return "[" + ",".join(sorted(values)) + "]"


def expected_nodes_diagnostics(
    roles: list[dict], machines: list[dict], nodes: list[dict]
) -> tuple[bool, list[str], list[str]]:
    """Evaluate one management/guest snapshot without trusting list cardinality."""
    node_by_name = {
        item.get("metadata", {}).get("name"): item
        for item in nodes
        if isinstance(item.get("metadata", {}).get("name"), str)
        and not item.get("metadata", {}).get("deletionTimestamp")
    }
    claimed_node_refs: set[str] = set()
    diagnostics = []
    shortfalls = []
    all_ready = True

    for role in roles:
        deployment = role["machine_deployment"]
        matching_machines = []
        for machine in machines:
            labels = machine.get("metadata", {}).get("labels", {})
            if not isinstance(labels, dict):
                continue
            if deployment is None:
                matches = "cluster.x-k8s.io/control-plane" in labels
            else:
                matches = (
                    "cluster.x-k8s.io/control-plane" not in labels
                    and labels.get("cluster.x-k8s.io/deployment-name") == deployment
                )
            if matches:
                matching_machines.append(machine)

        excluded_machines = [
            f"{machine.get('metadata', {}).get('name', '<unnamed-machine>')}"
            f"({_machine_exclusion(machine)})"
            for machine in matching_machines
            if _machine_exclusion(machine) is not None
        ]
        role_machines = [
            machine
            for machine in matching_machines
            if _machine_exclusion(machine) is None
        ]

        expected = role["expected"]
        machines_not_created = max(0, expected - len(matching_machines))
        missing_nodes = []
        not_ready_nodes = []
        unique_node_refs = True
        registered = 0
        ready = 0
        for machine in sorted(
            role_machines,
            key=lambda item: item.get("metadata", {}).get("name", ""),
        ):
            machine_name = machine.get("metadata", {}).get(
                "name", "<unnamed-machine>"
            )
            node_reference = machine.get("status", {}).get("nodeRef")
            node_name = (
                node_reference.get("name")
                if isinstance(node_reference, dict)
                else None
            )
            if not isinstance(node_name, str) or not node_name:
                missing_nodes.append(machine_name)
                continue
            if node_name in claimed_node_refs:
                missing_nodes.append(f"{node_name}(duplicate)")
                unique_node_refs = False
                continue
            claimed_node_refs.add(node_name)
            node = node_by_name.get(node_name)
            if node is None:
                missing_nodes.append(node_name)
                continue
            registered += 1
            if _ready_node(node):
                ready += 1
            else:
                not_ready_nodes.append(node_name)

        role_ready = (
            len(role_machines) == expected
            and registered == expected
            and ready == expected
            and unique_node_refs
        )
        all_ready = all_ready and role_ready
        if not role_ready:
            if registered != expected:
                shortfalls.append(
                    f"{role['name']}: {registered} of {expected} expected nodes registered"
                )
            elif ready != expected:
                shortfalls.append(
                    f"{role['name']}: {ready} of {expected} expected nodes Ready"
                )
            else:
                shortfalls.append(
                    f"{role['name']}: active Machine count or node identities do not match render"
                )
        diagnostics.append(
            f"role={role['name']} expected={expected} registered={registered} "
            f"ready={ready} machines_not_created={machines_not_created} "
            f"excluded_machines={_diagnostic_list(excluded_machines)} "
            f"missing_nodes={_diagnostic_list(missing_nodes)} "
            f"not_ready_nodes={_diagnostic_list(not_ready_nodes)}"
        )
    return all_ready, diagnostics, shortfalls


def kubectl_json_bounded(
    kubeconfig: Path, arguments: list[str], timeout_seconds: float
) -> dict:
    if timeout_seconds <= 0:
        raise TalosLifecycleError("kubectl deadline expired")
    request_timeout = max(1, math.ceil(timeout_seconds))
    command = [
        "kubectl",
        "--kubeconfig",
        str(kubeconfig),
        f"--request-timeout={request_timeout}s",
        *arguments,
        "-o",
        "json",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise TalosLifecycleError(
            f"{' '.join(command[:6])} timed out after {timeout_seconds:.3g}s"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise TalosLifecycleError(
            f"{' '.join(command[:6])} exited {result.returncode}: {detail}"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise TalosLifecycleError(
            f"{' '.join(command[:6])} returned invalid JSON"
        ) from error
    if not isinstance(value, dict):
        raise TalosLifecycleError(
            f"{' '.join(command[:6])} returned a non-object JSON value"
        )
    return value


def _validate_api_items(items: object, description: str) -> list[dict]:
    if not isinstance(items, list):
        raise TalosLifecycleError(f"{description} list has invalid items")
    for item in items:
        if not isinstance(item, dict):
            raise TalosLifecycleError(f"{description} list contains a non-object item")
        metadata = item.get("metadata")
        if (
            not isinstance(metadata, dict)
            or not isinstance(metadata.get("name"), str)
            or not metadata["name"]
        ):
            raise TalosLifecycleError(
                f"{description} list contains an item without a valid metadata.name"
            )
    return items


def wait_expected_nodes(args: argparse.Namespace) -> int:
    if not args.cluster_dir:
        raise TalosLifecycleError("--wait-expected-nodes requires --cluster-dir")
    if not args.workload_kubeconfig:
        raise TalosLifecycleError(
            "--wait-expected-nodes requires --workload-kubeconfig"
        )
    manifest_path = cluster_directory(args) / "cluster-base.yaml"
    if not manifest_path.is_file():
        raise TalosLifecycleError(f"rendered manifest is absent: {manifest_path}")
    namespace, roles = expected_node_roles(manifest_path, args.cluster)
    management_kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    workload_kubeconfig = Path(args.workload_kubeconfig).expanduser().resolve()
    if not management_kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit management kubeconfig is absent: {management_kubeconfig}"
        )
    if not workload_kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit workload kubeconfig is absent: {workload_kubeconfig}"
        )

    deadline = time.monotonic() + args.expected_nodes_timeout_seconds
    diagnostics = expected_nodes_diagnostics(roles, [], [])[1]
    shortfalls = []
    complete_snapshot = False
    last_api_error = ""
    while True:
        api_errors = []
        machines = []
        nodes = []
        remaining = deadline - time.monotonic()
        if remaining < 2.0:
            break
        call_budget = min(remaining, max(2.0, args.expected_nodes_poll_seconds))
        try:
            machine_response = kubectl_json_bounded(
                management_kubeconfig,
                [
                    "-n",
                    namespace,
                    "get",
                    "machines.cluster.x-k8s.io",
                    "-l",
                    f"cluster.x-k8s.io/cluster-name={args.cluster}",
                ],
                call_budget,
            )
            validated_machines = _validate_api_items(
                machine_response.get("items"), "management Machine"
            )
            for machine in validated_machines:
                metadata = machine["metadata"]
                if not isinstance(metadata.get("namespace"), str):
                    raise TalosLifecycleError(
                        "management Machine has no valid metadata.namespace"
                    )
                if not isinstance(metadata.get("labels"), dict):
                    raise TalosLifecycleError(
                        "management Machine has no valid metadata.labels"
                    )
            machines = validated_machines
        except TalosLifecycleError as error:
            machines = []
            api_errors.append(f"management API: {error}")

        remaining = deadline - time.monotonic()
        if remaining > 0:
            call_budget = min(
                remaining, max(2.0, args.expected_nodes_poll_seconds)
            )
            try:
                node_response = kubectl_json_bounded(
                    workload_kubeconfig, ["get", "nodes"], call_budget
                )
                nodes = _validate_api_items(
                    node_response.get("items"), "workload Node"
                )
            except TalosLifecycleError as error:
                nodes = []
                api_errors.append(f"workload API: {error}")

        else:
            api_errors.append("workload API: deadline expired before Node snapshot")

        machines = [
            item
            for item in machines
            if item["metadata"].get("namespace") == namespace
            and isinstance(item["metadata"].get("labels"), dict)
            and item["metadata"]["labels"].get("cluster.x-k8s.io/cluster-name")
            == args.cluster
        ]
        if api_errors:
            last_api_error = "; ".join(api_errors)
        else:
            snapshot_ready, snapshot_diagnostics, shortfalls = expected_nodes_diagnostics(
                roles, machines, nodes
            )
            if snapshot_diagnostics != diagnostics or not complete_snapshot:
                for diagnostic in snapshot_diagnostics:
                    print(diagnostic, flush=True)
            diagnostics = snapshot_diagnostics
            complete_snapshot = True
            if snapshot_ready and time.monotonic() <= deadline:
                print("READY all expected nodes are registered and Ready")
                return 0

        remaining = deadline - time.monotonic()
        if remaining < 2.0:
            break
        time.sleep(min(args.expected_nodes_poll_seconds, remaining - 2.0))

    if complete_snapshot:
        cause = "; ".join(shortfalls) or "deadline expired before readiness outcome"
        api_note = f"; last API error: {last_api_error}" if last_api_error else ""
    else:
        cause = last_api_error or "API snapshot was not completed"
        api_note = ""
    raise TalosLifecycleError(
        "timed out waiting for expected nodes: "
        + cause
        + "; "
        + "; ".join(diagnostics)
        + api_note
    )


def ready_nodes(workload_kubeconfig: Path, expected: int) -> tuple[list, str]:
    nodes = kubectl_json(workload_kubeconfig, ["get", "nodes"]).get(
        "items", []
    )
    if len(nodes) != expected:
        raise TalosLifecycleError(
            f"expected {expected} Nodes, observed {len(nodes)}"
        )
    evidence = []
    ready_times = []
    for node in nodes:
        ready = next(
            (
                condition
                for condition in node.get("status", {}).get(
                    "conditions", []
                )
                if condition.get("type") == "Ready"
            ),
            None,
        )
        provider_id = node.get("spec", {}).get("providerID", "")
        os_image = (
            node.get("status", {}).get("nodeInfo", {}).get("osImage", "")
        )
        if (
            ready is None
            or ready.get("status") != "True"
            or not ready.get("lastTransitionTime")
            or not provider_id.startswith("kubevirt://")
            or "talos" not in os_image.lower()
        ):
            raise TalosLifecycleError(
                "runtime Node readiness/provider/OS identity is invalid"
            )
        ready_times.append(ready["lastTransitionTime"])
        evidence.append(
            {
                "name": node["metadata"]["name"],
                "uid": node["metadata"]["uid"],
                "provider_id": provider_id,
                "os_image": os_image,
                "ready_at": ready["lastTransitionTime"],
            }
        )
    return evidence, max(ready_times, key=parse_time)


def cilium_runtime(
    workload_kubeconfig: Path, chart_path: Path
) -> dict:
    digest = verify_cilium_chart(chart_path)
    if digest != CILIUM_CHART_SHA256:
        raise TalosLifecycleError("local Cilium chart identity is invalid")
    daemonset = kubectl_json(
        workload_kubeconfig,
        ["-n", "kube-system", "get", "daemonset", "cilium"],
    )
    daemon_status = daemonset.get("status", {})
    if (
        daemon_status.get("desiredNumberScheduled", 0) < 1
        or daemon_status.get("numberReady")
        != daemon_status.get("desiredNumberScheduled")
    ):
        raise TalosLifecycleError("Cilium DaemonSet is not fully Ready")
    operator = kubectl_json(
        workload_kubeconfig,
        ["-n", "kube-system", "get", "deployment", "cilium-operator"],
    )
    if operator.get("status", {}).get("readyReplicas", 0) < 1:
        raise TalosLifecycleError("Cilium operator is not Ready")
    releases = json.loads(
        run(
            [
                "helm",
                "list",
                "--kubeconfig",
                str(workload_kubeconfig),
                "--namespace",
                "kube-system",
                "--output",
                "json",
            ]
        ).stdout
    )
    release = next(
        (item for item in releases if item.get("name") == "cilium"),
        None,
    )
    if (
        release is None
        or release.get("chart") != "cilium-1.19.6"
        or release.get("status") != "deployed"
    ):
        raise TalosLifecycleError("Cilium Helm release identity is invalid")
    return {
        "chart": "cilium-1.19.6",
        "chart_sha256": f"sha256:{digest}",
        "release_status": "deployed",
        "daemonset_ready": daemon_status["numberReady"],
        "daemonset_desired": daemon_status["desiredNumberScheduled"],
        "operator_ready": operator["status"]["readyReplicas"],
    }


def runtime_infrastructure_state(
    config: dict,
    data_volumes: list[dict],
    virtual_machine_instances: list[dict],
    persistent_volume_claims: list[dict],
) -> dict:
    expected_count = (
        int(config["controlPlane"]["replicas"])
        + int(config["workers"]["replicas"])
    )
    provider = config["providerProfile"]
    golden = config["os"]["goldenImage"]
    expected_source = {
        "pvc": {"namespace": golden["namespace"], "name": golden["claim"]}
    }
    if len(data_volumes) != expected_count:
        raise TalosLifecycleError(
            f"expected {expected_count} boot DataVolumes, observed "
            f"{len(data_volumes)}"
        )
    data_volume_evidence = []
    for item in data_volumes:
        spec = item.get("spec", {})
        storage_class = (
            spec.get("pvc", {}).get("storageClassName")
            or spec.get("storage", {}).get("storageClassName")
        )
        if (
            spec.get("source") != expected_source
            or storage_class != provider["cloneTargetStorageClass"]
            or item.get("status", {}).get("phase") != "Succeeded"
        ):
            raise TalosLifecycleError(
                "runtime DataVolume source, storage or phase is invalid"
            )
        data_volume_evidence.append(
            {
                "name": item["metadata"]["name"],
                "uid": item["metadata"]["uid"],
                "storage_class": storage_class,
                "phase": "Succeeded",
            }
        )
    if len(virtual_machine_instances) != expected_count or any(
        item.get("status", {}).get("phase") != "Running"
        or item.get("status", {}).get("nodeName") != provider["nodeSelector"]
        for item in virtual_machine_instances
    ):
        raise TalosLifecycleError(
            "runtime VMI count, phase or provider-profile placement is invalid"
        )
    expected_sizes = {
        "control-plane": config["controlPlane"]["disk"],
        "worker": config["workers"]["disk"],
    }
    pvc_evidence = []
    boot_pvcs = [
        item
        for item in persistent_volume_claims
        if item.get("spec", {}).get("storageClassName")
        == provider["cloneTargetStorageClass"]
    ]
    if len(boot_pvcs) != expected_count:
        raise TalosLifecycleError(
            f"expected {expected_count} boot PVCs, observed {len(boot_pvcs)}"
        )
    for item in boot_pvcs:
        name = item["metadata"]["name"]
        role = "control-plane" if "-cp-" in name else "worker"
        requested = item.get("spec", {}).get("resources", {}).get(
            "requests", {}
        ).get("storage")
        if item.get("status", {}).get("phase") != "Bound":
            raise TalosLifecycleError(f"runtime boot PVC {name} is not Bound")
        # CDI may add filesystem overhead to the PVC request. The declared
        # role size remains authoritative and is proven on the DataVolume
        # template; the runtime PVC must be at least that large.
        if quantity_bytes(requested) < quantity_bytes(expected_sizes[role]):
            raise TalosLifecycleError(
                f"runtime boot PVC {name} is smaller than {expected_sizes[role]}"
            )
        pvc_evidence.append(
            {
                "name": name,
                "uid": item["metadata"]["uid"],
                "role": role,
                "requested": requested,
                "declared": expected_sizes[role],
                "phase": "Bound",
            }
        )
    return {
        "data_volumes": data_volume_evidence,
        "virtual_machine_instances": [
            {
                "name": item["metadata"]["name"],
                "uid": item["metadata"]["uid"],
                "node": item["status"]["nodeName"],
                "phase": "Running",
            }
            for item in virtual_machine_instances
        ],
        "persistent_volume_claims": pvc_evidence,
    }


def longhorn_runtime_state(
    config: dict,
    persistent_volume_claims: list[dict],
    volumes: list[dict],
    replicas: list[dict],
) -> list[dict]:
    """Prove requested Longhorn replicas actually exist and are healthy."""
    expected_replicas = int(config["providerProfile"]["replicaCount"])
    volume_names = {
        item.get("spec", {}).get("volumeName")
        for item in persistent_volume_claims
        if item.get("spec", {}).get("storageClassName")
        == config["providerProfile"]["cloneTargetStorageClass"]
    }
    volume_names.discard(None)
    observed = {
        item.get("metadata", {}).get("name"): item
        for item in volumes
        if item.get("metadata", {}).get("name") in volume_names
    }
    if set(observed) != volume_names:
        raise TalosLifecycleError(
            "runtime Longhorn volumes do not match the boot PVCs"
        )
    evidence = []
    for name in sorted(volume_names):
        volume = observed[name]
        matching_replicas = [
            item
            for item in replicas
            if item.get("metadata", {}).get("labels", {}).get(
                "longhornvolume"
            )
            == name
        ]
        replica_nodes = {
            item.get("spec", {}).get("nodeID") for item in matching_replicas
        }
        replica_nodes.discard(None)
        if (
            int(volume.get("spec", {}).get("numberOfReplicas", 0))
            != expected_replicas
            or volume.get("status", {}).get("state") != "attached"
            or volume.get("status", {}).get("robustness") != "healthy"
            or len(matching_replicas) != expected_replicas
            or len(replica_nodes) != expected_replicas
            or any(
                item.get("spec", {}).get("desireState") != "running"
                or item.get("status", {}).get("started") is not True
                for item in matching_replicas
            )
        ):
            raise TalosLifecycleError(
                f"runtime Longhorn volume {name} is not healthy with "
                f"{expected_replicas} replicas on distinct nodes"
            )
        evidence.append(
            {
                "name": name,
                "state": "attached",
                "robustness": "healthy",
                "replica_count": expected_replicas,
                "replica_nodes": sorted(replica_nodes),
            }
        )
    return evidence


def runtime_evidence(args: argparse.Namespace) -> int:
    """Record a read-only warm-provisioning result, separate from publication."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    kubevirt = verify_kubevirt(kubeconfig)
    scheduling = verify_scheduling(
        config, kubeconfig, require_create_capacity=False
    )
    storage = verify_clone_storage(config, kubeconfig)
    golden = verify_golden(config, kubeconfig)
    cluster_name = config["name"]
    namespace = kubectl_json(
        kubeconfig, ["get", "namespace", cluster_name]
    )
    cluster = kubectl_json(
        kubeconfig,
        ["-n", cluster_name, "get", "cluster", cluster_name],
    )
    available = true_condition(cluster, "Available", "Ready")
    if available is None or not available.get("lastTransitionTime"):
        raise TalosLifecycleError("Talos cluster is not Available")
    data_volumes = kubectl_json(
        kubeconfig, ["-n", cluster_name, "get", "datavolumes"]
    ).get("items", [])
    expected_count = (
        config["controlPlane"]["replicas"] + config["workers"]["replicas"]
    )
    persistent_volume_claims = kubectl_json(
        kubeconfig, ["-n", cluster_name, "get", "pvc"]
    ).get("items", [])
    infrastructure = runtime_infrastructure_state(
        config,
        data_volumes,
        kubectl_json(
            kubeconfig, ["-n", cluster_name, "get", "vmi"]
        ).get("items", []),
        persistent_volume_claims,
    )
    infrastructure["longhorn_volumes"] = longhorn_runtime_state(
        config,
        persistent_volume_claims,
        kubectl_json(
            kubeconfig,
            ["-n", "longhorn-system", "get", "volumes.longhorn.io"],
        ).get("items", []),
        kubectl_json(
            kubeconfig,
            ["-n", "longhorn-system", "get", "replicas.longhorn.io"],
        ).get("items", []),
    )
    started_at = namespace["metadata"]["creationTimestamp"]
    ready_at = available["lastTransitionTime"]
    duration = (parse_time(ready_at) - parse_time(started_at)).total_seconds()
    if duration < 0:
        raise TalosLifecycleError("cluster readiness predates its namespace")
    workload_kubeconfig = Path(
        args.workload_kubeconfig
    ).expanduser().resolve()
    if not workload_kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit workload kubeconfig is absent: {workload_kubeconfig}"
        )
    expected_nodes = expected_count
    nodes, nodes_ready_at = ready_nodes(
        workload_kubeconfig, expected_nodes
    )
    chart_path = Path(args.cilium_chart).expanduser().resolve()
    cilium = cilium_runtime(workload_kubeconfig, chart_path)
    completed_at = now()
    nodes_duration = (
        parse_time(nodes_ready_at) - parse_time(started_at)
    ).total_seconds()
    end_to_end_duration = (
        parse_time(completed_at) - parse_time(started_at)
    ).total_seconds()
    if nodes_duration < 0 or end_to_end_duration < 0:
        raise TalosLifecycleError("runtime milestone predates its namespace")
    evidence = {
        "schema_version": 1,
        "suite": "OK-130-talos-golden-image",
        "status": "PASS",
        "mode": "warm-provisioning",
        "cluster": cluster_name,
        "identity": config["os"]["identity"],
        "golden": golden,
        "scheduling": scheduling,
        "storage": storage,
        "kubevirt": kubevirt,
        "started_at": started_at,
        "capi_available_at": ready_at,
        "nodes_ready_at": nodes_ready_at,
        "completed_at": completed_at,
        "timings_seconds": {
            "capi_available": round(duration, 3),
            "nodes_ready": round(nodes_duration, 3),
            "end_to_end_cilium_ready": round(end_to_end_duration, 3),
        },
        "boot_data_volumes": len(data_volumes),
        "infrastructure": infrastructure,
        "nodes": nodes,
        "cilium": cilium,
        "public_import_count": 0,
        "secret_values_recorded": False,
        "mutation_attempted": False,
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE_DIR / f"warm-{cluster_name}.json"
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(
        f"PASS warm provisioning cluster={cluster_name} "
        f"duration={duration:.3f}s evidence={path}"
    )
    return 0


def preflight(args: argparse.Namespace) -> int:
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    kubevirt = verify_kubevirt(kubeconfig)
    scheduling = verify_scheduling(config, kubeconfig)
    storage = verify_clone_storage(config, kubeconfig)
    golden = verify_golden(config, kubeconfig)
    endpoint = verify_endpoint_available(config, kubeconfig)
    cluster = config["name"]
    namespace = kubectl(
        kubeconfig,
        ["get", "namespace", cluster, "-o", "name"],
        expected=(0, 1),
    )
    if namespace.returncode == 0:
        raise TalosLifecycleError(
            f"namespace {cluster} already exists; refusing create-overwrite"
        )
    workload_kubeconfig = Path.home() / ".kube" / f"{cluster}.yaml"
    if workload_kubeconfig.exists():
        raise TalosLifecycleError(
            f"workload kubeconfig collision: {workload_kubeconfig} already exists"
        )
    authorization = f"{cluster}-talos-golden-image-cloner"
    golden_namespace = config["os"]["goldenImage"]["namespace"]
    for kind in ("role", "rolebinding"):
        existing = kubectl(
            kubeconfig,
            [
                "-n",
                golden_namespace,
                "get",
                kind,
                authorization,
                "-o",
                "name",
            ],
            expected=(0, 1),
        )
        if existing.returncode == 0:
            raise TalosLifecycleError(
                f"{kind} {golden_namespace}/{authorization} already exists"
            )
    print(
        f"PASS Talos Golden preflight cluster={cluster} "
        f"node={scheduling['name']} kubevirt={kubevirt['version']} "
        f"expand_disks={kubevirt['expand_disks']} "
        f"storage={storage['storage_class']} replicas={storage['replica_count']} "
        f"endpoint={endpoint['endpoint']} "
        f"golden_uid={golden['uid']}"
    )
    return 0


def replacement_preflight(args: argparse.Namespace) -> int:
    """Verify a live cluster may consume a newly published Golden identity."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    kubevirt = verify_kubevirt(kubeconfig)
    scheduling = verify_scheduling(config, kubeconfig)
    verify_clone_storage(config, kubeconfig)
    golden = verify_golden(config, kubeconfig)
    cluster_name = config["name"]
    cluster = kubectl_json(
        kubeconfig,
        ["-n", cluster_name, "get", "cluster", cluster_name],
    )
    if true_condition(cluster, "Available", "Ready") is None:
        raise TalosLifecycleError(
            "existing Talos cluster is not Available for replacement"
        )
    print(
        f"PASS Talos replacement preflight cluster={cluster_name} "
        f"node={scheduling['name']} kubevirt={kubevirt['version']} "
        f"new_golden_uid={golden['uid']}"
    )
    return 0


def owner_uids(resource: dict, kind: str) -> set[str]:
    return {
        owner["uid"]
        for owner in resource.get("metadata", {}).get("ownerReferences", [])
        if owner.get("kind") == kind and owner.get("uid")
    }


def replacement_templates(
    config: dict, manifest_path: Path
) -> dict[str, int]:
    docs = objects(manifest_path)
    control_planes = [
        item for item in docs if item.get("kind") == "TalosControlPlane"
    ]
    deployments = [
        item for item in docs if item.get("kind") == "MachineDeployment"
    ]
    if len(control_planes) != 1 or len(deployments) != 1:
        raise TalosLifecycleError(
            "replacement manifest must contain one control plane and deployment"
        )
    return {
        control_planes[0]["spec"]["infrastructureTemplate"]["name"]: int(
            config["controlPlane"]["replicas"]
        ),
        deployments[0]["spec"]["template"]["spec"]["infrastructureRef"][
            "name"
        ]: int(config["workers"]["replicas"]),
    }


def replacement_data_volume_state(
    config: dict,
    manifest_path: Path,
    infrastructure_machines: list[dict],
    virtual_machines: list[dict],
    data_volumes: list[dict],
) -> dict:
    templates = replacement_templates(config, manifest_path)
    by_template = {name: [] for name in templates}
    for machine in infrastructure_machines:
        cloned_from = (
            machine.get("metadata", {})
            .get("annotations", {})
            .get("cluster.x-k8s.io/cloned-from-name")
        )
        if cloned_from in by_template:
            by_template[cloned_from].append(machine)
    for template, expected in templates.items():
        observed = len(by_template[template])
        if observed > expected:
            raise TalosLifecycleError(
                f"replacement template {template} has {observed} active "
                f"machines; expected {expected}"
            )

    target_machines = [
        machine
        for template in templates
        for machine in by_template[template]
    ]
    machine_names = {
        machine["metadata"]["name"] for machine in target_machines
    }
    owned_virtual_machines = [
        virtual_machine
        for virtual_machine in virtual_machines
        if virtual_machine.get("metadata", {}).get("name") in machine_names
    ]
    virtual_machines_by_owner = {
        machine_name: [
            virtual_machine
            for virtual_machine in owned_virtual_machines
            if virtual_machine["metadata"]["name"] == machine_name
        ]
        for machine_name in machine_names
    }
    if any(
        len(values) > 1 for values in virtual_machines_by_owner.values()
    ):
        raise TalosLifecycleError(
            "replacement KubevirtMachine owns multiple VirtualMachines"
        )
    virtual_machine_uids = {
        virtual_machine["metadata"]["uid"]
        for virtual_machine in owned_virtual_machines
    }
    owned_data_volumes = [
        data_volume
        for data_volume in data_volumes
        if owner_uids(data_volume, "VirtualMachine") & virtual_machine_uids
    ]
    by_owner = {
        virtual_machine_uid: [
            data_volume
            for data_volume in owned_data_volumes
            if virtual_machine_uid
            in owner_uids(data_volume, "VirtualMachine")
        ]
        for virtual_machine_uid in virtual_machine_uids
    }
    if any(len(values) > 1 for values in by_owner.values()):
        raise TalosLifecycleError(
            "replacement VirtualMachine owns multiple boot DataVolumes"
        )
    expected_source = {
        "pvc": {
            "namespace": config["os"]["goldenImage"]["namespace"],
            "name": config["os"]["goldenImage"]["claim"],
        }
    }
    for data_volume in owned_data_volumes:
        if data_volume.get("spec", {}).get("source") != expected_source:
            raise TalosLifecycleError(
                "replacement DataVolume source is not the reviewed Golden PVC"
            )
        if data_volume.get("status", {}).get("phase") == "Failed":
            raise TalosLifecycleError(
                f"replacement DataVolume "
                f"{data_volume['metadata']['name']} failed"
            )
    expected_count = sum(templates.values())
    phases = {
        data_volume["metadata"]["name"]: data_volume.get("status", {}).get(
            "phase", ""
        )
        for data_volume in owned_data_volumes
    }
    ready = (
        len(target_machines) == expected_count
        and len(owned_virtual_machines) == expected_count
        and all(
            len(values) == 1
            for values in virtual_machines_by_owner.values()
        )
        and len(owned_data_volumes) == expected_count
        and all(len(values) == 1 for values in by_owner.values())
        and all(phase == "Succeeded" for phase in phases.values())
    )
    return {
        "ready": ready,
        "expected": expected_count,
        "target_machine_names": sorted(machine_names),
        "virtual_machine_uids": sorted(virtual_machine_uids),
        "data_volume_names": sorted(phases),
        "data_volume_uids": sorted(
            data_volume["metadata"]["uid"]
            for data_volume in owned_data_volumes
        ),
        "phases": phases,
    }


def replacement_wait(args: argparse.Namespace) -> int:
    """Wait for exact current replacement-machine boot clones."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    deadline = time.monotonic() + args.replacement_timeout_seconds
    last_state = None
    while time.monotonic() < deadline:
        infrastructure_machines = kubectl_json(
            kubeconfig,
            [
                "-n",
                config["name"],
                "get",
                "kubevirtmachines.infrastructure.cluster.x-k8s.io",
            ],
        ).get("items", [])
        virtual_machines = kubectl_json(
            kubeconfig,
            [
                "-n",
                config["name"],
                "get",
                "virtualmachines.kubevirt.io",
            ],
        ).get("items", [])
        data_volumes = kubectl_json(
            kubeconfig,
            ["-n", config["name"], "get", "datavolumes.cdi.kubevirt.io"],
        ).get("items", [])
        state = replacement_data_volume_state(
            config,
            manifest,
            infrastructure_machines,
            virtual_machines,
            data_volumes,
        )
        for name in state["data_volume_names"]:
            annotation = kubectl(
                kubeconfig,
                [
                    "-n",
                    config["name"],
                    "annotate",
                    "pvc",
                    name,
                    "volume.kubernetes.io/selected-node=ok-infra",
                    "--overwrite",
                ],
                expected=(0, 1),
            )
            if (
                annotation.returncode != 0
                and not kubectl_not_found(annotation)
            ):
                raise TalosLifecycleError(
                    f"could not annotate replacement PVC {name}: "
                    f"{annotation.stderr.strip() or 'unknown error'}"
                )
        if state["ready"]:
            print(
                f"PASS {state['expected']}/{state['expected']} exact "
                "replacement DataVolumes succeeded "
                f"uids={','.join(state['data_volume_uids'])}"
            )
            return 0
        if state != last_state:
            print(
                "WAIT replacement DataVolumes "
                f"machines={len(state['target_machine_names'])}/"
                f"{state['expected']} phases={state['phases']}"
            )
            last_state = state
        time.sleep(15)
    raise TalosLifecycleError(
        "exact replacement DataVolumes did not succeed before timeout"
    )


def kubectl_json_optional(kubeconfig: Path, arguments: list[str]) -> dict | None:
    result = kubectl(kubeconfig, [*arguments, "-o", "json"], expected=(0, 1))
    if result.returncode == 0:
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise TalosLifecycleError("kubectl returned a non-object JSON value")
        return value
    if not kubectl_not_found(result):
        raise TalosLifecycleError(
            f"{' '.join(arguments)} read failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return None


def rendered_cluster(manifest_path: Path, cluster: str) -> dict:
    matches = [
        item
        for item in objects(manifest_path)
        if item.get("kind") == "Cluster"
        and item.get("metadata", {}).get("name") == cluster
        and item.get("metadata", {}).get("namespace") == cluster
    ]
    if len(matches) != 1:
        raise TalosLifecycleError(
            "cluster-base.yaml must contain exactly one requested CAPI Cluster"
        )
    return matches[0]


def require_rendered_subset(expected: object, observed: object, path: str) -> None:
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            raise TalosLifecycleError(f"live Cluster differs at {path}")
        for key, value in expected.items():
            if key not in observed:
                raise TalosLifecycleError(
                    f"live Cluster is missing rendered field {path}.{key}"
                )
            require_rendered_subset(value, observed[key], f"{path}.{key}")
        return
    if expected != observed:
        raise TalosLifecycleError(f"live Cluster differs at {path}")


def resume_preconditions(args: argparse.Namespace) -> int:
    cluster_dir = cluster_directory(args)
    config_path = cluster_dir / "cluster-config.yaml"
    manifest_path = cluster_dir / "cluster-base.yaml"
    if not config_path.is_file() or not manifest_path.is_file():
        raise TalosLifecycleError("rendered Talos config/manifest is absent")
    config = load_yaml(config_path)
    if config.get("name") != args.cluster:
        raise TalosLifecycleError("rendered cluster config name is invalid")
    expected = rendered_cluster(manifest_path, args.cluster)
    expected_labels = expected.get("metadata", {}).get("labels", {})
    required_labels = (
        "openkubes.io/type",
        "openkubes.io/k8s-version",
        "openkubes.io/talos-version",
    )
    expected_spec = expected.get("spec", {})
    if (
        not isinstance(expected_labels, dict)
        or any(not expected_labels.get(key) for key in required_labels)
        or expected_labels["openkubes.io/type"] != "talos"
        or config.get("type") not in ("talos", "talos-mgmt")
        or expected_labels.get("openkubes.io/provider", "kubevirt")
        != "kubevirt"
        or not isinstance(expected_spec.get("clusterNetwork"), dict)
        or not isinstance(expected_spec.get("controlPlaneRef"), dict)
        or not isinstance(expected_spec.get("infrastructureRef"), dict)
    ):
        raise TalosLifecycleError("rendered Cluster identity is incomplete")
    for reference in ("controlPlaneRef", "infrastructureRef"):
        if any(
            not expected_spec[reference].get(key)
            for key in ("apiGroup", "kind", "name")
        ):
            raise TalosLifecycleError("rendered Cluster identity is incomplete")
    for network in ("pods", "services"):
        cidrs = expected_spec["clusterNetwork"].get(network, {}).get(
            "cidrBlocks"
        )
        if not isinstance(cidrs, list) or not cidrs:
            raise TalosLifecycleError("rendered Cluster identity is incomplete")
    kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    if not kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit management kubeconfig is absent: {kubeconfig}"
        )
    live = kubectl_json_optional(
        kubeconfig,
        ["-n", args.cluster, "get", "cluster", args.cluster],
    )
    if live is None:
        raise TalosLifecycleError(
            f"CAPI Cluster {args.cluster}/{args.cluster} is absent"
        )
    metadata = live.get("metadata", {})
    live_spec = live.get("spec", {})
    status = live.get("status", {})
    if not all(
        isinstance(value, dict) for value in (metadata, live_spec, status)
    ):
        raise TalosLifecycleError("live Cluster structure is invalid")
    if (
        not metadata.get("uid")
        or metadata.get("name") != args.cluster
        or metadata.get("namespace") != args.cluster
    ):
        raise TalosLifecycleError("live Cluster identity is invalid")
    if metadata.get("deletionTimestamp"):
        raise TalosLifecycleError("live Cluster is deleting")
    if "cluster.x-k8s.io/paused" in (metadata.get("annotations") or {}):
        raise TalosLifecycleError("live Cluster is paused")
    if live_spec.get("paused") is True:
        raise TalosLifecycleError("live Cluster is paused")
    phase = status.get("phase", "")
    if phase not in ("", "Pending", "Provisioning", "Provisioned"):
        raise TalosLifecycleError(
            f"live Cluster phase {phase or '<empty>'} is not resumable"
        )
    if status.get("failureReason") or status.get("failureMessage"):
        raise TalosLifecycleError("live Cluster reports a lifecycle failure")
    require_rendered_subset(
        expected_labels,
        metadata.get("labels", {}),
        "metadata.labels",
    )
    require_rendered_subset(
        expected_spec, live_spec, "spec"
    )
    print(
        f"PASS bootstrap resume preconditions cluster={args.cluster} "
        f"uid={metadata['uid']} phase={phase or 'Pending'}"
    )
    return 0


def teardown_config_subset(config: dict) -> dict:
    os_config = config.get("os", {})
    if not isinstance(os_config, dict):
        raise TalosLifecycleError("cluster OS config is invalid")
    golden = os_config.get("goldenImage")
    has_golden = (
        config.get("type") == "talos"
        and isinstance(golden, dict)
        and bool(golden)
    )
    return {
        "type": config.get("type"),
        "golden_namespace": golden.get("namespace") if has_golden else None,
        "golden_claim": golden.get("claim") if has_golden else None,
        "os_identity": os_config.get("identity") if has_golden else None,
        "image_digest": os_config.get("imageDigest") if has_golden else None,
    }


def config_from_teardown_record(record: dict) -> dict:
    saved = record["config"]
    config = {
        "name": record["cluster"]["name"],
        "type": saved["type"],
    }
    if saved["golden_namespace"] is not None:
        config["os"] = {
            "identity": saved["os_identity"],
            "imageDigest": saved["image_digest"],
            "goldenImage": {
                "namespace": saved["golden_namespace"],
                "claim": saved["golden_claim"],
            },
        }
    return config


def has_golden_config(config: dict) -> bool:
    return bool(
        config.get("type") == "talos"
        and config.get("os", {}).get("goldenImage")
    )


def local_teardown_config(args: argparse.Namespace) -> dict | None:
    cluster_dir = cluster_directory(args)
    config_path = cluster_dir / "cluster-config.yaml"
    if not config_path.is_file():
        return None
    config = load_yaml(config_path)
    if config.get("name") != args.cluster:
        raise TalosLifecycleError("rendered cluster config name is invalid")
    if not config.get("type"):
        raise TalosLifecycleError("rendered cluster config type is absent")
    if config.get("type") == "flatcar":
        raise TalosLifecycleError(
            "constrained Flatcar requires the dedicated teardown path"
        )
    if has_golden_config(config):
        resolved = resolve_talos_config(
            config, Path(args.ok_linux_path).expanduser().resolve()
        )
        if resolved != config:
            raise TalosLifecycleError(
                "cluster config is not fully materialized; run make render"
            )
        manifest_path = cluster_dir / "cluster-base.yaml"
        if not manifest_path.is_file():
            raise TalosLifecycleError("rendered Talos manifest is absent")
        validate_manifest(config, manifest_path)
    subset = teardown_config_subset(config)
    if has_golden_config(config) and any(
        not subset[key]
        for key in (
            "golden_namespace",
            "golden_claim",
            "os_identity",
            "image_digest",
        )
    ):
        raise TalosLifecycleError("Talos Golden teardown identity is incomplete")
    return config


def canonical_record(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def validate_teardown_record(record: dict, cluster: str) -> None:
    required = {
        "schema_version",
        "cluster",
        "namespace_uid",
        "config",
        "golden_before",
        "data_volume_uids",
        "persistent_volumes",
        "complete",
    }
    if record.get("schema_version") == SPLIT_TEARDOWN_LEDGER_SCHEMA:
        required.add("planes")
        required.add("storage_uids")
        planes = record.get("planes")
        if (
            not isinstance(planes, dict)
            or set(planes) != {"management_uid", "provider_uid", "provider_namespace_uid"}
            or not all(isinstance(value, str) and value for value in planes.values())
            or planes["management_uid"] == planes["provider_uid"]
        ):
            raise TalosLifecycleError("teardown record plane identity is invalid")
    elif record.get("schema_version") != TEARDOWN_LEDGER_SCHEMA:
        raise TalosLifecycleError("teardown record schema is invalid")
    if set(record) != required:
        raise TalosLifecycleError("teardown record schema is invalid")
    cluster_identity = record.get("cluster")
    if (
        not isinstance(cluster_identity, dict)
        or set(cluster_identity) != {"name", "namespace", "uid"}
        or cluster_identity.get("name") != cluster
        or cluster_identity.get("namespace") != cluster
        or not cluster_identity.get("uid")
        or not record.get("namespace_uid")
    ):
        raise TalosLifecycleError("teardown record cluster identity is invalid")
    saved = record.get("config")
    config_keys = {
        "type",
        "golden_namespace",
        "golden_claim",
        "os_identity",
        "image_digest",
    }
    if not isinstance(saved, dict) or set(saved) != config_keys or not saved.get("type"):
        raise TalosLifecycleError("teardown record config identity is invalid")
    golden_values = [
        saved[key]
        for key in (
            "golden_namespace",
            "golden_claim",
            "os_identity",
            "image_digest",
        )
    ]
    if any(value is not None for value in golden_values):
        if (
            saved.get("type") != "talos"
            or not all(isinstance(value, str) and value for value in golden_values)
            or not isinstance(record.get("golden_before"), dict)
        ):
            raise TalosLifecycleError("teardown record Golden identity is invalid")
    elif record.get("golden_before") is not None:
        raise TalosLifecycleError("non-Golden teardown record has Golden evidence")
    for key in ("data_volume_uids", "persistent_volumes"):
        values = record.get(key)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            or values != sorted(set(values))
        ):
            raise TalosLifecycleError(f"teardown record {key} is invalid")
    if record.get("schema_version") == SPLIT_TEARDOWN_LEDGER_SCHEMA:
        storage = record.get("storage_uids")
        if (
            not isinstance(storage, dict)
            or set(storage) != set(record["persistent_volumes"])
            or any(
                not isinstance(value, dict)
                or set(value) != {"pv", "longhorn"}
                or not isinstance(value["pv"], str) or not value["pv"]
                or (value["longhorn"] is not None and (
                    not isinstance(value["longhorn"], str) or not value["longhorn"]
                ))
                for value in storage.values()
            )
        ):
            raise TalosLifecycleError("teardown record storage identity is invalid")
    if not isinstance(record.get("complete"), bool):
        raise TalosLifecycleError("teardown record completion marker is invalid")


def teardown_record_from_configmap(configmap: dict, cluster: str) -> dict:
    try:
        encoded = configmap["data"]["record.json"]
    except (KeyError, TypeError) as error:
        raise TalosLifecycleError("teardown ConfigMap record is absent") from error
    record = json.loads(encoded)
    if not isinstance(record, dict):
        raise TalosLifecycleError("teardown ConfigMap record is not an object")
    validate_teardown_record(record, cluster)
    return record


def read_teardown_configmap(kubeconfig: Path, cluster: str) -> dict | None:
    return kubectl_json_optional(
        kubeconfig,
        [
            "-n",
            TEARDOWN_LEDGER_NAMESPACE,
            "get",
            "configmap",
            f"{TEARDOWN_LEDGER_PREFIX}{cluster}",
        ],
    )


def persist_teardown_record(
    kubeconfig: Path, cluster: str, record: dict, existing: dict | None
) -> dict:
    validate_teardown_record(record, cluster)
    name = f"{TEARDOWN_LEDGER_PREFIX}{cluster}"
    encoded = canonical_record(record)
    if existing is None:
        kubectl(
            kubeconfig,
            [
                "-n",
                TEARDOWN_LEDGER_NAMESPACE,
                "create",
                "configmap",
                name,
                f"--from-literal=record.json={encoded}",
            ],
        )
    else:
        resource_version = existing.get("metadata", {}).get("resourceVersion")
        if not resource_version:
            raise TalosLifecycleError(
                "teardown ConfigMap resourceVersion is absent"
            )
        patch = {
            "metadata": {"resourceVersion": resource_version},
            "data": {"record.json": encoded},
        }
        kubectl(
            kubeconfig,
            [
                "-n",
                TEARDOWN_LEDGER_NAMESPACE,
                "patch",
                "configmap",
                name,
                "--type=merge",
                "-p",
                json.dumps(patch, sort_keys=True, separators=(",", ":")),
            ],
        )
    observed = read_teardown_configmap(kubeconfig, cluster)
    if observed is None or teardown_record_from_configmap(observed, cluster) != record:
        raise TalosLifecycleError("teardown record did not persist exactly")
    return observed


def bound_resource(
    kubeconfig: Path,
    arguments: list[str],
    expected_uid: str,
    description: str,
) -> dict | None:
    resource = kubectl_json_optional(kubeconfig, arguments)
    if resource is not None and resource.get("metadata", {}).get("uid") != expected_uid:
        raise TalosLifecycleError(
            f"{description} was recreated with a different UID; refusing teardown"
        )
    return resource


def teardown_inventory(
    kubeconfig: Path,
    cluster: str,
    config_identity: dict,
    namespace_uid: str,
    saved_persistent_volumes: set[str],
) -> tuple[set[str], set[str]]:
    if bound_resource(
        kubeconfig,
        ["get", "namespace", cluster],
        namespace_uid,
        "Namespace",
    ) is None:
        raise TalosLifecycleError("Namespace disappeared before inventory")
    data_volume_list = kubectl_json(
        kubeconfig, ["-n", cluster, "get", "datavolumes"]
    )
    data_volumes = data_volume_list.get("items")
    if not isinstance(data_volumes, list):
        raise TalosLifecycleError("DataVolume inventory is not a Kubernetes list")
    data_volume_uids = set()
    expected_source = None
    if config_identity["golden_namespace"] is not None:
        expected_source = {
            "pvc": {
                "namespace": config_identity["golden_namespace"],
                "name": config_identity["golden_claim"],
            }
        }
    for data_volume in data_volumes:
        if not isinstance(data_volume, dict):
            raise TalosLifecycleError("DataVolume inventory contains a non-object")
        uid = data_volume.get("metadata", {}).get("uid")
        if not uid:
            raise TalosLifecycleError("DataVolume inventory contains an empty UID")
        if expected_source is not None and data_volume.get("spec", {}).get("source") != expected_source:
            raise TalosLifecycleError(
                "cluster DataVolume source is not the recorded Golden PVC"
            )
        data_volume_uids.add(uid)
    claim_list = kubectl_json(kubeconfig, ["-n", cluster, "get", "pvc"])
    claims = claim_list.get("items")
    if not isinstance(claims, list):
        raise TalosLifecycleError("PVC inventory is not a Kubernetes list")
    persistent_volumes = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise TalosLifecycleError("PVC inventory contains a non-object")
        name = claim.get("spec", {}).get("volumeName")
        if not name:
            continue
        volume = kubectl_json_optional(kubeconfig, ["get", "pv", name])
        if volume is None:
            if name not in saved_persistent_volumes:
                raise TalosLifecycleError(
                    f"unknown bound PersistentVolume {name} is absent during inventory"
                )
            persistent_volumes.add(name)
            continue
        if volume.get("spec", {}).get("persistentVolumeReclaimPolicy") == "Retain":
            persistent_volumes.add(name)
    if bound_resource(
        kubeconfig,
        ["get", "namespace", cluster],
        namespace_uid,
        "Namespace",
    ) is None:
        raise TalosLifecycleError("Namespace disappeared during inventory")
    return data_volume_uids, persistent_volumes


def confirm_teardown(cluster: str, persistent_volumes: list[str], confirm: str) -> None:
    print(f"Tearing down Talos cluster {cluster}...")
    if persistent_volumes:
        print(
            "  VM disks use ok-storage-* (reclaimPolicy: Retain) -- these "
            "PV(s) survive cluster deletion by design and will be cleaned up here:"
        )
        for volume in persistent_volumes:
            print(f"    {volume}")
    if confirm == "yes":
        return
    suffix = ""
    if persistent_volumes:
        suffix = (
            f", and {len(persistent_volumes)} Retain-policy "
            "PV(s)/Longhorn volume(s)"
        )
    print(
        f"⚠️  This will TEAR DOWN {cluster}: Cluster object, namespace, "
        f"local render directory{suffix}."
    )
    prompt = f"Are you sure you want to tear down {cluster}? [y/N] "
    answer = "n"
    try:
        if sys.stdin.isatty():
            answer = input(prompt)
        else:
            print(prompt, end="", flush=True)
            with Path("/dev/tty").open(encoding="utf-8") as terminal:
                answer = terminal.readline().strip()
    except OSError:
        print()
    if answer.lower() not in ("y", "yes"):
        raise TalosLifecycleError(
            "Aborted. Re-run with CONFIRM=yes to skip this prompt (e.g. in CI)."
        )


def api_path(
    resource: dict,
    plural: str,
    *,
    expected_group: str | None = None,
) -> str:
    api_version = resource.get("apiVersion")
    metadata = resource.get("metadata", {})
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if not isinstance(api_version, str) or not name:
        raise TalosLifecycleError("delete target API identity is incomplete")
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        if expected_group is not None and group != expected_group:
            raise TalosLifecycleError("delete target API group is invalid")
        prefix = f"/apis/{quote(group, safe='')}/{quote(version, safe='')}"
    else:
        if expected_group is not None or api_version != "v1":
            raise TalosLifecycleError("delete target API version is invalid")
        prefix = f"/api/{quote(api_version, safe='')}"
    if namespace:
        prefix += f"/namespaces/{quote(namespace, safe='')}"
    return f"{prefix}/{quote(plural, safe='')}/{quote(name, safe='')}"


def preconditioned_delete(
    kubeconfig: Path,
    resource: dict,
    raw_path: str,
    get_arguments: list[str],
    description: str,
    *,
    propagation_policy: str | None = None,
    include_resource_version: bool = True,
    timeout_seconds: int = 600,
) -> None:
    metadata = resource.get("metadata", {})
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    if not uid or (include_resource_version and not resource_version):
        raise TalosLifecycleError(
            f"{description} UID/resourceVersion is absent"
        )
    options = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
    }
    if include_resource_version:
        options["preconditions"]["resourceVersion"] = resource_version
    if propagation_policy is not None:
        options["propagationPolicy"] = propagation_policy
    result = kubectl(
        kubeconfig,
        ["delete", "--raw", raw_path, "-f", "-"],
        expected=(0, 1),
        input_text=json.dumps(options, sort_keys=True, separators=(",", ":")),
    )
    if result.returncode != 0:
        if kubectl_not_found(result):
            print(f"SKIP {description} already absent")
            return
        raise TalosLifecycleError(
            f"{description} delete failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    deadline = time.monotonic() + timeout_seconds
    while True:
        current = kubectl_json_optional(kubeconfig, get_arguments)
        if current is None:
            return
        current_uid = current.get("metadata", {}).get("uid")
        if current_uid != uid:
            raise TalosLifecycleError(
                f"{description} was replaced while waiting for deletion"
            )
        if time.monotonic() >= deadline:
            raise TalosLifecycleError(
                f"{description} was not deleted within {timeout_seconds}s"
            )
        time.sleep(2)


def delete_resource(
    kubeconfig: Path, arguments: list[str], description: str
) -> None:
    result = kubectl(kubeconfig, arguments, expected=(0, 1))
    if result.returncode == 0:
        return
    if kubectl_not_found(result):
        print(f"SKIP {description} already absent")
        return
    raise TalosLifecycleError(
        f"{description} delete failed: "
        f"{result.stderr.strip() or result.stdout.strip()}"
    )


def teardown_storage_uids(
    kubeconfig: Path, names: list[str], saved: dict,
) -> dict:
    """Capture new storage provenance, but never rebind an existing name."""
    identities = dict(saved)
    for name in names:
        observed = {}
        for kind, arguments in (
            ("pv", ["get", "pv", name]),
            ("longhorn", ["-n", "longhorn-system", "get", "volumes.longhorn.io", name]),
        ):
            resource = kubectl_json_optional(kubeconfig, arguments)
            uid = None
            if resource is not None:
                uid = resource.get("metadata", {}).get("uid")
                if not isinstance(uid, str) or not uid:
                    raise TalosLifecycleError(f"{kind} {name} storage UID is absent")
            if name in saved and resource is not None and uid != saved[name][kind]:
                raise TalosLifecycleError(f"{kind} {name} differs from durable storage UID")
            observed[kind] = uid
        if name not in saved:
            if observed["pv"] is None:
                raise TalosLifecycleError(f"PV {name} disappeared before storage provenance")
            identities[name] = observed
    return identities


def cleanup_retained_volumes(
    kubeconfig: Path, names: list[str], *, storage_uids: dict | None = None,
) -> list[str]:
    require_longhorn_absence = storage_uids is not None
    failures = []
    if names:
        print(
            "Cleaning up Retain-policy PVs and their underlying Longhorn volumes..."
        )
    for name in names:
        try:
            volume = kubectl_json_optional(kubeconfig, ["get", "pv", name])
            if volume is None:
                print(f"SKIP PersistentVolume {name} already absent")
            else:
                if storage_uids is not None and volume.get("metadata", {}).get("uid") != storage_uids[name]["pv"]:
                    raise TalosLifecycleError(f"PV {name} differs from durable storage UID")
                if volume.get("metadata", {}).get("name") != name:
                    raise TalosLifecycleError(
                        f"PersistentVolume {name} identity is invalid"
                    )
                preconditioned_delete(
                    kubeconfig,
                    volume,
                    api_path(volume, "persistentvolumes"),
                    ["get", "pv", name],
                    f"PersistentVolume {name}",
                )
        except TalosLifecycleError as error:
            failures.append(str(error))
            if require_longhorn_absence:
                # Do not delete backing storage after an uncertain PV operation.
                continue
        try:
            if require_longhorn_absence:
                volume = kubectl_json_optional(
                    kubeconfig, ["-n", "longhorn-system", "get", "volumes.longhorn.io", name]
                )
                if volume is not None:
                    if volume.get("metadata", {}).get("uid") != storage_uids[name]["longhorn"]:
                        raise TalosLifecycleError(f"Longhorn volume {name} differs from durable storage UID")
                    preconditioned_delete(
                        kubeconfig, volume,
                        api_path(volume, "volumes", expected_group="longhorn.io"),
                        ["-n", "longhorn-system", "get", "volumes.longhorn.io", name],
                        f"Longhorn volume {name}",
                    )
                continue
            delete_resource(
                kubeconfig,
                [
                    "-n",
                    "longhorn-system",
                    "delete",
                    "volumes.longhorn.io",
                    name,
                ],
                f"Longhorn volume {name}",
            )
        except TalosLifecycleError as error:
            if require_longhorn_absence:
                failures.append(str(error))
            else:
                print(f"WARN {error}", file=sys.stderr)
    return failures


def cleanup_authorization(
    args: argparse.Namespace,
    *,
    config: dict | None = None,
    data_volume_uids: set[str] | None = None,
    golden_before: dict | None = None,
    kubeconfig: Path | None = None,
) -> int:
    if config is None:
        config, manifest, kubeconfig = inputs(args)
        validate_manifest(config, manifest)
    elif kubeconfig is None:
        kubeconfig = Path(args.kubeconfig).expanduser().resolve()
        if not kubeconfig.is_file():
            raise TalosLifecycleError(
                f"explicit management kubeconfig is absent: {kubeconfig}"
            )
    before = verify_golden(config, kubeconfig)
    if golden_before is not None and before != golden_before:
        raise TalosLifecycleError(
            "shared Talos Golden PVC differs from the teardown record"
        )
    cluster = config["name"]
    golden_namespace = config["os"]["goldenImage"]["namespace"]
    authorization = f"{cluster}-talos-golden-image-cloner"
    absent = set()
    authorization_objects = {}
    for kind in ("role", "rolebinding"):
        found = kubectl(
            kubeconfig,
            ["-n", golden_namespace, "get", kind, authorization, "-o", "json"],
            expected=(0, 1),
        )
        if found.returncode != 0:
            # Only an explicit NotFound means "already removed"; any other
            # read failure must still fail the teardown.
            if not kubectl_not_found(found):
                raise TalosLifecycleError(
                    f"{kind} {authorization} read failed: {found.stderr.strip()}"
                )
            print(f"SKIP {kind} {golden_namespace}/{authorization} already absent")
            absent.add(kind)
            continue
        obj = json.loads(found.stdout)
        if not isinstance(obj, dict):
            raise TalosLifecycleError(
                f"{kind} clone authorization read is not an object"
            )
        metadata = obj.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TalosLifecycleError(
                f"{kind} clone authorization metadata is invalid"
            )
        labels = metadata.get("labels") or {}
        if not isinstance(labels, dict):
            raise TalosLifecycleError(
                f"{kind} clone authorization labels are invalid"
            )
        if (
            metadata.get("name") != authorization
            or metadata.get("namespace") != golden_namespace
            or labels.get("openkubes.io/type") != "talos"
            or labels.get("openkubes.io/consumer-cluster") != cluster
            or labels.get("openkubes.io/os-identity")
            != config["os"]["identity"].removeprefix("sha256:")[:12]
        ):
            raise TalosLifecycleError(
                f"{kind} clone authorization ownership is invalid"
            )
        authorization_objects[kind] = obj
    for kind in ("rolebinding", "role"):
        if kind in absent:
            continue
        plural = "rolebindings" if kind == "rolebinding" else "roles"
        obj = authorization_objects[kind]
        preconditioned_delete(
            kubeconfig,
            obj,
            api_path(
                obj,
                plural,
                expected_group="rbac.authorization.k8s.io",
            ),
            [
                "-n",
                golden_namespace,
                "get",
                kind,
                authorization,
            ],
            f"{kind} {golden_namespace}/{authorization}",
        )
    for kind in ("role", "rolebinding"):
        if kubectl_json_optional(
            kubeconfig,
            ["-n", golden_namespace, "get", kind, authorization],
        ) is not None:
            raise TalosLifecycleError(
                f"{kind} clone authorization remains after cleanup"
            )
    if data_volume_uids is None:
        data_volume_uids = {
            value for value in args.data_volume_uids.split(",") if value
        }
    removed_snapshots = []
    if data_volume_uids:
        snapshot_list = kubectl_json(
            kubeconfig,
            ["-n", golden_namespace, "get", "volumesnapshots"],
        )
        snapshots = snapshot_list.get("items")
        if not isinstance(snapshots, list):
            raise TalosLifecycleError("VolumeSnapshot inventory is not a list")
        owned_snapshots = []
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                raise TalosLifecycleError(
                    "VolumeSnapshot inventory contains a non-object"
                )
            metadata = snapshot.get("metadata", {})
            if not isinstance(metadata, dict):
                raise TalosLifecycleError(
                    "VolumeSnapshot metadata is invalid"
                )
            labels = metadata.get("labels") or {}
            if not isinstance(labels, dict):
                raise TalosLifecycleError("VolumeSnapshot labels are invalid")
            if labels.get("cdi.kubevirt.io/OwnedByUID") not in data_volume_uids:
                continue
            if (
                labels.get("app") != "containerized-data-importer"
                or snapshot.get("spec", {})
                .get("source", {})
                .get("persistentVolumeClaimName")
                != config["os"]["goldenImage"]["claim"]
            ):
                raise TalosLifecycleError(
                    "cluster-owned CDI snapshot source is invalid"
                )
            if not metadata.get("name"):
                raise TalosLifecycleError(
                    "cluster-owned CDI snapshot name is absent"
                )
            if metadata.get("namespace") != golden_namespace:
                raise TalosLifecycleError(
                    "cluster-owned CDI snapshot namespace is invalid"
                )
            owned_snapshots.append(snapshot)
        for snapshot in owned_snapshots:
            metadata = snapshot["metadata"]
            name = metadata["name"]
            preconditioned_delete(
                kubeconfig,
                snapshot,
                api_path(
                    snapshot,
                    "volumesnapshots",
                    expected_group="snapshot.storage.k8s.io",
                ),
                [
                    "-n",
                    golden_namespace,
                    "get",
                    "volumesnapshot",
                    name,
                ],
                f"VolumeSnapshot {golden_namespace}/{name}",
            )
            removed_snapshots.append(name)
        remaining_list = kubectl_json(
            kubeconfig,
            ["-n", golden_namespace, "get", "volumesnapshots"],
        )
        remaining = remaining_list.get("items")
        if not isinstance(remaining, list):
            raise TalosLifecycleError(
                "remaining VolumeSnapshot inventory is not a list"
            )
        if any(
            item.get("metadata", {})
            .get("labels", {})
            .get("cdi.kubevirt.io/OwnedByUID")
            in data_volume_uids
            for item in remaining
        ):
            raise TalosLifecycleError(
                "cluster-owned CDI snapshots remain after cleanup"
            )
    after = verify_golden(config, kubeconfig)
    if after != before:
        raise TalosLifecycleError("shared Talos Golden PVC changed on cleanup")
    print(
        f"PASS clone RBAC {golden_namespace}/{authorization} "
        f"removed={sorted({'role', 'rolebinding'} - absent)} "
        f"already_absent={sorted(absent)}; "
        f"removed_snapshots={len(removed_snapshots)} "
        f"preserved golden_uid={after['uid']}"
    )
    return 0


def teardown_plane_uid(kubeconfig: Path) -> str:
    """Bind authority to a live cluster identity, never a token or path name."""
    namespace = kubectl_json(kubeconfig, ["get", "namespace", "kube-system"])
    uid = namespace.get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not uid:
        raise TalosLifecycleError("kube-system UID is required to bind teardown authority")
    return uid


def remove_local_teardown_files(args: argparse.Namespace) -> None:
    cluster_dir = cluster_directory(args)
    # Split-plane runs contain immutable CLI evidence. Never remove it as a
    # side effect of infrastructure teardown, including completed-record retries.
    if getattr(args, "provider_kubeconfig", None) or getattr(args, "preserve_local", False):
        print(f"PRESERVE local cluster directory {cluster_dir}")
    elif cluster_dir.exists():
        shutil.rmtree(cluster_dir)


def teardown(args: argparse.Namespace) -> int:
    kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    if not kubeconfig.is_file():
        raise TalosLifecycleError(
            f"explicit management kubeconfig is absent: {kubeconfig}"
        )
    provider_argument = getattr(args, "provider_kubeconfig", None)
    provider = Path(provider_argument).expanduser().resolve() if provider_argument else kubeconfig
    if not provider.is_file():
        raise TalosLifecycleError(f"explicit provider kubeconfig is absent: {provider}")
    planes = None
    if provider_argument:
        planes = {
            "management_uid": teardown_plane_uid(kubeconfig),
            "provider_uid": teardown_plane_uid(provider),
        }
        if planes["management_uid"] == planes["provider_uid"]:
            raise TalosLifecycleError("separate provider kubeconfig must identify a different plane")
    local_config = local_teardown_config(args)
    if local_config is not None and local_config.get("infraClusterSecretRef") and not planes:
        raise TalosLifecycleError(
            "external provider reference requires explicit --provider-kubeconfig for teardown"
        )
    configmap = read_teardown_configmap(kubeconfig, args.cluster)
    record = (
        teardown_record_from_configmap(configmap, args.cluster)
        if configmap is not None
        else None
    )
    if record is not None:
        saved_planes = record.get("planes")
        if (saved_planes is None) != (planes is None) or (
            saved_planes is not None
            and any(saved_planes[key] != value for key, value in planes.items())
        ):
            raise TalosLifecycleError("teardown plane authority differs from durable record")
    if local_config is None and record is None:
        raise TalosLifecycleError(
            "cleanup state cannot be determined: local cluster config and durable "
            "teardown record are both absent; missing Golden namespace/claim/OS "
            "identity and DataVolume inventory"
        )
    if record is not None and record["complete"]:
        cluster = kubectl_json_optional(
            kubeconfig, ["-n", args.cluster, "get", "cluster", args.cluster]
        )
        namespace = kubectl_json_optional(
            kubeconfig, ["get", "namespace", args.cluster]
        )
        provider_namespace = (
            bound_resource(provider, ["get", "namespace", args.cluster],
                           record["planes"]["provider_namespace_uid"], "Provider Namespace")
            if planes else None
        )
        if cluster is None and namespace is None and provider_namespace is None:
            if local_config is not None:
                remove_local_teardown_files(args)
            print(f"SKIP Talos cluster {args.cluster} already torn down")
            return 0
        if any(
            resource is not None and resource.get("metadata", {}).get("uid") != uid
            for resource, uid in (
                (cluster, record["cluster"]["uid"]),
                (namespace, record["namespace_uid"]),
            )
        ):
            if planes:
                raise TalosLifecycleError("completed split-plane record belongs to another generation")
            record = None
        else:
            raise TalosLifecycleError(
                "completed teardown record conflicts with live original resources"
            )
    fresh_record = record is None
    if fresh_record and local_config is None:
        raise TalosLifecycleError(
            "local cluster config is required to record a new teardown"
        )
    if record is not None and local_config is not None:
        if teardown_config_subset(local_config) != record["config"]:
            raise TalosLifecycleError(
                "local cluster config differs from the durable teardown record"
            )

    if record is not None:
        bound_cluster = bound_resource(
            kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        bound_namespace = bound_resource(
            kubeconfig,
            ["get", "namespace", args.cluster],
            record["namespace_uid"],
            "Namespace",
        )
        bound_provider_namespace = (
            bound_resource(provider, ["get", "namespace", args.cluster],
                           record["planes"]["provider_namespace_uid"], "Provider Namespace")
            if planes else bound_namespace
        )
    else:
        namespace = kubectl_json_optional(
            kubeconfig, ["get", "namespace", args.cluster]
        )
        cluster = kubectl_json_optional(
            kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
        )
        if namespace is None or cluster is None:
            raise TalosLifecycleError(
                "Cluster or Namespace is already absent before durable teardown "
                "provenance could be recorded"
            )
        namespace_uid = namespace.get("metadata", {}).get("uid")
        cluster_uid = cluster.get("metadata", {}).get("uid")
        if not namespace_uid or not cluster_uid:
            raise TalosLifecycleError("live Cluster or Namespace UID is absent")
        bound_provider_namespace = (
            kubectl_json_optional(provider, ["get", "namespace", args.cluster])
            if planes else namespace
        )
        provider_namespace_uid = (bound_provider_namespace or {}).get("metadata", {}).get("uid")
        if not provider_namespace_uid:
            raise TalosLifecycleError("Provider Namespace UID is absent before durable provenance")
        config_identity = teardown_config_subset(local_config)
        data_volume_uids, persistent_volumes = teardown_inventory(
            provider,
            args.cluster,
            config_identity,
            provider_namespace_uid,
            set(),
        )
        golden_before = (
            verify_golden(local_config, provider)
            if has_golden_config(local_config)
            else None
        )
        record = {
            "schema_version": TEARDOWN_LEDGER_SCHEMA,
            "cluster": {
                "name": args.cluster,
                "namespace": args.cluster,
                "uid": cluster_uid,
            },
            "namespace_uid": namespace_uid,
            "config": config_identity,
            "golden_before": golden_before,
            "data_volume_uids": sorted(data_volume_uids),
            "persistent_volumes": sorted(persistent_volumes),
            "complete": False,
        }
        if planes:
            record["schema_version"] = SPLIT_TEARDOWN_LEDGER_SCHEMA
            record["planes"] = {**planes, "provider_namespace_uid": provider_namespace_uid}
            record["storage_uids"] = teardown_storage_uids(
                provider, record["persistent_volumes"], {},
            )
        bound_cluster = cluster
        bound_namespace = namespace

    confirm_teardown(
        args.cluster, record["persistent_volumes"], args.confirm
    )
    if planes:
        # Check saved identities before any mutation, including an operator retry.
        teardown_storage_uids(provider, record["persistent_volumes"], record["storage_uids"])
    if fresh_record:
        current_cluster = bound_resource(
            kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        current_namespace = bound_resource(
            kubeconfig,
            ["get", "namespace", args.cluster],
            record["namespace_uid"],
            "Namespace",
        )
        if current_cluster is None or current_namespace is None:
            raise TalosLifecycleError(
                "Cluster or Namespace disappeared before durable teardown "
                "provenance could be recorded"
            )
        if planes and bound_resource(
            provider, ["get", "namespace", args.cluster],
            record["planes"]["provider_namespace_uid"], "Provider Namespace",
        ) is None:
            raise TalosLifecycleError("Provider Namespace disappeared before durable provenance")
        configmap = persist_teardown_record(
            kubeconfig, args.cluster, record, configmap
        )

    failures = []
    try:
        current_cluster = bound_resource(
            kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        if current_cluster is None:
            print(f"SKIP CAPI Cluster {args.cluster}/{args.cluster} already absent")
        else:
            preconditioned_delete(
                kubeconfig,
                current_cluster,
                api_path(
                    current_cluster,
                    "clusters",
                    expected_group="cluster.x-k8s.io",
                ),
                [
                    "-n",
                    args.cluster,
                    "get",
                    "cluster",
                    args.cluster,
                ],
                f"CAPI Cluster {args.cluster}/{args.cluster}",
                propagation_policy="Foreground",
                include_resource_version=False,
            )
    except TalosLifecycleError as error:
        failures.append(str(error))

    cluster_after = None
    try:
        cluster_after = bound_resource(
            kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        if cluster_after is not None:
            failures.append("original CAPI Cluster remains after delete")
    except TalosLifecycleError as error:
        failures.append(str(error))
        cluster_after = {"read_failed": True}

    provider_namespace_uid = record["planes"]["provider_namespace_uid"] if planes else record["namespace_uid"]
    inventory_ready = bound_provider_namespace is None
    if cluster_after is None and bound_provider_namespace is not None:
        try:
            refreshed_uids, refreshed_volumes = teardown_inventory(
                provider,
                args.cluster,
                record["config"],
                provider_namespace_uid,
                set(record["persistent_volumes"]),
            )
            refreshed = dict(record)
            refreshed["data_volume_uids"] = sorted(
                set(record["data_volume_uids"]) | refreshed_uids
            )
            refreshed["persistent_volumes"] = sorted(
                set(record["persistent_volumes"]) | refreshed_volumes
            )
            if planes:
                refreshed["storage_uids"] = teardown_storage_uids(
                    provider, refreshed["persistent_volumes"], record["storage_uids"],
                )
            configmap = persist_teardown_record(
                kubeconfig, args.cluster, refreshed, configmap
            )
            record = refreshed
            inventory_ready = True
        except TalosLifecycleError as error:
            failures.append(f"namespace inventory refresh failed: {error}")

    namespace_targets = [(provider, provider_namespace_uid)]
    if planes:
        namespace_targets.append((kubeconfig, record["namespace_uid"]))
    namespace_absent = True
    for namespace_kubeconfig, namespace_uid in namespace_targets:
        if cluster_after is None and inventory_ready and namespace_absent:
            try:
                current_namespace = bound_resource(
                    namespace_kubeconfig, ["get", "namespace", args.cluster],
                    namespace_uid, "Namespace",
                )
                if current_namespace is not None:
                    preconditioned_delete(
                        namespace_kubeconfig, current_namespace,
                        api_path(current_namespace, "namespaces"),
                        ["get", "namespace", args.cluster], f"Namespace {args.cluster}",
                        propagation_policy="Foreground", include_resource_version=False,
                    )
            except TalosLifecycleError as error:
                failures.append(str(error))
        try:
            if bound_resource(namespace_kubeconfig, ["get", "namespace", args.cluster],
                              namespace_uid, "Namespace") is not None:
                namespace_absent = False
                failures.append("original Namespace remains after delete")
        except TalosLifecycleError as error:
            namespace_absent = False
            failures.append(str(error))

    if cluster_after is None and namespace_absent:
        failures.extend(
            cleanup_retained_volumes(
                provider, record["persistent_volumes"], storage_uids=record.get("storage_uids")
            )
        )
        config = config_from_teardown_record(record)
        if has_golden_config(config):
            try:
                cleanup_authorization(
                    args,
                    config=config,
                    data_volume_uids=set(record["data_volume_uids"]),
                    golden_before=record["golden_before"],
                    kubeconfig=provider,
                )
            except TalosLifecycleError as error:
                failures.append(f"Golden clone cleanup failed: {error}")

    if failures:
        raise TalosLifecycleError(
            "teardown incomplete; retry after correcting: " + "; ".join(failures)
        )

    completed = dict(record)
    completed["complete"] = True
    persist_teardown_record(kubeconfig, args.cluster, completed, configmap)
    remove_local_teardown_files(args)
    print(
        f"✅ Talos cluster {args.cluster} torn down "
        "(including Retain-policy PV cleanup)"
    )
    return 0


def parse_args() -> argparse.Namespace:
    def positive_finite(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("must be a number") from error
        if not math.isfinite(parsed) or parsed <= 0:
            raise argparse.ArgumentTypeError("must be positive and finite")
        return parsed

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--replacement-preflight", action="store_true")
    mode.add_argument("--replacement-wait", action="store_true")
    mode.add_argument("--runtime-evidence", action="store_true")
    mode.add_argument("--cleanup-authorization", action="store_true")
    mode.add_argument("--resume-preconditions", action="store_true")
    mode.add_argument("--teardown", action="store_true")
    mode.add_argument("--wait-expected-nodes", action="store_true")
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--cluster-dir")
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--provider-kubeconfig", help="Separate provider plane (teardown only; preserves local files)")
    parser.add_argument("--preserve-local", action="store_true", help="Keep local render and evidence after teardown")
    parser.add_argument("--ok-linux-path", required=True)
    parser.add_argument("--confirm", default="false")
    parser.add_argument("--workload-kubeconfig")
    parser.add_argument("--cilium-chart")
    parser.add_argument("--data-volume-uids", default="")
    parser.add_argument("--replacement-timeout-seconds", type=int, default=600)
    parser.add_argument(
        "--expected-nodes-timeout-seconds", type=positive_finite, default=300.0
    )
    parser.add_argument(
        "--expected-nodes-poll-seconds", type=positive_finite, default=5.0
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (args.provider_kubeconfig or args.preserve_local) and not args.teardown:
        raise TalosLifecycleError("--provider-kubeconfig and --preserve-local require --teardown")
    if args.preflight:
        return preflight(args)
    if args.replacement_preflight:
        return replacement_preflight(args)
    if args.replacement_wait:
        if args.replacement_timeout_seconds <= 0:
            raise TalosLifecycleError(
                "--replacement-timeout-seconds must be positive"
            )
        return replacement_wait(args)
    if args.runtime_evidence:
        if not args.workload_kubeconfig or not args.cilium_chart:
            raise TalosLifecycleError(
                "--runtime-evidence requires --workload-kubeconfig "
                "and --cilium-chart"
            )
        return runtime_evidence(args)
    if args.resume_preconditions:
        return resume_preconditions(args)
    if args.wait_expected_nodes:
        return wait_expected_nodes(args)
    if args.teardown:
        if not args.cluster_dir:
            raise TalosLifecycleError("--teardown requires --cluster-dir")
        try:
            return teardown(args)
        except (
            TalosLifecycleError,
            TalosProfileError,
            AttributeError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            yaml.YAMLError,
        ) as error:
            print(
                f"❌ Teardown of {args.cluster} incomplete; "
                "re-run make teardown "
                f"CLUSTER={args.cluster} after fixing: {error}",
                file=sys.stderr,
            )
            return 1
    return cleanup_authorization(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ChartAcquisitionError,
        TalosLifecycleError,
        TalosProfileError,
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
