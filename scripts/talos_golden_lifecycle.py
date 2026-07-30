#!/usr/bin/env python3
"""Guard the OK-130 Talos Golden-Image consumer lifecycle."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "adoption" / "OK-130" / ".evidence"
sys.path.insert(0, str(ROOT))

from profile_resolvers.talos import (  # noqa: E402
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
    command: list[str], expected: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
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
) -> subprocess.CompletedProcess[str]:
    return run(
        ["kubectl", "--kubeconfig", str(kubeconfig), *arguments],
        expected,
    )


def kubectl_json(kubeconfig: Path, arguments: list[str]) -> dict:
    return json.loads(
        kubectl(kubeconfig, [*arguments, "-o", "json"]).stdout
    )


def inputs(args: argparse.Namespace) -> tuple[dict, Path, Path]:
    if not args.cluster:
        raise TalosLifecycleError("--cluster is required")
    config_path = ROOT / args.cluster / "cluster-config.yaml"
    manifest_path = ROOT / args.cluster / "cluster-base.yaml"
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


def validate_manifest(config: dict, manifest_path: Path) -> None:
    docs = objects(manifest_path)
    text = manifest_path.read_text(encoding="utf-8")
    if (
        "${" in text
        or "source:\n                http:" in text
        or "source:\n                      registry:" in text
        or "factory.talos.dev/image/" in text
        or "kind: Secret" in text
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


def verify_scheduling(kubeconfig: Path) -> dict:
    node = kubectl_json(kubeconfig, ["get", "node", "ok-infra"])
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
        raise TalosLifecycleError("ok-infra is not Ready and schedulable")
    return {
        "name": node["metadata"]["name"],
        "uid": node["metadata"]["uid"],
        "ready": True,
        "schedulable": True,
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


def runtime_evidence(args: argparse.Namespace) -> int:
    """Record a read-only warm-provisioning result, separate from publication."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    kubevirt = verify_kubevirt(kubeconfig)
    scheduling = verify_scheduling(kubeconfig)
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
    golden_source = config["os"]["goldenImage"]
    if len(data_volumes) < expected_count:
        raise TalosLifecycleError("expected Talos boot DataVolumes are absent")
    sources = [item.get("spec", {}).get("source", {}) for item in data_volumes]
    if any(
        source != {
            "pvc": {
                "namespace": golden_source["namespace"],
                "name": golden_source["claim"],
            }
        }
        for source in sources
    ):
        raise TalosLifecycleError(
            "runtime DataVolume used a non-Golden or public source"
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
    scheduling = verify_scheduling(kubeconfig)
    golden = verify_golden(config, kubeconfig)
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
        f"expand_disks={kubevirt['expand_disks']} golden_uid={golden['uid']}"
    )
    return 0


def replacement_preflight(args: argparse.Namespace) -> int:
    """Verify a live cluster may consume a newly published Golden identity."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    kubevirt = verify_kubevirt(kubeconfig)
    scheduling = verify_scheduling(kubeconfig)
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
                and "NotFound" not in annotation.stderr
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


def cleanup_authorization(args: argparse.Namespace) -> int:
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
    before = verify_golden(config, kubeconfig)
    cluster = config["name"]
    golden_namespace = config["os"]["goldenImage"]["namespace"]
    authorization = f"{cluster}-talos-golden-image-cloner"
    for kind in ("role", "rolebinding"):
        obj = kubectl_json(
            kubeconfig,
            [
                "-n",
                golden_namespace,
                "get",
                kind,
                authorization,
            ],
        )
        labels = obj["metadata"].get("labels", {})
        if (
            labels.get("openkubes.io/type") != "talos"
            or labels.get("openkubes.io/consumer-cluster") != cluster
            or labels.get("openkubes.io/os-identity")
            != config["os"]["identity"].removeprefix("sha256:")[:12]
        ):
            raise TalosLifecycleError(
                f"{kind} clone authorization ownership is invalid"
            )
    for kind in ("rolebinding", "role"):
        kubectl(
            kubeconfig,
            [
                "-n",
                golden_namespace,
                "delete",
                kind,
                authorization,
            ],
        )
    data_volume_uids = {
        value for value in args.data_volume_uids.split(",") if value
    }
    removed_snapshots = []
    if data_volume_uids:
        snapshots = kubectl_json(
            kubeconfig,
            ["-n", golden_namespace, "get", "volumesnapshots"],
        ).get("items", [])
        for snapshot in snapshots:
            metadata = snapshot.get("metadata", {})
            labels = metadata.get("labels", {})
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
            name = metadata["name"]
            kubectl(
                kubeconfig,
                [
                    "-n",
                    golden_namespace,
                    "delete",
                    "volumesnapshot",
                    name,
                ],
            )
            removed_snapshots.append(name)
        remaining = kubectl_json(
            kubeconfig,
            ["-n", golden_namespace, "get", "volumesnapshots"],
        ).get("items", [])
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
        f"PASS removed {golden_namespace}/{authorization}; "
        f"removed_snapshots={len(removed_snapshots)} "
        f"preserved golden_uid={after['uid']}"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--replacement-preflight", action="store_true")
    mode.add_argument("--replacement-wait", action="store_true")
    mode.add_argument("--runtime-evidence", action="store_true")
    mode.add_argument("--cleanup-authorization", action="store_true")
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--ok-linux-path", required=True)
    parser.add_argument("--workload-kubeconfig")
    parser.add_argument("--cilium-chart")
    parser.add_argument("--data-volume-uids", default="")
    parser.add_argument("--replacement-timeout-seconds", type=int, default=600)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
    return cleanup_authorization(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ChartAcquisitionError,
        TalosLifecycleError,
        TalosProfileError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
