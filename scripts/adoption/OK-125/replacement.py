#!/usr/bin/env python3
"""Guarded OK-125 G2 healthy and failed CAPI replacement evidence."""

from __future__ import annotations

import base64
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

import runtime as shared


ROOT = shared.ROOT
OK_LINUX = shared.OK_LINUX
EVIDENCE = shared.EVIDENCE
REPLACEMENT_DIR = EVIDENCE / "replacement"
RESULT = EVIDENCE / "replacement.json"

BASE_IDENTITY = shared.EXPECTED_OS_IDENTITY
HEALTHY_IDENTITY = (
    "sha256:6030632e0a7ce2972566b0b49d4e6bdad1780cd5b714c5635df9c51cd6f8866e"
)
UNHEALTHY_IDENTITY = (
    "sha256:fd0981887afe2af5b3b7acfeac39de71a2029d57811982c4d52fd2a7bf8630ff"
)
VARIANTS = {
    "healthy": {
        "identity": HEALTHY_IDENTITY,
        "profile_revision": 2,
        "node_selector": "ok-infra",
    },
    "deliberately_unhealthy": {
        "identity": UNHEALTHY_IDENTITY,
        "profile_revision": 3,
        "node_selector": "ok125-no-such-node",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def transient_workload_api_error(detail: str) -> bool:
    return any(
        term in detail.lower()
        for term in (
            "connection refused",
            "was refused",
            "i/o timeout",
            "context deadline exceeded",
            "tls handshake timeout",
        )
    )


def short(identity: str) -> str:
    return identity.removeprefix("sha256:")[:12]


def repo_state(path: Path) -> dict[str, object]:
    commit = shared.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"]
    ).stdout.strip()
    dirty = bool(
        shared.run(
            ["git", "-C", str(path), "status", "--porcelain"]
        ).stdout.strip()
    )
    pushed = bool(
        shared.run(
            ["git", "-C", str(path), "branch", "-r", "--contains", "HEAD"]
        ).stdout.strip()
    )
    return {"commit": commit, "clean": not dirty, "pushed": pushed}


def load_yaml_documents(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [item for item in yaml.safe_load_all(stream) if item]


def render_variant(variant: str) -> tuple[Path, list[dict], dict]:
    if variant not in VARIANTS:
        raise shared.RuntimeValidationError(
            f"unsupported replacement profile variant: {variant}"
        )
    shared.progress(f"rendering G2 {variant} profile")
    result = shared.run(
        [
            "make",
            "--no-print-directory",
            "ok125-render",
            f"CLUSTER={shared.CLUSTER}",
            f"OK_LINUX_PATH={OK_LINUX}",
            f"OK125_PROFILE_VARIANT={variant}",
        ]
    )
    if "MANIFEST sha256:" not in result.stdout:
        raise shared.RuntimeValidationError(
            f"{variant} renderer did not emit a manifest identity"
        )
    manifest = REPLACEMENT_DIR / variant / "render" / "cluster-v2.yaml"
    if not manifest.is_file():
        raise shared.RuntimeValidationError(
            f"{variant} replacement manifest is missing"
        )
    documents = load_yaml_documents(manifest)
    namespaces = [item for item in documents if item["kind"] == "Namespace"]
    expected = VARIANTS[variant]
    selectors = {
        item["spec"]["template"]["spec"]["virtualMachineTemplate"]["spec"][
            "template"
        ]["spec"]["nodeSelector"]["kubernetes.io/hostname"]
        for item in documents
        if item["kind"] == "KubevirtMachineTemplate"
    }
    if (
        len(namespaces) != 1
        or namespaces[0]["metadata"]["annotations"][
            "openkubes.io/os-identity-full"
        ]
        != expected["identity"]
        or namespaces[0]["metadata"]["labels"][
            "openkubes.io/profile-revision"
        ]
        != str(expected["profile_revision"])
        or selectors != {expected["node_selector"]}
    ):
        raise shared.RuntimeValidationError(
            f"{variant} render identity guard failed"
        )
    return manifest, documents, {
        "variant": variant,
        "manifest_sha256": f"sha256:{shared.sha256(manifest)}",
        **expected,
    }


def by_kind(documents: list[dict], kind: str) -> list[dict]:
    return [item for item in documents if item["kind"] == kind]


def one_by_kind(documents: list[dict], kind: str) -> dict:
    matches = by_kind(documents, kind)
    if len(matches) != 1:
        raise shared.RuntimeValidationError(
            f"expected one {kind}, observed {len(matches)}"
        )
    return matches[0]


def write_documents(path: Path, documents: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    shared.write_yaml(path, documents)


def ensure_workload_kubeconfig(
    kubectl_bin: str,
    management_kubeconfig: Path,
) -> None:
    result = shared.kubectl(
        kubectl_bin,
        management_kubeconfig,
        [
            "-n",
            shared.CLUSTER,
            "get",
            "secret",
            f"{shared.CLUSTER}-kubeconfig",
            "-o",
            "json",
        ],
        sensitive_stdout=True,
    )
    secret = json.loads(result.stdout)
    encoded = secret.get("data", {}).get("value")
    if not encoded:
        raise shared.RuntimeValidationError(
            "workload kubeconfig Secret has no value key"
        )
    shared.WORKLOAD_KUBECONFIG.write_bytes(base64.b64decode(encoded))
    shared.WORKLOAD_KUBECONFIG.chmod(0o600)
    del encoded
    del secret


def node_role(node: dict) -> str:
    labels = node["metadata"].get("labels", {})
    return (
        "control-plane"
        if "node-role.kubernetes.io/control-plane" in labels
        else "worker"
    )


def ready_condition(node: dict) -> dict | None:
    return next(
        (
            condition
            for condition in node.get("status", {}).get("conditions", [])
            if condition.get("type") == "Ready"
        ),
        None,
    )


def node_snapshot(kubectl_bin: str) -> list[dict]:
    nodes = shared.kubectl_json(
        kubectl_bin,
        shared.WORKLOAD_KUBECONFIG,
        ["get", "node"],
    )["items"]
    result = []
    for node in nodes:
        ready = ready_condition(node)
        result.append(
            {
                "name": node["metadata"]["name"],
                "uid": node["metadata"]["uid"],
                "created_at": node["metadata"]["creationTimestamp"],
                "ready": ready is not None and ready.get("status") == "True",
                "ready_at": ready.get("lastTransitionTime") if ready else None,
                "provider_id": node["spec"].get("providerID", ""),
                "identity": node["metadata"]
                .get("labels", {})
                .get("openkubes.io/os-identity", ""),
                "profile_revision": node["metadata"]
                .get("labels", {})
                .get("openkubes.io/profile-revision", ""),
                "role": node_role(node),
                "os_image": node["status"]["nodeInfo"]["osImage"],
                "kubelet_version": node["status"]["nodeInfo"][
                    "kubeletVersion"
                ],
            }
        )
    return result


def machine_role(machine: dict) -> str:
    owners = machine["metadata"].get("ownerReferences", [])
    return (
        "control-plane"
        if any(owner.get("kind") == "KubeadmControlPlane" for owner in owners)
        else "worker"
    )


def machine_snapshot(
    kubectl_bin: str,
    management_kubeconfig: Path,
) -> list[dict]:
    machines = shared.kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", shared.CLUSTER, "get", "machine"],
    )["items"]
    return [
        {
            "name": machine["metadata"]["name"],
            "uid": machine["metadata"]["uid"],
            "created_at": machine["metadata"]["creationTimestamp"],
            "ready": shared.condition_is_true(machine, "Ready"),
            "available": shared.condition_is_true(machine, "Available"),
            "provider_id": machine["spec"].get("providerID", ""),
            "identity": machine["metadata"]
            .get("labels", {})
            .get("openkubes.io/os-identity", ""),
            "profile_revision": machine["metadata"]
            .get("labels", {})
            .get("openkubes.io/profile-revision", ""),
            "role": machine_role(machine),
            "phase": machine.get("status", {}).get("phase", ""),
        }
        for machine in machines
    ]


def machine_drain_event(
    kubectl_bin: str,
    management_kubeconfig: Path,
    machine_name: str,
) -> dict:
    events = shared.kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", shared.CLUSTER, "get", "event"],
    )["items"]
    matching = [
        event
        for event in events
        if event.get("involvedObject", {}).get("kind") == "Machine"
        and event.get("involvedObject", {}).get("name") == machine_name
        and event.get("reason") == "SuccessfulDrainNode"
    ]
    if not matching:
        raise shared.RuntimeValidationError(
            f"no SuccessfulDrainNode event for predecessor {machine_name}"
        )
    event = max(
        matching,
        key=lambda item: (
            item.get("eventTime")
            or item.get("lastTimestamp")
            or item["metadata"]["creationTimestamp"]
        ),
    )
    return {
        "reason": "SuccessfulDrainNode",
        "time": (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event["metadata"]["creationTimestamp"]
        ),
        "event_uid": event["metadata"]["uid"],
    }


def annotate_test_pvcs(
    kubectl_bin: str,
    management_kubeconfig: Path,
) -> None:
    pvcs = shared.kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", shared.CLUSTER, "get", "pvc"],
    )["items"]
    for pvc in pvcs:
        annotations = pvc["metadata"].get("annotations", {})
        if annotations.get("volume.kubernetes.io/selected-node") != "ok-infra":
            shared.kubectl(
                kubectl_bin,
                management_kubeconfig,
                [
                    "-n",
                    shared.CLUSTER,
                    "annotate",
                    "pvc",
                    pvc["metadata"]["name"],
                    "volume.kubernetes.io/selected-node=ok-infra",
                    "--overwrite",
                ],
            )


def patch_for(document: dict) -> dict:
    if document["kind"] == "KubeadmControlPlane":
        return {
            "metadata": {"labels": document["metadata"]["labels"]},
            "spec": {
                "rollout": document["spec"]["rollout"],
                "machineTemplate": document["spec"]["machineTemplate"],
                "kubeadmConfigSpec": document["spec"]["kubeadmConfigSpec"],
            },
        }
    if document["kind"] == "MachineDeployment":
        return {
            "metadata": {"labels": document["metadata"]["labels"]},
            "spec": {
                "rollout": document["spec"]["rollout"],
                "template": document["spec"]["template"],
            },
        }
    raise shared.RuntimeValidationError(
        f"patch generation is not allowed for {document['kind']}"
    )


def patch_resource(
    kubectl_bin: str,
    management_kubeconfig: Path,
    document: dict,
    *,
    dry_run: bool = False,
) -> None:
    kind = document["kind"].lower()
    name = document["metadata"]["name"]
    variant = document["metadata"]["labels"]["openkubes.io/os-identity"]
    suffix = "-dry-run" if dry_run else ""
    patch_path = REPLACEMENT_DIR / "runtime" / (
        f"{kind}-{variant}{suffix}-patch.json"
    )
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text(
        json.dumps(patch_for(document), indent=2) + "\n",
        encoding="utf-8",
    )
    arguments = [
        "-n",
        shared.CLUSTER,
        "patch",
        kind,
        name,
        "--type=merge",
        "--patch-file",
        str(patch_path),
    ]
    if dry_run:
        arguments.extend(["--dry-run=server", "-o", "name"])
    shared.kubectl(
        kubectl_bin,
        management_kubeconfig,
        arguments,
    )


def create_templates(
    kubectl_bin: str,
    management_kubeconfig: Path,
    documents: list[dict],
    variant: str,
    *,
    worker_only: bool = False,
) -> list[dict]:
    templates = [
        item
        for item in documents
        if item["kind"]
        in ("KubevirtMachineTemplate", "KubeadmConfigTemplate")
    ]
    if worker_only:
        templates = [
            item
            for item in templates
            if "-workers-" in item["metadata"]["name"]
        ]
    expected_count = 2 if worker_only else 3
    if len(templates) != expected_count:
        raise shared.RuntimeValidationError(
            f"{variant} template set has {len(templates)} objects"
        )
    for template in templates:
        existing = shared.kubectl(
            kubectl_bin,
            management_kubeconfig,
            [
                "-n",
                shared.CLUSTER,
                "get",
                template["kind"].lower(),
                template["metadata"]["name"],
                "-o",
                "name",
            ],
            expected=(0, 1),
        )
        if existing.returncode == 0:
            raise shared.RuntimeValidationError(
                f"replacement template already exists: "
                f"{template['kind']}/{template['metadata']['name']}"
            )
    path = REPLACEMENT_DIR / "runtime" / f"{variant}-templates.yaml"
    write_documents(path, templates)
    shared.kubectl(
        kubectl_bin,
        management_kubeconfig,
        [
            "create",
            "--dry-run=server",
            "--validate=strict",
            "-f",
            str(path),
            "-o",
            "name",
        ],
    )
    shared.kubectl(
        kubectl_bin,
        management_kubeconfig,
        ["create", "-f", str(path)],
    )
    return templates


def baseline_preflight(
    kubectl_bin: str,
    management_kubeconfig: Path,
) -> dict:
    node_ready_path = EVIDENCE / "node-ready.json"
    if not node_ready_path.is_file():
        raise shared.RuntimeValidationError("G1/G3 PASS evidence is missing")
    node_ready = json.loads(node_ready_path.read_text(encoding="utf-8"))
    if (
        node_ready.get("status") != "PASS"
        or node_ready.get("runtime_gates")
        != {
            "G1_kubernetes_node_ready": "PASS",
            "G3_provider_scoped_bootstrap_secret": "PASS",
        }
    ):
        raise shared.RuntimeValidationError("G1/G3 must pass before G2")

    namespace = shared.kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["get", "namespace", shared.CLUSTER],
    )
    labels = namespace["metadata"].get("labels", {})
    annotations = namespace["metadata"].get("annotations", {})
    if (
        labels.get("openkubes.io/type") != "flatcar"
        or labels.get("openkubes.io/adoption-status") != "adoption-gated"
        or labels.get("openkubes.io/deployable") != "false"
        or annotations.get("openkubes.io/os-identity-full") != BASE_IDENTITY
    ):
        raise shared.RuntimeValidationError(
            "live G2 baseline identity or ownership guard failed"
        )

    ensure_workload_kubeconfig(kubectl_bin, management_kubeconfig)
    nodes = node_snapshot(kubectl_bin)
    machines = machine_snapshot(kubectl_bin, management_kubeconfig)
    evidence_node_uids = {
        item["uid"] for item in node_ready["runtime"]["nodes"]
    }
    if (
        len(nodes) != 2
        or len(machines) != 2
        or not all(item["ready"] for item in nodes)
        or {item["uid"] for item in nodes} != evidence_node_uids
        or {item["role"] for item in nodes} != {"control-plane", "worker"}
        or {item["role"] for item in machines} != {"control-plane", "worker"}
    ):
        raise shared.RuntimeValidationError(
            "live cluster no longer matches the G1/G3 baseline"
        )
    node_provider_ids = {item["provider_id"] for item in nodes}
    if not all(
        item["provider_id"] in node_provider_ids for item in machines
    ):
        raise shared.RuntimeValidationError(
            "baseline Machine/Node ProviderIDs do not match"
        )
    return {
        "node_ready_source": node_ready["source"],
        "nodes": nodes,
        "machines": machines,
    }


def wait_for_healthy_replacement(
    kubectl_bin: str,
    management_kubeconfig: Path,
    baseline: dict,
    timeout: int = 900,
) -> dict:
    shared.progress(
        "waiting for healthy control-plane and worker replacements"
    )
    old_by_role = {item["role"]: item for item in baseline["machines"]}
    old_uids = {item["uid"] for item in baseline["machines"]}
    removed_observed: dict[str, str] = {}
    minimum_ready = 2
    api_unavailable_windows: list[dict] = []
    active_api_outage: dict | None = None
    deadline = time.monotonic() + timeout
    latest_nodes: list[dict] = []
    latest_machines: list[dict] = []
    while time.monotonic() < deadline:
        annotate_test_pvcs(kubectl_bin, management_kubeconfig)
        latest_machines = machine_snapshot(
            kubectl_bin, management_kubeconfig
        )
        try:
            latest_nodes = node_snapshot(kubectl_bin)
        except shared.RuntimeValidationError as error:
            detail = str(error)
            if not transient_workload_api_error(detail):
                raise
            observed_at = utc_now()
            if active_api_outage is None:
                active_api_outage = {
                    "started_at": observed_at,
                    "last_observed_at": observed_at,
                    "samples": 1,
                }
            else:
                active_api_outage["last_observed_at"] = observed_at
                active_api_outage["samples"] += 1
            if (
                parse_time(observed_at)
                - parse_time(active_api_outage["started_at"])
            ).total_seconds() > 120:
                raise shared.RuntimeValidationError(
                    "workload API was unavailable for more than 120 seconds"
                )
            time.sleep(5)
            continue
        if active_api_outage is not None:
            active_api_outage["recovered_at"] = utc_now()
            active_api_outage["duration_seconds"] = int(
                (
                    parse_time(active_api_outage["recovered_at"])
                    - parse_time(active_api_outage["started_at"])
                ).total_seconds()
            )
            api_unavailable_windows.append(active_api_outage)
            active_api_outage = None
        ready_nodes = [item for item in latest_nodes if item["ready"]]
        minimum_ready = min(minimum_ready, len(ready_nodes))
        if len(ready_nodes) < 2:
            raise shared.RuntimeValidationError(
                "healthy capacity dropped below two Ready Nodes"
            )
        current_uids = {item["uid"] for item in latest_machines}
        for role, old in old_by_role.items():
            if old["uid"] not in current_uids and role not in removed_observed:
                removed_observed[role] = utc_now()

        target_nodes = [
            item
            for item in ready_nodes
            if item["identity"] == short(HEALTHY_IDENTITY)
            and item["profile_revision"] == "2"
        ]
        target_machines = [
            item
            for item in latest_machines
            if item["identity"] == short(HEALTHY_IDENTITY)
            and item["profile_revision"] == "2"
        ]
        if (
            len(target_nodes) == 2
            and len(target_machines) == 2
            and {item["role"] for item in target_nodes}
            == {"control-plane", "worker"}
            and {item["role"] for item in target_machines}
            == {"control-plane", "worker"}
            and not (old_uids & current_uids)
            and set(removed_observed) == {"control-plane", "worker"}
            and len(latest_nodes) == 2
        ):
            by_provider = {
                item["provider_id"]: item for item in target_nodes
            }
            if not all(
                item["provider_id"] in by_provider
                and item["provider_id"].startswith("kubevirt://")
                for item in target_machines
            ):
                raise shared.RuntimeValidationError(
                    "replacement Machine/Node ProviderIDs do not match"
                )
            timeline = []
            for role in ("control-plane", "worker"):
                machine = next(
                    item for item in target_machines if item["role"] == role
                )
                node = by_provider[machine["provider_id"]]
                removed_at = removed_observed[role]
                drain_event = machine_drain_event(
                    kubectl_bin,
                    management_kubeconfig,
                    old_by_role[role]["name"],
                )
                if not (
                    parse_time(machine["created_at"])
                    <= parse_time(node["ready_at"])
                    <= parse_time(drain_event["time"])
                    <= parse_time(removed_at)
                ):
                    raise shared.RuntimeValidationError(
                        f"{role} replacement ordering is invalid"
                    )
                timeline.append(
                    {
                        "role": role,
                        "predecessor": {
                            "name": old_by_role[role]["name"],
                            "uid": old_by_role[role]["uid"],
                            "drain_event": drain_event,
                            "removed_observed_at": removed_at,
                        },
                        "replacement": {
                            "machine": machine,
                            "node": node,
                        },
                    }
                )
            return {
                "minimum_ready_nodes": minimum_ready,
                "api_unavailable_windows": api_unavailable_windows,
                "timeline": timeline,
                "nodes": target_nodes,
                "machines": target_machines,
            }
        time.sleep(5)
    raise shared.RuntimeValidationError(
        "healthy replacement did not converge before timeout"
    )


def pod_unschedulable(pod: dict) -> bool:
    return any(
        condition.get("type") == "PodScheduled"
        and condition.get("status") == "False"
        and condition.get("reason") == "Unschedulable"
        for condition in pod.get("status", {}).get("conditions", [])
    )


def wait_for_expected_failure(
    kubectl_bin: str,
    management_kubeconfig: Path,
    healthy: dict,
    timeout: int = 300,
) -> dict:
    shared.progress(
        "proving the unhealthy worker replacement preserves healthy capacity"
    )
    healthy_worker_machine = next(
        item for item in healthy["machines"] if item["role"] == "worker"
    )
    healthy_worker_node = next(
        item for item in healthy["nodes"] if item["role"] == "worker"
    )
    deadline = time.monotonic() + timeout
    minimum_ready = 2
    while time.monotonic() < deadline:
        annotate_test_pvcs(kubectl_bin, management_kubeconfig)
        nodes = node_snapshot(kubectl_bin)
        machines = machine_snapshot(kubectl_bin, management_kubeconfig)
        ready_nodes = [item for item in nodes if item["ready"]]
        minimum_ready = min(minimum_ready, len(ready_nodes))
        if len(ready_nodes) < 2:
            raise shared.RuntimeValidationError(
                "failed replacement reduced healthy Node capacity"
            )
        if not any(
            item["uid"] == healthy_worker_node["uid"] and item["ready"]
            for item in nodes
        ) or not any(
            item["uid"] == healthy_worker_machine["uid"]
            for item in machines
        ):
            raise shared.RuntimeValidationError(
                "failed replacement removed the last healthy worker"
            )
        failed = [
            item
            for item in machines
            if item["identity"] == short(UNHEALTHY_IDENTITY)
        ]
        if len(failed) != 1 or failed[0]["ready"]:
            time.sleep(5)
            continue
        pods = shared.kubectl_json(
            kubectl_bin,
            management_kubeconfig,
            ["-n", shared.CLUSTER, "get", "pod"],
        )["items"]
        matching_pods = [
            pod
            for pod in pods
            if (
                pod["metadata"].get("labels", {}).get("kubevirt.io/domain")
                == failed[0]["name"]
                or pod["metadata"]
                .get("annotations", {})
                .get("kubevirt.io/domain")
                == failed[0]["name"]
                or pod["metadata"]["name"].startswith(
                    f"virt-launcher-{failed[0]['name']}-"
                )
            )
        ]
        if not any(pod_unschedulable(pod) for pod in matching_pods):
            time.sleep(5)
            continue
        resource_names: dict[str, list[str]] = {}
        for kind in ("virtualmachine", "datavolume", "pvc", "secret"):
            items = shared.kubectl_json(
                kubectl_bin,
                management_kubeconfig,
                ["-n", shared.CLUSTER, "get", kind],
            )["items"]
            resource_names[kind] = [
                item["metadata"]["name"]
                for item in items
                if item["metadata"]["name"].startswith(failed[0]["name"])
            ]
        return {
            "observed_at": utc_now(),
            "minimum_ready_nodes": minimum_ready,
            "failed_machine": failed[0],
            "unschedulable_pods": [
                {
                    "name": pod["metadata"]["name"],
                    "uid": pod["metadata"]["uid"],
                    "reason": "Unschedulable",
                }
                for pod in matching_pods
                if pod_unschedulable(pod)
            ],
            "preserved_worker": {
                "machine": healthy_worker_machine,
                "node": healthy_worker_node,
            },
            "created_resources": resource_names,
        }
    raise shared.RuntimeValidationError(
        "deliberately unhealthy replacement was not reported as unschedulable"
    )


def wait_for_failure_revert(
    kubectl_bin: str,
    management_kubeconfig: Path,
    healthy: dict,
    failure: dict,
    timeout: int = 600,
) -> dict:
    shared.progress("waiting for controller convergence after desired-state revert")
    expected_node_uids = {item["uid"] for item in healthy["nodes"]}
    expected_machine_uids = {item["uid"] for item in healthy["machines"]}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        nodes = node_snapshot(kubectl_bin)
        machines = machine_snapshot(kubectl_bin, management_kubeconfig)
        failed_machines = [
            item
            for item in machines
            if item["identity"] == short(UNHEALTHY_IDENTITY)
        ]
        if (
            len(nodes) == 2
            and all(item["ready"] for item in nodes)
            and {item["uid"] for item in nodes} == expected_node_uids
            and {item["uid"] for item in machines} == expected_machine_uids
            and not failed_machines
        ):
            leftovers = []
            for kind, names in failure["created_resources"].items():
                for name in names:
                    observed = shared.kubectl(
                        kubectl_bin,
                        management_kubeconfig,
                        [
                            "-n",
                            shared.CLUSTER,
                            "get",
                            kind,
                            name,
                            "-o",
                            "name",
                        ],
                        expected=(0, 1),
                    )
                    if observed.returncode == 0:
                        leftovers.append(f"{kind}/{name}")
            pvs = shared.kubectl_json(
                kubectl_bin,
                management_kubeconfig,
                ["get", "pv"],
            )["items"]
            failed_claims = set(failure["created_resources"]["pvc"])
            pv_leftovers = [
                item["metadata"]["name"]
                for item in pvs
                if item.get("spec", {})
                .get("claimRef", {})
                .get("namespace")
                == shared.CLUSTER
                and item.get("spec", {})
                .get("claimRef", {})
                .get("name")
                in failed_claims
            ]
            if leftovers or pv_leftovers:
                time.sleep(5)
                continue
            return {
                "converged_at": utc_now(),
                "nodes": nodes,
                "machines": machines,
                "failed_resource_leftovers": [],
                "failed_pv_leftovers": [],
            }
        time.sleep(5)
    raise shared.RuntimeValidationError(
        "failed replacement revert did not converge or left resources behind"
    )


def delete_failure_scaffolding(
    kubectl_bin: str,
    management_kubeconfig: Path,
    templates: list[dict],
) -> None:
    machine_sets = shared.kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", shared.CLUSTER, "get", "machineset"],
    )["items"]
    for machine_set in machine_sets:
        labels = machine_set["metadata"].get("labels", {})
        if labels.get("openkubes.io/os-identity") != short(
            UNHEALTHY_IDENTITY
        ):
            continue
        if machine_set.get("spec", {}).get("replicas", 0) != 0:
            raise shared.RuntimeValidationError(
                "refusing to delete a non-zero failed MachineSet"
            )
        shared.kubectl(
            kubectl_bin,
            management_kubeconfig,
            [
                "-n",
                shared.CLUSTER,
                "delete",
                "machineset",
                machine_set["metadata"]["name"],
                "--wait=true",
            ],
        )
    for template in reversed(templates):
        shared.kubectl(
            kubectl_bin,
            management_kubeconfig,
            [
                "-n",
                shared.CLUSTER,
                "delete",
                template["kind"].lower(),
                template["metadata"]["name"],
                "--wait=true",
            ],
        )


def align_safe_metadata(
    kubectl_bin: str,
    management_kubeconfig: Path,
    healthy_documents: list[dict],
) -> None:
    for kind in ("Namespace", "Cluster", "KubevirtCluster"):
        document = one_by_kind(healthy_documents, kind)
        patch = {
            "metadata": {
                "labels": document["metadata"].get("labels", {}),
                "annotations": document["metadata"].get("annotations", {}),
            }
        }
        patch_path = REPLACEMENT_DIR / "runtime" / (
            f"{kind.lower()}-metadata-patch.json"
        )
        patch_path.write_text(
            json.dumps(patch, indent=2) + "\n",
            encoding="utf-8",
        )
        arguments = ["patch", kind.lower(), document["metadata"]["name"]]
        if kind != "Namespace":
            arguments[0:0] = ["-n", shared.CLUSTER]
        arguments.extend(
            ["--type=merge", "--patch-file", str(patch_path)]
        )
        shared.kubectl(
            kubectl_bin,
            management_kubeconfig,
            arguments,
        )


def write_result(payload: dict) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def replacement() -> int:
    started_at = utc_now()
    stage = "preflight"
    sources = {
        "ok_cluster": repo_state(ROOT),
        "ok_linux": repo_state(OK_LINUX),
    }
    result: dict = {
        "schema_version": 1,
        "suite": "OK-125-replacement",
        "gate": "G2_day2_node_replacement",
        "status": "PREFLIGHT",
        "started_at": started_at,
        "cluster": shared.CLUSTER,
        "namespace": shared.CLUSTER,
        "architecture": "amd64",
        "provider": "kubevirt",
        "sources": sources,
        "identities": {
            "baseline": BASE_IDENTITY,
            "healthy": HEALTHY_IDENTITY,
            "deliberately_unhealthy": UNHEALTHY_IDENTITY,
        },
        "lifecycle_authorities": {
            "ssh": False,
            "remote_shell": False,
            "imperative_guest_mutation": False,
            "package_manager": False,
        },
        "secret_values_captured": False,
    }
    failure_applied = False
    healthy_md: dict | None = None
    kubectl_bin = ""
    management_kubeconfig = Path("/")
    try:
        if not all(
            state["clean"] and state["pushed"] for state in sources.values()
        ):
            raise shared.RuntimeValidationError(
                "G2 requires clean ok-cluster and ok-linux commits on origin"
            )
        kubectl_bin, _, management_kubeconfig = shared.require_inputs()
        healthy_manifest, healthy_documents, healthy_render = render_variant(
            "healthy"
        )
        (
            unhealthy_manifest,
            unhealthy_documents,
            unhealthy_render,
        ) = render_variant("deliberately_unhealthy")
        result["renders"] = {
            "healthy": healthy_render,
            "deliberately_unhealthy": unhealthy_render,
        }
        baseline = baseline_preflight(kubectl_bin, management_kubeconfig)
        result["baseline"] = baseline

        healthy_kcp = one_by_kind(
            healthy_documents, "KubeadmControlPlane"
        )
        healthy_md = one_by_kind(healthy_documents, "MachineDeployment")
        unhealthy_md = one_by_kind(
            unhealthy_documents, "MachineDeployment"
        )
        for document in (healthy_kcp, healthy_md, unhealthy_md):
            patch_resource(
                kubectl_bin,
                management_kubeconfig,
                document,
                dry_run=True,
            )
        stage = "healthy-replacement"
        shared.progress(
            "creating healthy immutable templates and changing desired refs"
        )
        create_templates(
            kubectl_bin,
            management_kubeconfig,
            healthy_documents,
            "healthy",
        )
        patch_resource(
            kubectl_bin, management_kubeconfig, healthy_kcp
        )
        patch_resource(kubectl_bin, management_kubeconfig, healthy_md)
        healthy = wait_for_healthy_replacement(
            kubectl_bin, management_kubeconfig, baseline
        )
        result["healthy_replacement"] = healthy

        stage = "failed-replacement"
        shared.progress(
            "creating the deliberately unschedulable worker replacement"
        )
        failure_templates = create_templates(
            kubectl_bin,
            management_kubeconfig,
            unhealthy_documents,
            "deliberately_unhealthy",
            worker_only=True,
        )
        patch_resource(kubectl_bin, management_kubeconfig, unhealthy_md)
        failure_applied = True
        failure = wait_for_expected_failure(
            kubectl_bin, management_kubeconfig, healthy
        )
        result["failed_replacement"] = failure

        stage = "failed-replacement-revert"
        patch_resource(kubectl_bin, management_kubeconfig, healthy_md)
        failure_applied = False
        reverted = wait_for_failure_revert(
            kubectl_bin,
            management_kubeconfig,
            healthy,
            failure,
        )
        delete_failure_scaffolding(
            kubectl_bin,
            management_kubeconfig,
            failure_templates,
        )
        result["failed_replacement"]["revert"] = reverted

        stage = "final-verification"
        align_safe_metadata(
            kubectl_bin, management_kubeconfig, healthy_documents
        )
        final_runtime = shared.collect_runtime_evidence(
            kubectl_bin, management_kubeconfig
        )
        final_nodes = final_runtime["nodes"]
        if (
            len(final_nodes) != 2
            or not all(
                item["ready"] == "True"
                and item["providerID"].startswith("kubevirt://")
                for item in final_nodes
            )
        ):
            raise shared.RuntimeValidationError(
                "final G2 runtime verification failed"
            )
        result["final_runtime"] = final_runtime
        result["status"] = "PASS"
        result["completed_at"] = utc_now()
        result["runtime_gates"] = {
            "G1_kubernetes_node_ready": "PASS",
            "G2_day2_node_replacement": "PASS",
            "G3_provider_scoped_bootstrap_secret": "PASS",
        }
        write_result(result)
        shared.progress(
            "PASS G2 healthy replacement, failed replacement, and revert"
        )
        return 0
    except BaseException as error:
        if (
            failure_applied
            and healthy_md is not None
            and kubectl_bin
            and management_kubeconfig != Path("/")
        ):
            try:
                patch_resource(
                    kubectl_bin, management_kubeconfig, healthy_md
                )
                result["safety_revert_requested"] = True
            except Exception as revert_error:
                result["safety_revert_requested"] = False
                result["safety_revert_error"] = str(revert_error)
        result["status"] = (
            "ABORTED" if isinstance(error, KeyboardInterrupt) else "FAIL"
        )
        result["failed_stage"] = stage
        result["detail"] = (
            "operator interrupted the replacement runtime"
            if isinstance(error, KeyboardInterrupt)
            else str(error)
        )
        result["completed_at"] = utc_now()
        result["runtime_gates"] = {
            "G1_kubernetes_node_ready": "PASS",
            "G2_day2_node_replacement": "FAIL",
            "G3_provider_scoped_bootstrap_secret": "PASS",
        }
        write_result(result)
        raise


def self_test() -> int:
    assert short(BASE_IDENTITY) == "afd862491620"
    assert short(HEALTHY_IDENTITY) == "6030632e0a7c"
    assert short(UNHEALTHY_IDENTITY) == "fd0981887afe"
    assert len({BASE_IDENTITY, HEALTHY_IDENTITY, UNHEALTHY_IDENTITY}) == 3
    assert VARIANTS["healthy"]["node_selector"] == "ok-infra"
    assert (
        VARIANTS["deliberately_unhealthy"]["node_selector"]
        == "ok125-no-such-node"
    )
    assert transient_workload_api_error(
        "The connection to the server 192.168.100.249:6443 was refused"
    )
    assert not transient_workload_api_error(
        "forbidden: user cannot list nodes"
    )
    print("PASS G2 identities and failure scope are pinned")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        raise shared.RuntimeValidationError(
            "usage: replacement.py --run|--self-test"
        )
    if sys.argv[1] == "--self-test":
        return self_test()
    if sys.argv[1] == "--run":
        return replacement()
    raise shared.RuntimeValidationError(
        "usage: replacement.py --run|--self-test"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("ABORTED operator interrupted the replacement runtime")
        raise SystemExit(130)
    except (shared.RuntimeValidationError, OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
