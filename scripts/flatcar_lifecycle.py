#!/usr/bin/env python3
"""Guarded ordinary lifecycle for the constrained ADR-009 Flatcar profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from profile_resolvers.flatcar import (  # noqa: E402
    EXPECTED_PROFILE,
    resolve_flatcar_config,
    validate_cluster_name,
)


EXPECTED_CILIUM_CHART_SHA256 = (
    "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
)
EXPECTED_PROVIDER_INVENTORY = {
    ("capi-system", "cluster-api", "CoreProvider"): "v1.13.3",
    (
        "capi-kubeadm-bootstrap-system",
        "bootstrap-kubeadm",
        "BootstrapProvider",
    ): "v1.13.3",
    (
        "capi-kubeadm-control-plane-system",
        "control-plane-kubeadm",
        "ControlPlaneProvider",
    ): "v1.13.3",
    (
        "capk-system",
        "infrastructure-kubevirt",
        "InfrastructureProvider",
    ): "v0.11.2",
}
GATE_DEPLOYMENTS = (
    {
        "namespace": "capi-kubeadm-bootstrap-system",
        "name": "capi-kubeadm-bootstrap-controller-manager",
        "image": (
            "registry.k8s.io/cluster-api/"
            "kubeadm-bootstrap-controller:v1.13.3"
        ),
    },
    {
        "namespace": "capi-kubeadm-control-plane-system",
        "name": "capi-kubeadm-control-plane-controller-manager",
        "image": (
            "registry.k8s.io/cluster-api/"
            "kubeadm-control-plane-controller:v1.13.3"
        ),
    },
)
FORBIDDEN_MANIFEST_TERMS = (
    "sshAuthorizedKeys",
    "authorized_keys",
    "PRIVATE KEY",
    "password:",
    "token:",
    "http://",
    "https://",
    "containerDisk:",
    "kind: Secret",
    "apt-get ",
    "dnf ",
    "yum ",
    "apk add",
    "curl ",
    "wget ",
)


class FlatcarLifecycleError(RuntimeError):
    """A local or live precondition is outside the accepted support envelope."""


def progress(message: str) -> None:
    print(f"[flatcar] {message}", flush=True)


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    expected: tuple[int, ...] = (0,),
    sensitive_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in expected:
        detail = result.stderr.strip()
        if not detail and not sensitive_stdout:
            detail = result.stdout.strip()
        raise FlatcarLifecycleError(
            f"{' '.join(command[:4])} exited {result.returncode}: "
            f"{detail or 'no non-sensitive diagnostic'}"
        )
    return result


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise FlatcarLifecycleError(f"required executable not found: {name}")
    return str(Path(resolved).resolve())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def manifest_objects(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [item for item in yaml.safe_load_all(stream) if item]


def source_state(path: Path) -> dict[str, object]:
    commit = run(["git", "rev-parse", "HEAD"], cwd=path).stdout.strip()
    dirty = bool(run(["git", "status", "--porcelain"], cwd=path).stdout.strip())
    pushed = bool(
        run(["git", "branch", "-r", "--contains", "HEAD"], cwd=path)
        .stdout.strip()
    )
    return {"commit": commit, "clean": not dirty, "pushed": pushed}


def kubectl(
    binary: str,
    kubeconfig: Path,
    args: list[str],
    *,
    expected: tuple[int, ...] = (0,),
    sensitive_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    return run(
        [binary, "--kubeconfig", str(kubeconfig), *args],
        expected=expected,
        sensitive_stdout=sensitive_stdout,
    )


def kubectl_json(
    binary: str,
    kubeconfig: Path,
    args: list[str],
) -> dict:
    result = kubectl(binary, kubeconfig, [*args, "-o", "json"])
    return json.loads(result.stdout)


def require_inputs(args: argparse.Namespace) -> dict[str, object]:
    if not args.cluster or args.cluster == "ok125-flatcar":
        raise FlatcarLifecycleError(
            "ordinary lifecycle requires a non-evidence cluster name"
        )
    validate_cluster_name(args.cluster)
    management_value = args.management_kubeconfig
    chart_value = args.cilium_chart
    if not management_value:
        raise FlatcarLifecycleError(
            "an explicit --management-kubeconfig path is required"
        )
    if not chart_value:
        raise FlatcarLifecycleError(
            "an explicit --cilium-chart path is required"
        )
    management = Path(management_value).expanduser().resolve()
    chart = Path(chart_value).expanduser().resolve()
    if not management.is_file():
        raise FlatcarLifecycleError(
            f"management kubeconfig does not exist: {management}"
        )
    if not chart.is_file():
        raise FlatcarLifecycleError(f"Cilium chart does not exist: {chart}")

    ok_linux = Path(
        os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
    ).resolve()
    config_path = ROOT / args.cluster / "cluster-config.yaml"
    manifest_path = ROOT / args.cluster / "cluster-v2.yaml"
    cilium_values = ROOT / args.cluster / "cilium-values.yaml"
    for path in (config_path, manifest_path, cilium_values):
        if not path.is_file():
            raise FlatcarLifecycleError(
                f"rendered Flatcar input does not exist: {path}"
            )

    workload = (
        Path(args.workload_kubeconfig).expanduser().resolve()
        if args.workload_kubeconfig
        else (Path.home() / ".kube" / f"{args.cluster}.yaml").resolve()
    )
    if workload.exists():
        raise FlatcarLifecycleError(
            f"workload kubeconfig target already exists: {workload}"
        )
    return {
        "ok_linux": ok_linux,
        "management": management,
        "chart": chart,
        "config": config_path,
        "manifest": manifest_path,
        "cilium_values": cilium_values,
        "workload": workload,
    }


def require_teardown_inputs(args: argparse.Namespace) -> dict[str, object]:
    if not args.cluster or args.cluster == "ok125-flatcar":
        raise FlatcarLifecycleError(
            "ordinary teardown requires a non-evidence cluster name"
        )
    validate_cluster_name(args.cluster)
    if not args.management_kubeconfig:
        raise FlatcarLifecycleError(
            "an explicit --management-kubeconfig path is required"
        )
    management = Path(args.management_kubeconfig).expanduser().resolve()
    if not management.is_file():
        raise FlatcarLifecycleError(
            f"management kubeconfig does not exist: {management}"
        )
    ok_linux = Path(
        os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
    ).resolve()
    config_path = ROOT / args.cluster / "cluster-config.yaml"
    if not config_path.is_file():
        raise FlatcarLifecycleError(
            f"cluster config does not exist: {config_path}"
        )
    config = load_yaml(config_path)
    resolved = resolve_flatcar_config(config, ok_linux)
    if resolved != config:
        raise FlatcarLifecycleError(
            "cluster config no longer matches the promoted profile"
        )
    workload = (
        Path(args.workload_kubeconfig).expanduser().resolve()
        if args.workload_kubeconfig
        else (Path.home() / ".kube" / f"{args.cluster}.yaml").resolve()
    )
    if workload.is_file():
        workload_config = load_yaml(workload)
        if not isinstance(workload_config, dict):
            raise FlatcarLifecycleError(
                "workload kubeconfig is not a mapping"
            )
        contexts = {
            item.get("name"): item.get("context", {}).get("cluster")
            for item in workload_config.get("contexts", [])
        }
        if (
            workload_config.get("current-context") != args.cluster
            or contexts.get(args.cluster) != args.cluster
        ):
            raise FlatcarLifecycleError(
                "workload kubeconfig ownership does not match the cluster"
            )
    return {
        "ok_linux": ok_linux,
        "management": management,
        "config": config_path,
        "resolved": resolved,
        "workload": workload,
    }


def validate_local(
    args: argparse.Namespace,
    paths: dict[str, object],
    helm_bin: str,
) -> tuple[dict, list[dict]]:
    progress("validating exact profile, manifest, and local Cilium artifact")
    config = load_yaml(paths["config"])
    resolved = resolve_flatcar_config(config, paths["ok_linux"])
    if resolved != config:
        raise FlatcarLifecycleError(
            "cluster-config.yaml is not fully materialized; run make render"
        )

    documents = manifest_objects(paths["manifest"])
    namespaces = [
        item
        for item in documents
        if item.get("kind") == "Namespace"
        and item.get("metadata", {}).get("name") == args.cluster
    ]
    if len(namespaces) != 1:
        raise FlatcarLifecycleError("manifest must contain the exact namespace")
    namespace = namespaces[0]
    labels = namespace["metadata"].get("labels", {})
    annotations = namespace["metadata"].get("annotations", {})
    if (
        labels.get("openkubes.io/type") != "flatcar"
        or labels.get("openkubes.io/provider") != "kubevirt"
        or labels.get("openkubes.io/adoption-status")
        != "production-constrained"
        or labels.get("openkubes.io/deployable") != "true"
        or annotations.get("openkubes.io/os-identity-full")
        != EXPECTED_PROFILE["identity"]
        or annotations.get("openkubes.io/os-image-digest")
        != EXPECTED_PROFILE["image_digest"]
    ):
        raise FlatcarLifecycleError(
            "manifest labels/annotations do not match the promoted identity"
        )
    manifest_text = paths["manifest"].read_text(encoding="utf-8")
    if "${" in manifest_text or any(
        term in manifest_text for term in FORBIDDEN_MANIFEST_TERMS
    ):
        raise FlatcarLifecycleError(
            "manifest contains an unresolved, secret, remote, or mutable input"
        )

    chart_digest = sha256(paths["chart"])
    if chart_digest != EXPECTED_CILIUM_CHART_SHA256:
        raise FlatcarLifecycleError(
            f"Cilium chart digest mismatch: observed sha256:{chart_digest}"
        )
    chart_metadata = yaml.safe_load(
        run([helm_bin, "show", "chart", str(paths["chart"])]).stdout
    )
    if (
        chart_metadata.get("name") != "cilium"
        or str(chart_metadata.get("version")) != EXPECTED_PROFILE["cilium_version"]
    ):
        raise FlatcarLifecycleError(
            "local Cilium chart metadata does not match version 1.19.6"
        )
    rendered_cilium = run(
        [
            helm_bin,
            "template",
            "cilium",
            str(paths["chart"]),
            "--namespace",
            "kube-system",
            "--values",
            str(paths["cilium_values"]),
        ]
    ).stdout
    images = {
        line.split("image:", 1)[1].strip().strip('"')
        for line in rendered_cilium.splitlines()
        if line.strip().startswith("image:")
    }
    if not images or not all("@sha256:" in image for image in images):
        raise FlatcarLifecycleError(
            "all rendered Cilium images must be digest-bound"
        )
    return config, documents


def management_preflight(
    args: argparse.Namespace,
    paths: dict[str, object],
    config: dict,
    kubectl_bin: str,
) -> None:
    progress("checking source state and management-cluster preconditions")
    states = {
        "ok-cluster": source_state(ROOT),
        "ok-linux": source_state(paths["ok_linux"]),
    }
    if not all(
        state["clean"] and state["pushed"] for state in states.values()
    ):
        raise FlatcarLifecycleError(
            f"install requires clean, pushed source states: {states}"
        )

    inventory = kubectl_json(
        kubectl_bin,
        paths["management"],
        ["get", "providers.clusterctl.cluster.x-k8s.io", "-A"],
    )
    observed_inventory = {
        (
            item["metadata"]["namespace"],
            item["metadata"]["name"],
            item["type"],
        ): item["version"]
        for item in inventory.get("items", [])
    }
    for identity, expected_version in EXPECTED_PROVIDER_INVENTORY.items():
        if observed_inventory.get(identity) != expected_version:
            raise FlatcarLifecycleError(
                f"provider {identity[0]}/{identity[1]} must be "
                f"{expected_version}, observed "
                f"{observed_inventory.get(identity, 'absent')}"
            )

    kubevirt_items = kubectl_json(
        kubectl_bin,
        paths["management"],
        ["get", "kubevirt.kubevirt.io", "-A"],
    ).get("items", [])
    if len(kubevirt_items) != 1:
        raise FlatcarLifecycleError(
            f"expected one KubeVirt installation, observed {len(kubevirt_items)}"
        )
    kubevirt_status = kubevirt_items[0].get("status", {})
    if (
        kubevirt_status.get("phase") != "Deployed"
        or kubevirt_status.get("observedKubeVirtVersion") != "v1.8.1"
        or kubevirt_status.get("targetKubeVirtVersion") != "v1.8.1"
    ):
        raise FlatcarLifecycleError(
            "management KubeVirt must be deployed at exact version v1.8.1"
        )

    for expected_deployment in GATE_DEPLOYMENTS:
        namespace = expected_deployment["namespace"]
        deployment = expected_deployment["name"]
        obj = kubectl_json(
            kubectl_bin,
            paths["management"],
            ["-n", namespace, "get", "deployment", deployment],
        )
        container = obj["spec"]["template"]["spec"]["containers"][0]
        feature_args = [
            value
            for value in container.get("args", [])
            if value.startswith("--feature-gates=")
        ]
        if (
            container.get("image") != expected_deployment["image"]
            or not feature_args
            or "KubeadmBootstrapFormatIgnition=true" not in feature_args[0]
            or obj.get("status", {}).get("availableReplicas") != 1
        ):
            raise FlatcarLifecycleError(
                f"Ignition gate/controller is not ready: {namespace}/{deployment}"
            )

    cluster = args.cluster
    absent = kubectl(
        kubectl_bin,
        paths["management"],
        ["get", "namespace", cluster, "-o", "name"],
        expected=(0, 1),
    )
    if absent.returncode == 0:
        raise FlatcarLifecycleError(
            f"namespace {cluster} already exists; refusing create-overwrite"
        )
    clone_name = f"{cluster}-golden-image-cloner"
    golden_namespace = config["os"]["goldenImage"]["namespace"]
    for kind in ("role", "rolebinding"):
        existing = kubectl(
            kubectl_bin,
            paths["management"],
            [
                "-n",
                golden_namespace,
                "get",
                kind,
                clone_name,
                "-o",
                "name",
            ],
            expected=(0, 1),
        )
        if existing.returncode == 0:
            raise FlatcarLifecycleError(
                f"{kind} {golden_namespace}/{clone_name} already exists"
            )

    golden = kubectl_json(
        kubectl_bin,
        paths["management"],
        [
            "-n",
            golden_namespace,
            "get",
            "pvc",
            config["os"]["goldenImage"]["claim"],
        ],
    )
    if (
        golden.get("status", {}).get("phase") != "Bound"
        or golden["metadata"].get("annotations", {}).get(
            "ok-linux.openkubes.io/image-sha256"
        )
        != EXPECTED_PROFILE["image_digest"]
    ):
        raise FlatcarLifecycleError("golden-image PVC identity is invalid")

    endpoint = config["network"]["endpoint"]
    services = kubectl_json(
        kubectl_bin,
        paths["management"],
        ["get", "service", "-A"],
    )
    collisions = []
    for service in services.get("items", []):
        addresses = [service.get("spec", {}).get("loadBalancerIP")]
        addresses.extend(
            item.get("ip")
            for item in service.get("status", {})
            .get("loadBalancer", {})
            .get("ingress", [])
        )
        if endpoint in addresses:
            collisions.append(
                f"{service['metadata']['namespace']}/"
                f"{service['metadata']['name']}"
            )
    if collisions:
        raise FlatcarLifecycleError(
            f"endpoint {endpoint} is already allocated to {collisions}"
        )

    kubectl(
        kubectl_bin,
        paths["management"],
        [
            "create",
            "--dry-run=client",
            "--validate=strict",
            "-f",
            str(paths["manifest"]),
            "-o",
            "name",
        ],
    )


def write_documents(path: Path, documents: list[dict]) -> None:
    path.write_text(
        "".join(
            f"---\n{yaml.safe_dump(item, sort_keys=False)}"
            for item in documents
        ),
        encoding="utf-8",
    )


def wait_for_datavolumes(
    kubectl_bin: str,
    management: Path,
    cluster: str,
    node_selector: str,
    expected_count: int,
    timeout: int = 600,
) -> None:
    deadline = time.monotonic() + timeout
    phases: list[str] = []
    while time.monotonic() < deadline:
        pvcs = kubectl_json(
            kubectl_bin,
            management,
            ["-n", cluster, "get", "pvc"],
        ).get("items", [])
        for pvc in pvcs:
            annotations = pvc["metadata"].get("annotations", {})
            if (
                annotations.get("volume.kubernetes.io/selected-node")
                != node_selector
            ):
                kubectl(
                    kubectl_bin,
                    management,
                    [
                        "-n",
                        cluster,
                        "annotate",
                        "pvc",
                        pvc["metadata"]["name"],
                        f"volume.kubernetes.io/selected-node={node_selector}",
                        "--overwrite",
                    ],
                )
        datavolumes = kubectl_json(
            kubectl_bin,
            management,
            ["-n", cluster, "get", "datavolume"],
        ).get("items", [])
        phases = [item.get("status", {}).get("phase", "") for item in datavolumes]
        if (
            len(phases) == expected_count
            and all(phase == "Succeeded" for phase in phases)
        ):
            return
        time.sleep(10)
    raise FlatcarLifecycleError(
        f"{expected_count} DataVolumes did not succeed; observed {phases}"
    )


def write_workload_kubeconfig(
    clusterctl_bin: str,
    management: Path,
    cluster: str,
    target: Path,
) -> None:
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        result = run(
            [
                clusterctl_bin,
                "--kubeconfig",
                str(management),
                "get",
                "kubeconfig",
                cluster,
                "-n",
                cluster,
            ],
            expected=(0, 1),
            sensitive_stdout=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(result.stdout, encoding="utf-8")
            target.chmod(0o600)
            return
        time.sleep(10)
    raise FlatcarLifecycleError("workload kubeconfig was not published")


def wait_for_nodes(
    kubectl_bin: str,
    workload: Path,
    expected_count: int,
    *,
    require_ready: bool,
    timeout: int = 600,
) -> list[dict]:
    deadline = time.monotonic() + timeout
    nodes: list[dict] = []
    while time.monotonic() < deadline:
        result = kubectl(
            kubectl_bin,
            workload,
            ["get", "node", "-o", "json"],
            expected=(0, 1),
        )
        if result.returncode == 0:
            nodes = json.loads(result.stdout).get("items", [])
            readiness = [
                next(
                    (
                        condition.get("status")
                        for condition in node.get("status", {}).get(
                            "conditions", []
                        )
                        if condition.get("type") == "Ready"
                    ),
                    "False",
                )
                for node in nodes
            ]
            if len(nodes) == expected_count and (
                not require_ready or all(value == "True" for value in readiness)
            ):
                return nodes
        time.sleep(10)
    raise FlatcarLifecycleError(
        f"expected {expected_count} Nodes, observed {len(nodes)}"
    )


def install(
    args: argparse.Namespace,
    paths: dict[str, object],
    config: dict,
    documents: list[dict],
    kubectl_bin: str,
    helm_bin: str,
    clusterctl_bin: str,
) -> int:
    if os.environ.get("FLATCAR_APPLY") != "yes":
        raise FlatcarLifecycleError("install requires FLATCAR_APPLY=yes")

    namespace = [item for item in documents if item["kind"] == "Namespace"]
    resources = [item for item in documents if item["kind"] != "Namespace"]
    with tempfile.TemporaryDirectory(prefix="flatcar-install-") as temp_name:
        temp = Path(temp_name)
        namespace_path = temp / "namespace.yaml"
        resources_path = temp / "resources.yaml"
        write_documents(namespace_path, namespace)
        write_documents(resources_path, resources)

        progress("creating the exact namespace and CAPI/CAPK resource set")
        kubectl(
            kubectl_bin,
            paths["management"],
            ["create", "-f", str(namespace_path)],
        )
        kubectl(
            kubectl_bin,
            paths["management"],
            [
                "create",
                "--dry-run=server",
                "--validate=strict",
                "-f",
                str(resources_path),
                "-o",
                "name",
            ],
        )
        kubectl(
            kubectl_bin,
            paths["management"],
            ["create", "-f", str(resources_path)],
        )

    wait_for_datavolumes(
        kubectl_bin,
        paths["management"],
        args.cluster,
        config["nodeSelector"],
        expected_count=1,
    )
    write_workload_kubeconfig(
        clusterctl_bin,
        paths["management"],
        args.cluster,
        paths["workload"],
    )
    progress("waiting for the control-plane Node before installing Cilium")
    wait_for_nodes(
        kubectl_bin,
        paths["workload"],
        expected_count=1,
        require_ready=False,
    )
    progress("installing digest-verified local Cilium 1.19.6")
    run(
        [
            helm_bin,
            "upgrade",
            "--install",
            "cilium",
            str(paths["chart"]),
            "--kubeconfig",
            str(paths["workload"]),
            "--namespace",
            "kube-system",
            "--values",
            str(paths["cilium_values"]),
            "--wait",
            "--timeout",
            "10m",
        ]
    )
    expected_nodes = (
        config["controlPlane"]["replicas"] + config["workers"]["replicas"]
    )
    wait_for_datavolumes(
        kubectl_bin,
        paths["management"],
        args.cluster,
        config["nodeSelector"],
        expected_count=expected_nodes,
    )
    nodes = wait_for_nodes(
        kubectl_bin,
        paths["workload"],
        expected_count=expected_nodes,
        require_ready=True,
    )
    for node in nodes:
        info = node.get("status", {}).get("nodeInfo", {})
        if (
            "Flatcar" not in info.get("osImage", "")
            or info.get("kubeletVersion")
            != EXPECTED_PROFILE["kubernetes_version"]
            or not node.get("spec", {}).get("providerID", "").startswith(
                "kubevirt://"
            )
        ):
            raise FlatcarLifecycleError(
                f"Node contract failed: {node['metadata']['name']}"
            )
    progress(
        f"PASS {args.cluster}: constrained Flatcar profile reached Node Ready"
    )
    return 0


def teardown(
    args: argparse.Namespace,
    paths: dict[str, object],
    kubectl_bin: str,
) -> int:
    if os.environ.get("FLATCAR_TEARDOWN") != "yes":
        raise FlatcarLifecycleError("teardown requires FLATCAR_TEARDOWN=yes")

    cluster = args.cluster
    management = paths["management"]
    config = paths["resolved"]
    namespace = kubectl_json(
        kubectl_bin,
        management,
        ["get", "namespace", cluster],
    )
    labels = namespace["metadata"].get("labels", {})
    annotations = namespace["metadata"].get("annotations", {})
    if (
        labels.get("openkubes.io/type") != "flatcar"
        or labels.get("openkubes.io/provider") != "kubevirt"
        or labels.get("openkubes.io/adoption-status")
        != "production-constrained"
        or labels.get("openkubes.io/deployable") != "true"
        or annotations.get("openkubes.io/os-identity-full")
        != EXPECTED_PROFILE["identity"]
    ):
        raise FlatcarLifecycleError(
            "namespace ownership does not match the promoted profile"
        )

    pvs = kubectl_json(
        kubectl_bin,
        management,
        ["get", "persistentvolume"],
    ).get("items", [])
    owned_pvs = sorted(
        item["metadata"]["name"]
        for item in pvs
        if item.get("spec", {}).get("claimRef", {}).get("namespace") == cluster
    )
    clone_name = f"{cluster}-golden-image-cloner"
    golden_namespace = config["os"]["goldenImage"]["namespace"]
    progress(
        "teardown targets: "
        f"namespace={cluster}, clone_authorization="
        f"{golden_namespace}/{clone_name}, pvs={owned_pvs}"
    )

    kubectl(
        kubectl_bin,
        management,
        [
            "-n",
            cluster,
            "delete",
            "cluster",
            cluster,
            "--ignore-not-found",
            "--cascade=foreground",
            "--timeout=10m",
        ],
    )
    kubectl(
        kubectl_bin,
        management,
        ["delete", "namespace", cluster, "--ignore-not-found", "--timeout=10m"],
    )
    for kind in ("role", "rolebinding"):
        kubectl(
            kubectl_bin,
            management,
            [
                "-n",
                golden_namespace,
                "delete",
                kind,
                clone_name,
                "--ignore-not-found",
            ],
        )
    for pv in owned_pvs:
        kubectl(
            kubectl_bin,
            management,
            ["delete", "persistentvolume", pv, "--ignore-not-found"],
        )

    absent = kubectl(
        kubectl_bin,
        management,
        ["get", "namespace", cluster, "-o", "name"],
        expected=(0, 1),
    )
    if absent.returncode == 0:
        raise FlatcarLifecycleError(
            f"namespace {cluster} still exists after teardown"
        )
    golden = kubectl_json(
        kubectl_bin,
        management,
        [
            "-n",
            golden_namespace,
            "get",
            "pvc",
            config["os"]["goldenImage"]["claim"],
        ],
    )
    if (
        golden.get("status", {}).get("phase") != "Bound"
        or golden["metadata"].get("annotations", {}).get(
            "ok-linux.openkubes.io/image-sha256"
        )
        != EXPECTED_PROFILE["image_digest"]
    ):
        raise FlatcarLifecycleError(
            "golden-image PVC changed during teardown"
        )

    workload = paths["workload"]
    if workload.is_file():
        workload.unlink()
    cluster_dir = (ROOT / cluster).resolve()
    if cluster_dir.parent != ROOT.resolve() or cluster_dir.name != cluster:
        raise FlatcarLifecycleError("refusing unsafe local directory removal")
    shutil.rmtree(cluster_dir)
    progress(f"PASS {cluster}: exact constrained Flatcar teardown completed")
    return 0


def self_test() -> int:
    if (
        EXPECTED_PROFILE["architecture"] != "amd64"
        or EXPECTED_PROFILE["provider"] != "kubevirt"
        or EXPECTED_PROFILE["node_selector"] != "ok-infra"
        or EXPECTED_CILIUM_CHART_SHA256
        != "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
        or len(EXPECTED_PROVIDER_INVENTORY) != 4
        or EXPECTED_PROVIDER_INVENTORY[
            ("capk-system", "infrastructure-kubevirt", "InfrastructureProvider")
        ]
        != "v0.11.2"
        or "sshAuthorizedKeys" not in FORBIDDEN_MANIFEST_TERMS
        or "FLATCAR_TEARDOWN" not in teardown.__code__.co_consts
    ):
        raise FlatcarLifecycleError("lifecycle constants are not fail-closed")
    print("PASS constrained Flatcar lifecycle constants are pinned")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--install", action="store_true")
    action.add_argument("--teardown", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--cluster", default="")
    parser.add_argument("--management-kubeconfig", default="")
    parser.add_argument("--cilium-chart", default="")
    parser.add_argument("--workload-kubeconfig", default="")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.teardown:
        paths = require_teardown_inputs(args)
        return teardown(args, paths, require_tool("kubectl"))

    paths = require_inputs(args)
    kubectl_bin = require_tool("kubectl")
    helm_bin = require_tool("helm")
    clusterctl_bin = require_tool("clusterctl")
    config, documents = validate_local(args, paths, helm_bin)
    management_preflight(args, paths, config, kubectl_bin)
    progress("PASS constrained Flatcar production preflight")
    if args.preflight:
        return 0
    return install(
        args,
        paths,
        config,
        documents,
        kubectl_bin,
        helm_bin,
        clusterctl_bin,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FlatcarLifecycleError, OSError, ValueError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
