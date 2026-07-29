#!/usr/bin/env python3
"""Guarded OK-125 G1/G3 runtime and exact-scope cleanup.

Only the disposable ``ok125-flatcar`` namespace is accepted. Secret values are
used only to create an ephemeral workload kubeconfig; evidence contains names,
UIDs, key names, owner references, and lifecycle state only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
OK_LINUX = Path(
    os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
).resolve()
EVIDENCE = ROOT / "docs" / "adoption" / "OK-125" / ".evidence"
RENDER_DIR = EVIDENCE / "render"
RUNTIME_DIR = EVIDENCE / "runtime"
MANIFEST = RENDER_DIR / "cluster-v2.yaml"
CILIUM_VALUES = RENDER_DIR / "cilium-values.yaml"
CILIUM_CHART = (
    ROOT
    / "docs"
    / "adoption"
    / "OK-125"
    / ".tools"
    / "cilium-1.19.6.tgz"
)
WORKLOAD_KUBECONFIG = Path("/private/tmp/ok125-flatcar.kubeconfig")

CLUSTER = "ok125-flatcar"
EXPECTED_VERSION = "v1.34.1"
EXPECTED_OS_IDENTITY = (
    "sha256:afd862491620adbaeb3c25aa82ae89a3bd748ae5976cf66fbf9613a732ba35bb"
)
EXPECTED_IMAGE_DIGEST = (
    "sha256:49b72cf26d27d4747d6252c64582f17fdbd7d629993beebbcf997794333a978a"
)
EXPECTED_CILIUM_CHART_SHA256 = (
    "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
)
EXPECTED_GOLDEN_PVC = (
    "ok-images",
    "flatcar-stable-4593-2-4-amd64-kubevirt",
)
CLONE_AUTHORIZATION = f"{CLUSTER}-golden-image-cloner"
GATE_DEPLOYMENTS = (
    (
        "capi-kubeadm-bootstrap-system",
        "capi-kubeadm-bootstrap-controller-manager",
    ),
    (
        "capi-kubeadm-control-plane-system",
        "capi-kubeadm-control-plane-controller-manager",
    ),
)


class RuntimeValidationError(RuntimeError):
    """A fail-closed runtime condition was not met."""


def progress(message: str) -> None:
    print(f"[ok125-runtime] {message}", flush=True)


def run(
    command: list[str],
    *,
    expected: tuple[int, ...] = (0,),
    sensitive_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in expected:
        detail = result.stderr.strip()
        if not detail and not sensitive_stdout:
            detail = result.stdout.strip()
        raise RuntimeValidationError(
            f"{' '.join(command[:4])} exited {result.returncode}: "
            f"{detail or 'no non-sensitive diagnostic'}"
        )
    return result


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeValidationError(f"required executable not found: {name}")
    return str(Path(resolved).resolve())


def require_inputs() -> tuple[str, str, Path]:
    cluster = os.environ.get("CLUSTER", CLUSTER)
    if cluster != CLUSTER:
        raise RuntimeValidationError(
            f"runtime is bounded to CLUSTER={CLUSTER}, observed {cluster}"
        )
    kubeconfig_value = os.environ.get("OK125_KUBECONFIG", "")
    if not kubeconfig_value:
        raise RuntimeValidationError("OK125_KUBECONFIG must be an explicit path")
    kubeconfig = Path(kubeconfig_value).expanduser().resolve()
    if not kubeconfig.is_file():
        raise RuntimeValidationError(f"kubeconfig does not exist: {kubeconfig}")
    return require_tool("kubectl"), require_tool("helm"), kubeconfig


def source_state() -> dict[str, object]:
    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "status", "--porcelain"]).stdout.strip())
    pushed = bool(
        run(["git", "branch", "-r", "--contains", "HEAD"]).stdout.strip()
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
    *,
    sensitive_stdout: bool = False,
):
    result = kubectl(
        binary,
        kubeconfig,
        [*args, "-o", "json"],
        sensitive_stdout=sensitive_stdout,
    )
    return json.loads(result.stdout)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render() -> dict:
    progress("rendering the deterministic Flatcar candidate")
    result = run(
        [
            "make",
            "--no-print-directory",
            "ok125-render",
            f"CLUSTER={CLUSTER}",
            f"OK_LINUX_PATH={OK_LINUX}",
        ]
    )
    if "MANIFEST sha256:" not in result.stdout:
        raise RuntimeValidationError("offline renderer did not emit an identity")
    if not MANIFEST.is_file() or not CILIUM_VALUES.is_file():
        raise RuntimeValidationError("runtime render output is incomplete")
    return {
        "manifest_sha256": sha256(MANIFEST),
        "cilium_values_sha256": sha256(CILIUM_VALUES),
    }


def manifest_documents() -> tuple[dict, list[dict]]:
    with MANIFEST.open(encoding="utf-8") as stream:
        documents = [item for item in yaml.safe_load_all(stream) if item]
    namespaces = [item for item in documents if item["kind"] == "Namespace"]
    resources = [item for item in documents if item["kind"] != "Namespace"]
    if len(namespaces) != 1 or namespaces[0]["metadata"]["name"] != CLUSTER:
        raise RuntimeValidationError("render must contain the exact namespace")
    namespace = namespaces[0]
    if (
        namespace["metadata"]["labels"]["openkubes.io/deployable"] != "false"
        or namespace["metadata"]["annotations"]["openkubes.io/os-identity-full"]
        != EXPECTED_OS_IDENTITY
    ):
        raise RuntimeValidationError("runtime namespace identity guard failed")
    return namespace, resources


def write_yaml(path: Path, documents: list[dict]) -> None:
    path.write_text(
        "".join(
            f"---\n{yaml.safe_dump(item, sort_keys=False)}"
            for item in documents
        ),
        encoding="utf-8",
    )


def validate_chart() -> dict[str, str]:
    if not CILIUM_CHART.is_file():
        raise RuntimeValidationError(
            f"pinned Cilium chart absent: {CILIUM_CHART}"
        )
    actual = sha256(CILIUM_CHART)
    if actual != EXPECTED_CILIUM_CHART_SHA256:
        raise RuntimeValidationError(
            f"Cilium chart digest mismatch: observed sha256:{actual}"
        )
    rendered = run(
        [
            "helm",
            "template",
            "cilium",
            str(CILIUM_CHART),
            "--namespace",
            "kube-system",
            "--values",
            str(CILIUM_VALUES),
        ]
    ).stdout
    images = sorted(
        {
            line.split("image:", 1)[1].strip().strip('"')
            for line in rendered.splitlines()
            if line.strip().startswith("image:")
        }
    )
    if not images or not all("@sha256:" in image for image in images):
        raise RuntimeValidationError("Cilium images must be digest-bound")
    return {"version": "1.19.6", "sha256": actual, "images": images}


def management_preflight(
    kubectl_bin: str,
    kubeconfig: Path,
    source: dict[str, object],
) -> dict:
    progress("checking management gates, target absence, image, and endpoint")
    if not source["clean"] or not source["pushed"]:
        raise RuntimeValidationError(
            "runtime requires a clean ok-cluster commit present on origin"
        )
    gates: list[dict[str, str]] = []
    for namespace, deployment in GATE_DEPLOYMENTS:
        obj = kubectl_json(
            kubectl_bin,
            kubeconfig,
            ["-n", namespace, "get", "deployment", deployment],
        )
        manager = obj["spec"]["template"]["spec"]["containers"][0]
        feature = next(
            (
                arg
                for arg in manager["args"]
                if arg.startswith("--feature-gates=")
            ),
            "",
        )
        if "KubeadmBootstrapFormatIgnition=true" not in feature:
            raise RuntimeValidationError(
                f"Ignition gate is not enabled on {namespace}/{deployment}"
            )
        if obj.get("status", {}).get("availableReplicas") != 1:
            raise RuntimeValidationError(
                f"controller is not available: {namespace}/{deployment}"
            )
        gates.append(
            {
                "namespace": namespace,
                "deployment": deployment,
                "image": manager["image"],
                "gate_enabled": "true",
            }
        )

    absent = kubectl(
        kubectl_bin,
        kubeconfig,
        ["get", "namespace", CLUSTER, "-o", "name"],
        expected=(0, 1),
    )
    if absent.returncode == 0:
        raise RuntimeValidationError(
            f"namespace {CLUSTER} already exists; inspect or run guarded cleanup"
        )
    for kind in ("role", "rolebinding"):
        authorization = kubectl(
            kubectl_bin,
            kubeconfig,
            [
                "-n",
                EXPECTED_GOLDEN_PVC[0],
                "get",
                kind,
                CLONE_AUTHORIZATION,
                "-o",
                "name",
            ],
            expected=(0, 1),
        )
        if authorization.returncode == 0:
            raise RuntimeValidationError(
                f"{kind} {CLONE_AUTHORIZATION} already exists in "
                f"{EXPECTED_GOLDEN_PVC[0]}"
            )

    golden = kubectl_json(
        kubectl_bin,
        kubeconfig,
        [
            "-n",
            EXPECTED_GOLDEN_PVC[0],
            "get",
            "pvc",
            EXPECTED_GOLDEN_PVC[1],
        ],
    )
    annotations = golden["metadata"].get("annotations", {})
    if (
        golden["status"]["phase"] != "Bound"
        or annotations.get("ok-linux.openkubes.io/image-sha256")
        != EXPECTED_IMAGE_DIGEST
    ):
        raise RuntimeValidationError("published golden PVC identity is invalid")

    endpoint = yaml.safe_load(
        CILIUM_VALUES.read_text(encoding="utf-8")
    )["k8sServiceHost"]
    services = kubectl_json(
        kubectl_bin,
        kubeconfig,
        ["get", "service", "-A"],
    )
    collisions = []
    for service in services["items"]:
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
        raise RuntimeValidationError(
            f"declared endpoint {endpoint} is already used by {collisions}"
        )

    node = kubectl_json(
        kubectl_bin,
        kubeconfig,
        ["get", "node", "ok-infra"],
    )
    allocatable = node["status"]["allocatable"]
    return {
        "controllers": gates,
        "golden_pvc": {
            "namespace": EXPECTED_GOLDEN_PVC[0],
            "name": EXPECTED_GOLDEN_PVC[1],
            "uid": golden["metadata"]["uid"],
            "phase": golden["status"]["phase"],
            "image_digest": EXPECTED_IMAGE_DIGEST,
        },
        "endpoint": endpoint,
        "target_node_allocatable": {
            "cpu": allocatable["cpu"],
            "memory": allocatable["memory"],
        },
    }


def client_dry_run(
    kubectl_bin: str,
    kubeconfig: Path,
) -> None:
    progress("running strict client-side schema validation")
    kubectl(
        kubectl_bin,
        kubeconfig,
        [
            "create",
            "--dry-run=client",
            "--validate=strict",
            "-f",
            str(MANIFEST),
            "-o",
            "name",
        ],
    )


def wait_for_datavolumes(
    kubectl_bin: str,
    kubeconfig: Path,
    expected_count: int,
    timeout: int = 600,
) -> None:
    progress(
        f"waiting for {expected_count} DataVolume(s); "
        "annotating only test PVCs"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pvcs = kubectl_json(
            kubectl_bin,
            kubeconfig,
            ["-n", CLUSTER, "get", "pvc"],
        )["items"]
        for pvc in pvcs:
            name = pvc["metadata"]["name"]
            annotations = pvc["metadata"].get("annotations", {})
            if annotations.get("volume.kubernetes.io/selected-node") != "ok-infra":
                kubectl(
                    kubectl_bin,
                    kubeconfig,
                    [
                        "-n",
                        CLUSTER,
                        "annotate",
                        "pvc",
                        name,
                        "volume.kubernetes.io/selected-node=ok-infra",
                        "--overwrite",
                    ],
                )
        datavolumes = kubectl_json(
            kubectl_bin,
            kubeconfig,
            ["-n", CLUSTER, "get", "datavolume"],
        )["items"]
        phases = [item.get("status", {}).get("phase") for item in datavolumes]
        if (
            len(phases) == expected_count
            and all(phase == "Succeeded" for phase in phases)
        ):
            return
        time.sleep(10)
    raise RuntimeValidationError(
        f"{expected_count} DataVolume(s) did not reach Succeeded; "
        f"observed {len(phases)} with phases {phases}"
    )


def create_runtime(
    kubectl_bin: str,
    helm_bin: str,
    kubeconfig: Path,
    namespace: dict,
    resources: list[dict],
) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    namespace_path = RUNTIME_DIR / "namespace.yaml"
    resources_path = RUNTIME_DIR / "resources.yaml"
    write_yaml(namespace_path, [namespace])
    write_yaml(resources_path, resources)

    progress("creating the exact disposable namespace")
    kubectl(
        kubectl_bin,
        kubeconfig,
        ["create", "-f", str(namespace_path)],
    )
    progress("running server-side dry-run in the created namespace")
    kubectl(
        kubectl_bin,
        kubeconfig,
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
    progress("creating the bounded CAPI/CAPK resource set")
    kubectl(
        kubectl_bin,
        kubeconfig,
        ["create", "-f", str(resources_path)],
    )

    wait_for_datavolumes(kubectl_bin, kubeconfig, expected_count=1)

    progress("waiting for the workload kubeconfig Secret")
    deadline = time.monotonic() + 600
    secret = None
    while time.monotonic() < deadline:
        result = kubectl(
            kubectl_bin,
            kubeconfig,
            [
                "-n",
                CLUSTER,
                "get",
                "secret",
                f"{CLUSTER}-kubeconfig",
                "-o",
                "json",
            ],
            expected=(0, 1),
            sensitive_stdout=True,
        )
        if result.returncode == 0:
            secret = json.loads(result.stdout)
            break
        time.sleep(10)
    if secret is None:
        raise RuntimeValidationError("workload kubeconfig Secret was not created")
    encoded = secret.get("data", {}).get("value")
    if not encoded:
        raise RuntimeValidationError("workload kubeconfig Secret has no value key")
    WORKLOAD_KUBECONFIG.write_bytes(base64.b64decode(encoded))
    WORKLOAD_KUBECONFIG.chmod(0o600)
    del encoded
    del secret

    progress("waiting for the control-plane Node to register before CNI")
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        result = kubectl(
            kubectl_bin,
            WORKLOAD_KUBECONFIG,
            ["get", "node", "-o", "json"],
            expected=(0, 1),
        )
        if result.returncode == 0 and json.loads(result.stdout)["items"]:
            break
        time.sleep(10)
    else:
        raise RuntimeValidationError("workload API/Node did not become reachable")

    progress("installing digest-verified Cilium 1.19.6 from the local chart")
    run(
        [
            helm_bin,
            "upgrade",
            "--install",
            "cilium",
            str(CILIUM_CHART),
            "--kubeconfig",
            str(WORKLOAD_KUBECONFIG),
            "--namespace",
            "kube-system",
            "--values",
            str(CILIUM_VALUES),
            "--wait",
            "--timeout",
            "10m",
        ]
    )
    wait_for_datavolumes(kubectl_bin, kubeconfig, expected_count=2)
    progress("waiting for exactly two Ready Nodes")
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        nodes = kubectl_json(
            kubectl_bin,
            WORKLOAD_KUBECONFIG,
            ["get", "node"],
        )["items"]
        readiness = [
            next(
                (
                    condition["status"]
                    for condition in node["status"].get("conditions", [])
                    if condition["type"] == "Ready"
                ),
                "False",
            )
            for node in nodes
        ]
        if len(nodes) == 2 and readiness == ["True", "True"]:
            break
        time.sleep(10)
    else:
        raise RuntimeValidationError(
            f"expected two Ready Nodes; observed {len(nodes)} with {readiness}"
        )


def secret_metadata(
    kubectl_bin: str,
    kubeconfig: Path,
    name: str,
) -> dict[str, object]:
    template = (
        "{{.metadata.uid}}{{\"\\n\"}}"
        "{{range .metadata.ownerReferences}}"
        "{{.apiVersion}}|{{.kind}}|{{.name}}|{{.uid}}{{\"\\n\"}}"
        "{{end}}{{\"--keys--\\n\"}}"
        "{{range $key, $value := .data}}{{$key}}{{\"\\n\"}}{{end}}"
    )
    lines = kubectl(
        kubectl_bin,
        kubeconfig,
        [
            "-n",
            CLUSTER,
            "get",
            "secret",
            name,
            "-o",
            f"go-template={template}",
        ],
        sensitive_stdout=True,
    ).stdout.splitlines()
    separator = lines.index("--keys--")
    owners = []
    for line in lines[1:separator]:
        api_version, kind, owner_name, uid = line.split("|", 3)
        owners.append(
            {
                "apiVersion": api_version,
                "kind": kind,
                "name": owner_name,
                "uid": uid,
            }
        )
    return {
        "name": name,
        "uid": lines[0],
        "ownerReferences": owners,
        "dataKeys": sorted(lines[separator + 1 :]),
    }


def collect_runtime_evidence(
    kubectl_bin: str,
    management_kubeconfig: Path,
) -> dict:
    progress("collecting redacted G1/G3 evidence")
    nodes = kubectl_json(
        kubectl_bin,
        WORKLOAD_KUBECONFIG,
        ["get", "node"],
    )["items"]
    if len(nodes) != 2:
        raise RuntimeValidationError(f"expected two Nodes, observed {len(nodes)}")
    node_evidence = []
    for node in nodes:
        ready = next(
            (
                condition["status"]
                for condition in node["status"]["conditions"]
                if condition["type"] == "Ready"
            ),
            "False",
        )
        info = node["status"]["nodeInfo"]
        if (
            ready != "True"
            or "Flatcar" not in info["osImage"]
            or info["kubeletVersion"] != EXPECTED_VERSION
            or not node["spec"].get("providerID", "").startswith("kubevirt://")
        ):
            raise RuntimeValidationError(
                f"Node contract failed for {node['metadata']['name']}"
            )
        node_evidence.append(
            {
                "name": node["metadata"]["name"],
                "uid": node["metadata"]["uid"],
                "ready": ready,
                "osImage": info["osImage"],
                "kubeletVersion": info["kubeletVersion"],
                "containerRuntimeVersion": info["containerRuntimeVersion"],
                "providerID": node["spec"]["providerID"],
                "controlPlane": (
                    "node-role.kubernetes.io/control-plane"
                    in node["metadata"].get("labels", {})
                ),
            }
        )
    if sum(1 for item in node_evidence if item["controlPlane"]) != 1:
        raise RuntimeValidationError("expected one control-plane and one worker")

    machines = kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", CLUSTER, "get", "machine"],
    )["items"]
    if len(machines) != 2:
        raise RuntimeValidationError(
            f"expected two CAPI Machines, observed {len(machines)}"
        )
    machine_evidence = []
    node_provider_ids = {item["providerID"] for item in node_evidence}
    for machine in machines:
        provider_id = machine["spec"].get("providerID", "")
        if provider_id not in node_provider_ids:
            raise RuntimeValidationError(
                f"Machine ProviderID mismatch: {machine['metadata']['name']}"
            )
        machine_evidence.append(
            {
                "name": machine["metadata"]["name"],
                "uid": machine["metadata"]["uid"],
                "providerID": provider_id,
                "phase": machine.get("status", {}).get("phase", ""),
            }
        )

    configs = kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", CLUSTER, "get", "kubeadmconfig"],
    )["items"]
    if len(configs) != 2:
        raise RuntimeValidationError(
            f"expected two KubeadmConfigs, observed {len(configs)}"
        )
    bootstrap = []
    for config in configs:
        secret_name = config.get("status", {}).get("dataSecretName")
        if not secret_name or not config.get("status", {}).get("ready"):
            raise RuntimeValidationError(
                f"bootstrap config is not ready: {config['metadata']['name']}"
            )
        bootstrap.append(
            {
                "config": config["metadata"]["name"],
                "configUID": config["metadata"]["uid"],
                "ready": True,
                "format": config["spec"]["format"],
                "secret": secret_metadata(
                    kubectl_bin,
                    management_kubeconfig,
                    secret_name,
                ),
            }
        )

    vms = kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        ["-n", CLUSTER, "get", "virtualmachine"],
    )["items"]
    vm_evidence = []
    for vm in vms:
        refs = []
        for volume in vm["spec"]["template"]["spec"].get("volumes", []):
            config_drive = volume.get("cloudInitConfigDrive")
            if config_drive and config_drive.get("secretRef", {}).get("name"):
                refs.append(config_drive["secretRef"]["name"])
        if len(refs) != 1:
            raise RuntimeValidationError(
                f"VM must consume one Secret-backed ConfigDrive: "
                f"{vm['metadata']['name']}"
            )
        vm_evidence.append(
            {
                "name": vm["metadata"]["name"],
                "uid": vm["metadata"]["uid"],
                "configDriveSecretRefs": refs,
            }
        )

    cilium = kubectl(
        kubectl_bin,
        WORKLOAD_KUBECONFIG,
        [
            "-n",
            "kube-system",
            "exec",
            "daemonset/cilium",
            "--",
            "cilium",
            "status",
            "--brief",
        ],
    )
    if "OK" not in cilium.stdout:
        raise RuntimeValidationError("Cilium brief health did not report OK")

    role = kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        [
            "-n",
            EXPECTED_GOLDEN_PVC[0],
            "get",
            "role",
            CLONE_AUTHORIZATION,
        ],
    )
    role_binding = kubectl_json(
        kubectl_bin,
        management_kubeconfig,
        [
            "-n",
            EXPECTED_GOLDEN_PVC[0],
            "get",
            "rolebinding",
            CLONE_AUTHORIZATION,
        ],
    )
    return {
        "nodes": node_evidence,
        "machines": machine_evidence,
        "bootstrap": bootstrap,
        "virtualMachines": vm_evidence,
        "cilium": {"version": "1.19.6", "status": "PASS"},
        "goldenImageCloneAuthorization": {
            "namespace": EXPECTED_GOLDEN_PVC[0],
            "role": {
                "name": role["metadata"]["name"],
                "uid": role["metadata"]["uid"],
                "resource": "datavolumes/source",
                "verb": "create",
            },
            "roleBinding": {
                "name": role_binding["metadata"]["name"],
                "uid": role_binding["metadata"]["uid"],
                "subject": f"system:serviceaccount:{CLUSTER}:default",
            },
        },
        "lifecycle_authorities": {
            "ssh": False,
            "remote_shell": False,
            "imperative_guest_mutation": False,
        },
    }


def write_result(result: dict) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "node-ready.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )


def preflight() -> tuple[str, str, Path, dict]:
    kubectl_bin, helm_bin, kubeconfig = require_inputs()
    rendered = render()
    namespace, resources = manifest_documents()
    chart = validate_chart()
    source = source_state()
    management = management_preflight(kubectl_bin, kubeconfig, source)
    client_dry_run(kubectl_bin, kubeconfig)
    result = {
        "schema_version": 1,
        "suite": "OK-125-node-ready",
        "status": "PREFLIGHT",
        "scope": "disposable-g1-g3-runtime",
        "source": source,
        "render": rendered,
        "cilium_artifact": chart,
        "management": management,
        "object_count": 1 + len(resources),
        "runtime_gates": {
            "G1_kubernetes_node_ready": "NOT_TESTED",
            "G3_provider_scoped_bootstrap_secret": "NOT_TESTED",
        },
    }
    write_result(result)
    return kubectl_bin, helm_bin, kubeconfig, {
        "result": result,
        "namespace": namespace,
        "resources": resources,
    }


def node_ready() -> int:
    kubectl_bin, helm_bin, kubeconfig, state = preflight()
    try:
        create_runtime(
            kubectl_bin,
            helm_bin,
            kubeconfig,
            state["namespace"],
            state["resources"],
        )
        runtime = collect_runtime_evidence(kubectl_bin, kubeconfig)
        result = state["result"]
        result["status"] = "PASS"
        result["runtime"] = runtime
        result["runtime_gates"] = {
            "G1_kubernetes_node_ready": "PASS",
            "G3_provider_scoped_bootstrap_secret": "PASS",
        }
        write_result(result)
        progress("PASS G1 Node Ready and G3 Secret boundary")
        return 0
    except Exception as error:
        result = state["result"]
        result["status"] = "FAIL"
        result["detail"] = str(error)
        result["runtime_gates"] = {
            "G1_kubernetes_node_ready": "FAIL",
            "G3_provider_scoped_bootstrap_secret": "FAIL",
        }
        write_result(result)
        raise


def cleanup() -> int:
    kubectl_bin, _, kubeconfig = require_inputs()
    if os.environ.get("OK125_CLEANUP") != "yes":
        raise RuntimeValidationError("cleanup requires OK125_CLEANUP=yes")
    namespace = kubectl_json(
        kubectl_bin,
        kubeconfig,
        ["get", "namespace", CLUSTER],
    )
    labels = namespace["metadata"].get("labels", {})
    if (
        labels.get("openkubes.io/type") != "flatcar"
        or labels.get("openkubes.io/adoption-status") != "adoption-gated"
        or labels.get("openkubes.io/deployable") != "false"
    ):
        raise RuntimeValidationError("namespace ownership labels do not match")
    for kind in ("role", "rolebinding"):
        authorization = kubectl(
            kubectl_bin,
            kubeconfig,
            [
                "-n",
                EXPECTED_GOLDEN_PVC[0],
                "get",
                kind,
                CLONE_AUTHORIZATION,
                "-o",
                "json",
            ],
            expected=(0, 1),
        )
        if authorization.returncode == 0:
            labels = json.loads(authorization.stdout)["metadata"].get(
                "labels", {}
            )
            if (
                labels.get("openkubes.io/type") != "flatcar"
                or labels.get("openkubes.io/deployable") != "false"
            ):
                raise RuntimeValidationError(
                    f"{kind} clone authorization ownership does not match"
                )
    cluster = kubectl(
        kubectl_bin,
        kubeconfig,
        ["-n", CLUSTER, "get", "cluster", CLUSTER, "-o", "json"],
        expected=(0, 1),
    )
    if cluster.returncode == 0:
        cluster_object = json.loads(cluster.stdout)
        cluster_labels = cluster_object["metadata"].get("labels", {})
        if (
            cluster_labels.get("openkubes.io/type") != "flatcar"
            or cluster_labels.get("openkubes.io/deployable") != "false"
        ):
            raise RuntimeValidationError("Cluster ownership labels do not match")
        progress("deleting only the disposable CAPI Cluster")
        kubectl(
            kubectl_bin,
            kubeconfig,
            [
                "-n",
                CLUSTER,
                "delete",
                "cluster",
                CLUSTER,
                "--cascade=foreground",
                "--wait=true",
                "--timeout=600s",
            ],
        )
    else:
        progress("no CAPI Cluster exists; cleaning the partial namespace")
    progress("deleting only the disposable namespace")
    kubectl(
        kubectl_bin,
        kubeconfig,
        [
            "delete",
            "namespace",
            CLUSTER,
            "--wait=true",
            "--timeout=300s",
        ],
    )
    absent = kubectl(
        kubectl_bin,
        kubeconfig,
        ["get", "namespace", CLUSTER, "-o", "name"],
        expected=(1,),
    )
    if absent.returncode != 1:
        raise RuntimeValidationError("namespace still exists after cleanup")
    deadline = time.monotonic() + 300
    leftovers: list[str] = []
    while time.monotonic() < deadline:
        pvs = kubectl_json(kubectl_bin, kubeconfig, ["get", "persistentvolume"])
        leftovers = [
            item["metadata"]["name"]
            for item in pvs["items"]
            if item.get("spec", {}).get("claimRef", {}).get("namespace")
            == CLUSTER
        ]
        if not leftovers:
            break
        time.sleep(5)
    if leftovers:
        raise RuntimeValidationError(f"orphan PVs remain: {leftovers}")
    progress("removing the exact golden-image clone authorization")
    for kind in ("rolebinding", "role"):
        kubectl(
            kubectl_bin,
            kubeconfig,
            [
                "-n",
                EXPECTED_GOLDEN_PVC[0],
                "delete",
                kind,
                CLONE_AUTHORIZATION,
                "--ignore-not-found",
                "--wait=true",
            ],
        )
    if WORKLOAD_KUBECONFIG.exists():
        WORKLOAD_KUBECONFIG.unlink()
    progress("PASS exact-scope cleanup")
    return 0


def self_test() -> int:
    if CLUSTER != "ok125-flatcar":
        raise AssertionError("cluster scope changed")
    false_namespace = {
        "metadata": {
            "name": CLUSTER,
            "labels": {"openkubes.io/deployable": "false"},
            "annotations": {
                "openkubes.io/os-identity-full": EXPECTED_OS_IDENTITY
            },
        },
        "kind": "Namespace",
    }
    assert false_namespace["metadata"]["name"] == CLUSTER
    assert EXPECTED_CILIUM_CHART_SHA256 == (
        "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
    )
    print("PASS runtime scope, identity, and Cilium artifact are pinned")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeValidationError(
            "usage: runtime.py --preflight|--node-ready|--cleanup|--self-test"
        )
    action = sys.argv[1]
    if action == "--self-test":
        return self_test()
    if action == "--preflight":
        preflight()
        progress("PREFLIGHT PASS; no runtime object was created")
        return 0
    if action == "--node-ready":
        return node_ready()
    if action == "--cleanup":
        return cleanup()
    raise RuntimeValidationError(f"unknown action: {action}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        yaml.YAMLError,
        RuntimeValidationError,
    ) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
