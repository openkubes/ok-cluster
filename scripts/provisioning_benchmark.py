#!/usr/bin/env python3
"""Guarded, OS-neutral provisioning observer for OK-128.

The observer wraps an existing supported Make target.  It does not render,
apply, install, or clean up resources itself.  Kubernetes reads are sampled
once per second and evidence is written only after redaction and validation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "docs" / "adoption" / "OK-128" / "evidence"
EXPECTED_CHART_SHA256 = (
    "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
)
EXPECTED_KUBERNETES = "v1.34.1"
EXPECTED_NODE = "ok-infra"
EXPECTED_STORAGE_CLASS = "ok-storage-block"
EXPECTED_NODES = 2
MILESTONES = (
    "command_started",
    "capi_cluster_created",
    "api_reachable_control_plane_registered",
    "first_node_ready",
    "all_nodes_ready",
    "cilium_daemonset_available",
    "cilium_operator_available",
    "capi_cluster_available",
    "command_completed",
)
SECRET_KEY = re.compile(
    r"(?im)^(\s*(?:token|password|client-key-data|client-certificate-data|"
    r"certificate-authority-data|data|stringData)\s*:\s*).+$"
)
SECRET_FLAG = re.compile(
    r"(?i)(--(?:token|password|client-key|client-certificate|"
    r"certificate-authority)(?:=|\s+))(\S+)"
)
JSON_SECRET_KEY = re.compile(
    r'(?i)("(?:token|password|client-key-data|client-certificate-data|'
    r'certificate-authority-data)"\s*:\s*)(".*?"|[^,\n}]+)'
)
PEM = re.compile(
    r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL
)
FORBIDDEN_AFTER_REDACTION = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?im)^\s*(?:token|password|client-key-data)\s*:\s*"
        r"(?!\[REDACTED\])\S+"
    ),
    re.compile(r"(?i)--(?:token|password)(?:=|\s+)(?!\[REDACTED\])\S+"),
    re.compile(
        r'(?i)"(?:token|password|client-key-data)"\s*:\s*'
        r'(?!"\[REDACTED\]")".+?"'
    ),
)


class BenchmarkError(RuntimeError):
    """The benchmark cannot produce trustworthy comparable evidence."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text: str) -> str:
    text = PEM.sub("[REDACTED PEM]", text)
    text = SECRET_KEY.sub(r"\1[REDACTED]", text)
    text = SECRET_FLAG.sub(r"\1[REDACTED]", text)
    return JSON_SECRET_KEY.sub(r'\1"[REDACTED]"', text)


def require_sanitized(text: str) -> None:
    matches = [
        pattern.pattern
        for pattern in FORBIDDEN_AFTER_REDACTION
        if pattern.search(text)
    ]
    if matches:
        raise BenchmarkError(
            "secret scan failed closed after redaction; refusing evidence publication"
        )


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    require_sanitized(content)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        raise BenchmarkError(f"required file does not exist: {path}")
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise BenchmarkError(f"expected YAML mapping: {path}")
    return value


def validate_envelope(config: dict, os_name: str, cluster: str) -> dict:
    expected_type = {"flatcar": "flatcar", "talos": "talos"}[os_name]
    failures = []
    checks = {
        "name": (config.get("name"), cluster),
        "type": (config.get("type"), expected_type),
        "provider": (config.get("provider"), "kubevirt"),
        "architecture": (config.get("architecture", "amd64"), "amd64"),
        "controlPlane.replicas": (
            config.get("controlPlane", {}).get("replicas"),
            1,
        ),
        "controlPlane.cores": (config.get("controlPlane", {}).get("cores"), 2),
        "controlPlane.memory": (
            config.get("controlPlane", {}).get("memory"),
            "4Gi",
        ),
        "controlPlane.disk": (
            config.get("controlPlane", {}).get("disk"),
            "20Gi",
        ),
        "workers.replicas": (config.get("workers", {}).get("replicas"), 1),
        "workers.cores": (config.get("workers", {}).get("cores"), 2),
        "workers.memory": (config.get("workers", {}).get("memory"), "4Gi"),
        "workers.disk": (config.get("workers", {}).get("disk"), "20Gi"),
        "nodeSelector": (config.get("nodeSelector"), EXPECTED_NODE),
    }
    for key, (actual, expected) in checks.items():
        if actual != expected:
            failures.append(f"{key}={actual!r}, expected {expected!r}")
    version = config.get("versions", {}).get("kubernetes")
    if version not in (None, EXPECTED_KUBERNETES):
        failures.append(
            f"versions.kubernetes={version!r}, expected {EXPECTED_KUBERNETES!r}"
        )
    golden = config.get("os", {}).get("goldenImage", {})
    expected_storage = (
        "local-path" if os_name == "flatcar" else EXPECTED_STORAGE_CLASS
    )
    storage = golden.get("storageClass")
    if storage not in (None, expected_storage):
        failures.append(
            f"os.goldenImage.storageClass={storage!r}, "
            f"expected {expected_storage!r}"
        )
    if failures:
        raise BenchmarkError(
            "cluster is outside the controlled OK-128 envelope: "
            + "; ".join(failures)
        )
    return {
        "provider": "kubevirt",
        "architecture": "amd64",
        "kubernetes": EXPECTED_KUBERNETES,
        "control_plane_replicas": 1,
        "worker_replicas": 1,
        "expected_nodes": EXPECTED_NODES,
        "node_selector": EXPECTED_NODE,
    }


def git_state(path: Path) -> dict:
    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(path), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise BenchmarkError(
                f"git {' '.join(arguments)} failed for {path}: "
                f"{result.stderr.strip()}"
            )
        return result.stdout.strip()

    return {
        "path": str(path),
        "revision": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "clean": not bool(git("status", "--porcelain")),
        "pushed": bool(git("branch", "-r", "--contains", "HEAD")),
    }


def run_json(command: list[str]) -> dict | None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def kubectl_json(kubeconfig: Path, arguments: list[str]) -> dict | None:
    return run_json(
        ["kubectl", "--kubeconfig", str(kubeconfig), *arguments, "-o", "json"]
    )


def kubectl_json_strict_optional(
    kubeconfig: Path, arguments: list[str]
) -> dict | None:
    command = [
        "kubectl",
        "--kubeconfig",
        str(kubeconfig),
        *arguments,
        "-o",
        "json",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise BenchmarkError(
                f"kubectl returned invalid JSON for {' '.join(arguments)}"
            ) from error
    if result.returncode == 1 and re.search(
        r"\bnot found\b|\bNotFound\b", result.stderr
    ):
        return None
    raise BenchmarkError(
        f"kubectl read failed for {' '.join(arguments)}: "
        f"{redact(result.stderr.strip()) or f'exit {result.returncode}'}"
    )


def true_condition(resource: dict | None, *names: str) -> dict | None:
    if not resource:
        return None
    status = resource.get("status", {})
    sets = [status.get("conditions", [])]
    if isinstance(status.get("v1beta2"), dict):
        sets.append(status["v1beta2"].get("conditions", []))
    return next(
        (
            condition
            for conditions in sets
            for condition in conditions
            if condition.get("type") in names
            and condition.get("status") == "True"
        ),
        None,
    )


def ready_transition(node: dict) -> str | None:
    condition = next(
        (
            item
            for item in node.get("status", {}).get("conditions", [])
            if item.get("type") == "Ready" and item.get("status") == "True"
        ),
        None,
    )
    return condition.get("lastTransitionTime") if condition else None


def update_milestones(
    milestones: dict[str, str],
    management: dict | None,
    workload: dict[str, dict | None],
    observed_at: str,
    expected_nodes: int = EXPECTED_NODES,
) -> None:
    if management:
        metadata = management.get("metadata", {})
        if metadata.get("creationTimestamp"):
            milestones.setdefault(
                "capi_cluster_created", metadata["creationTimestamp"]
            )
        available = true_condition(management, "Available", "Ready")
        if available:
            milestones.setdefault(
                "capi_cluster_available",
                available.get("lastTransitionTime") or observed_at,
            )

    nodes = (workload.get("nodes") or {}).get("items", [])
    control_plane = [
        item
        for item in nodes
        if "node-role.kubernetes.io/control-plane"
        in item.get("metadata", {}).get("labels", {})
    ]
    if control_plane:
        milestones.setdefault(
            "api_reachable_control_plane_registered", observed_at
        )
    ready = [value for value in (ready_transition(node) for node in nodes) if value]
    if ready:
        milestones.setdefault("first_node_ready", min(ready, key=parse_time))
    if len(ready) == expected_nodes and len(nodes) == expected_nodes:
        milestones.setdefault("all_nodes_ready", max(ready, key=parse_time))

    daemonset = workload.get("cilium_daemonset") or {}
    ds_status = daemonset.get("status", {})
    if (
        ds_status.get("desiredNumberScheduled", 0) == expected_nodes
        and ds_status.get("numberAvailable", 0) == expected_nodes
    ):
        milestones.setdefault("cilium_daemonset_available", observed_at)

    operator = workload.get("cilium_operator") or {}
    op_status = operator.get("status", {})
    if op_status.get("availableReplicas", 0) >= 1:
        milestones.setdefault("cilium_operator_available", observed_at)


def workload_snapshot(kubeconfig: Path) -> dict[str, dict | None]:
    if not kubeconfig.is_file():
        return {}
    return {
        "nodes": kubectl_json(kubeconfig, ["get", "nodes"]),
        "cilium_daemonset": kubectl_json(
            kubeconfig, ["-n", "kube-system", "get", "daemonset", "cilium"]
        ),
        "cilium_operator": kubectl_json(
            kubeconfig,
            ["-n", "kube-system", "get", "deployment", "cilium-operator"],
        ),
    }


def management_load(kubeconfig: Path) -> dict:
    node = kubectl_json_strict_optional(
        kubeconfig, ["get", "node", EXPECTED_NODE]
    )
    pods = kubectl_json_strict_optional(
        kubeconfig,
        ["get", "pods", "-A", "--field-selector", f"spec.nodeName={EXPECTED_NODE}"],
    )
    vmis = kubectl_json_strict_optional(
        kubeconfig, ["get", "virtualmachineinstances", "-A"]
    )
    if node is None or pods is None or vmis is None:
        raise BenchmarkError("cannot read management-cluster load snapshot")
    phases: dict[str, int] = {}
    for item in pods.get("items", []):
        phase = item.get("status", {}).get("phase", "Unknown")
        phases[phase] = phases.get(phase, 0) + 1
    return {
        "observed_at": utc_now(),
        "node": EXPECTED_NODE,
        "allocatable": node.get("status", {}).get("allocatable", {}),
        "scheduled_pods": len(pods.get("items", [])),
        "pod_phases": phases,
        "running_vmis": sum(
            item.get("status", {}).get("phase") == "Running"
            for item in vmis.get("items", [])
        ),
        "total_vmis": len(vmis.get("items", [])),
    }


def golden_image_snapshot(kubeconfig: Path, config: dict) -> dict:
    os_config = config.get("os", {})
    golden = os_config.get("goldenImage", {})
    namespace = golden.get("namespace")
    claim = golden.get("claim")
    identity = os_config.get("identity")
    image_digest = os_config.get("imageDigest")
    if (
        not namespace
        or not claim
        or not str(identity).startswith("sha256:")
        or not str(image_digest).startswith("sha256:")
    ):
        raise BenchmarkError(
            "materialized config lacks Golden claim, identity, or image digest"
        )
    pvc = kubectl_json_strict_optional(
        kubeconfig,
        ["-n", namespace, "get", "persistentvolumeclaim", claim],
    )
    if not pvc or pvc.get("status", {}).get("phase") != "Bound":
        raise BenchmarkError(
            f"Golden-Image PVC is absent or not Bound: {namespace}/{claim}"
        )
    metadata = pvc.get("metadata", {})
    actual_storage = pvc.get("spec", {}).get("storageClassName")
    annotations = {
        key: value
        for key, value in metadata.get("annotations", {}).items()
        if key.startswith("openkubes.io/")
        or key == "cdi.kubevirt.io/storage.contentType"
    }
    return {
        "namespace": namespace,
        "claim": claim,
        "uid": metadata.get("uid"),
        "phase": "Bound",
        "source_storage_class": actual_storage,
        "clone_target_storage_class": golden.get("storageClass"),
        "identity": identity,
        "image_digest": image_digest,
        "annotations": annotations,
    }


def parse_posix_time(text: str) -> dict[str, float]:
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"(real|user|sys)\s+([0-9]+(?:\.[0-9]+)?)", line.strip()
        )
        if match:
            values[match.group(1)] = float(match.group(2))
    if set(values) != {"real", "user", "sys"}:
        raise BenchmarkError("could not parse POSIX real/user/sys timing")
    return values


def validate_timeline(timeline: dict[str, str]) -> None:
    if set(timeline) != set(MILESTONES):
        raise BenchmarkError("milestone timeline is incomplete")
    started = parse_time(timeline["command_started"])
    completed = parse_time(timeline["command_completed"])
    if completed < started:
        raise BenchmarkError("command completion predates command start")
    outside = [
        name
        for name, value in timeline.items()
        if parse_time(value) < started or parse_time(value) > completed
    ]
    if outside:
        raise BenchmarkError(
            f"milestones outside command bounds: {outside}"
        )
    if parse_time(timeline["first_node_ready"]) > parse_time(
        timeline["all_nodes_ready"]
    ):
        raise BenchmarkError("first Node Ready follows all Nodes Ready")


def manifest_identities(cluster_dir: Path) -> list[dict]:
    result = []
    for name in (
        "cluster-config.yaml",
        "cluster-base.yaml",
        "cluster-v2.yaml",
        "cilium-values.yaml",
    ):
        path = cluster_dir / name
        if path.is_file():
            result.append(
                {"path": str(path.relative_to(ROOT)), "sha256": sha256(path)}
            )
    return result


def validate_command(os_name: str, command: list[str]) -> None:
    expected = "install-flatcar" if os_name == "flatcar" else "bootstrap"
    if not command or Path(command[0]).name not in {"make", "gmake"}:
        raise BenchmarkError("wrapped command must invoke make")
    if expected not in command:
        raise BenchmarkError(
            f"{os_name} benchmark must wrap the supported make {expected} target"
        )


def benchmark_preflight(args: argparse.Namespace) -> dict:
    management_kubeconfig = Path(args.management_kubeconfig).expanduser().resolve()
    workload_kubeconfig = Path(args.workload_kubeconfig).expanduser().resolve()
    chart = Path(args.cilium_chart).expanduser().resolve()
    config_path = ROOT / args.cluster / "cluster-config.yaml"
    config = load_yaml(config_path)
    envelope = validate_envelope(config, args.os, args.cluster)
    for path, label in (
        (management_kubeconfig, "management kubeconfig"),
        (chart, "Cilium chart"),
    ):
        if not path.is_file():
            raise BenchmarkError(f"{label} does not exist: {path}")
    if sha256(chart) != EXPECTED_CHART_SHA256:
        raise BenchmarkError("Cilium chart digest mismatch")
    if workload_kubeconfig.exists():
        raise BenchmarkError(
            f"workload kubeconfig already exists; refusing stale observation: "
            f"{workload_kubeconfig}"
        )
    if shutil.which("kubectl") is None:
        raise BenchmarkError("required executable not found: kubectl")
    if kubectl_json_strict_optional(
        management_kubeconfig, ["get", "namespace", args.cluster]
    ) is not None:
        raise BenchmarkError(
            f"namespace {args.cluster} already exists; cold cluster run required"
        )

    sources = {
        "ok-cluster": git_state(ROOT),
        "ok-linux": git_state(Path(args.ok_linux_path).expanduser().resolve()),
    }
    if any(
        not value["clean"] or not value["pushed"]
        for value in sources.values()
    ):
        raise BenchmarkError(
            "source repositories must be clean and present on a remote "
            "before benchmark"
        )
    golden_snapshot = golden_image_snapshot(management_kubeconfig, config)
    before = management_load(management_kubeconfig)
    return {
        "management_kubeconfig": management_kubeconfig,
        "workload_kubeconfig": workload_kubeconfig,
        "chart": chart,
        "config": config,
        "envelope": envelope,
        "sources": sources,
        "golden_snapshot": golden_snapshot,
        "management_load": before,
    }


def preflight_command(args: argparse.Namespace) -> int:
    state = benchmark_preflight(args)
    summary = {
        "cluster": args.cluster,
        "os": args.os,
        "envelope": state["envelope"],
        "source": state["sources"],
        "golden_image": state["golden_snapshot"],
        "management_load": state["management_load"],
        "cilium_chart_sha256": EXPECTED_CHART_SHA256,
        "workload_kubeconfig_absent": True,
        "cluster_namespace_absent": True,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("PASS OK-128 read-only management preflight")
    return 0


def run_benchmark(args: argparse.Namespace) -> int:
    if os.environ.get("OK128_BENCHMARK_APPLY") != "yes":
        raise BenchmarkError(
            "refusing runtime: set OK128_BENCHMARK_APPLY=yes after explicit approval"
        )
    validate_command(args.os, args.command)
    time_binary = Path(args.time_binary)
    if not time_binary.is_file():
        raise BenchmarkError(f"POSIX time binary does not exist: {time_binary}")
    output = Path(args.output_dir).resolve()
    conflicts = sorted(output.glob(f"{args.run_id}.*")) if output.exists() else []
    if conflicts:
        raise BenchmarkError(
            f"run ID {args.run_id!r} already has evidence; refusing overwrite: "
            f"{[path.name for path in conflicts]}"
        )
    state = benchmark_preflight(args)
    management_kubeconfig = state["management_kubeconfig"]
    workload_kubeconfig = state["workload_kubeconfig"]
    chart = state["chart"]
    config = state["config"]
    envelope = state["envelope"]
    sources = state["sources"]
    golden_snapshot = state["golden_snapshot"]
    before = state["management_load"]
    milestones = {"command_started": utc_now()}
    time_descriptor, time_name = tempfile.mkstemp(prefix=".ok128-time-")
    os.close(time_descriptor)
    time_file = Path(time_name)
    output_lines: list[str] = []
    command = [
        str(time_binary),
        "-p",
        "-o",
        str(time_file),
        *args.command,
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def consume() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            sanitized = redact(line)
            output_lines.append(sanitized)
            print(sanitized, end="", flush=True)

    reader = threading.Thread(target=consume, daemon=True)
    reader.start()
    deadline_after_completion: float | None = None
    lifecycle_completed_at: str | None = None
    while True:
        observed = utc_now()
        cluster = kubectl_json(
            management_kubeconfig,
            ["-n", args.cluster, "get", "cluster", args.cluster],
        )
        update_milestones(
            milestones,
            cluster,
            workload_snapshot(workload_kubeconfig),
            observed,
        )
        returncode = process.poll()
        if returncode is not None and deadline_after_completion is None:
            lifecycle_completed_at = observed
            deadline_after_completion = time.monotonic() + args.post_command_timeout
        if returncode is not None:
            observable = all(
                name in milestones for name in MILESTONES[:-1]
            )
            timed_out = time.monotonic() >= deadline_after_completion
            if observable or timed_out:
                milestones["command_completed"] = observed
                break
        time.sleep(1)
    reader.join(timeout=10)
    timing = parse_posix_time(time_file.read_text(encoding="utf-8"))
    time_file.unlink(missing_ok=True)
    after = management_load(management_kubeconfig)

    missing = [name for name in MILESTONES if name not in milestones]
    if process.returncode != 0 or missing:
        failed = {
            "schema": "openkubes.ok128.provisioning-benchmark-failure/v1",
            "classification": "failed-observation-no-slo",
            "run_id": args.run_id,
            "os": args.os,
            "cluster": args.cluster,
            "test_order": args.test_order,
            "command": args.command,
            "exit_code": process.returncode,
            "operator_timing_seconds": timing,
            "lifecycle_command_completed": lifecycle_completed_at,
            "observed_timeline": milestones,
            "missing_milestones": missing,
            "envelope": envelope,
            "source": sources,
            "management_load": {"before": before, "after": after},
        }
        output = Path(args.output_dir).resolve()
        atomic_text(
            output / f"{args.run_id}.failed.json",
            redact(json.dumps(failed, indent=2, sort_keys=True) + "\n"),
        )
        atomic_text(
            output / f"{args.run_id}.failed.log",
            redact("".join(output_lines)),
        )
        raise BenchmarkError(
            f"run is incomplete: exit={process.returncode}, missing={missing}; "
            f"sanitized failure evidence was retained in {output}"
        )
    validate_timeline(milestones)
    nodes = workload_snapshot(workload_kubeconfig).get("nodes") or {}
    observed_nodes = nodes.get("items", [])
    if len(observed_nodes) != EXPECTED_NODES:
        raise BenchmarkError("final workload node count is not exactly two")
    for node in observed_nodes:
        info = node.get("status", {}).get("nodeInfo", {})
        if info.get("kubeletVersion") != EXPECTED_KUBERNETES:
            raise BenchmarkError("observed Kubernetes version differs from pin")
        os_image = info.get("osImage", "").lower()
        if args.os not in os_image:
            raise BenchmarkError(
                f"node OS identity does not contain {args.os!r}: {os_image!r}"
            )

    started = parse_time(milestones["command_started"])
    evidence = {
        "schema": "openkubes.ok128.provisioning-benchmark/v1",
        "classification": "observed-single-run-no-slo",
        "run_id": args.run_id,
        "os": args.os,
        "cluster": args.cluster,
        "test_order": args.test_order,
        "command": args.command,
        "exit_code": process.returncode,
        "operator_timing_seconds": timing,
        "lifecycle_command_completed": {
            "timestamp": lifecycle_completed_at,
            "elapsed_seconds": int(
                (parse_time(lifecycle_completed_at) - started).total_seconds()
            ),
        },
        "timeline": {
            name: {
                "timestamp": milestones[name],
                "elapsed_seconds": int(
                    (parse_time(milestones[name]) - started).total_seconds()
                ),
            }
            for name in MILESTONES
        },
        "envelope": envelope,
        "source": sources,
        "inputs": {
            "cluster_config": config,
            "cilium_chart": {
                "version": "1.19.6",
                "path": str(chart),
                "sha256": EXPECTED_CHART_SHA256,
            },
            "files": manifest_identities(ROOT / args.cluster),
            "golden_image": golden_snapshot,
            "os_identity": config.get("os", {}).get("identity"),
            "image_digest": config.get("os", {}).get("imageDigest"),
            "talos_version": config.get("versions", {}).get("talos"),
            "talos_schematic_id": config.get("os", {}).get("schematic_id"),
        },
        "management_load": {"before": before, "after": after},
        "final_nodes": [
            {
                "name": node.get("metadata", {}).get("name"),
                "kubelet_version": node.get("status", {})
                .get("nodeInfo", {})
                .get("kubeletVersion"),
                "os_image": node.get("status", {})
                .get("nodeInfo", {})
                .get("osImage"),
            }
            for node in observed_nodes
        ],
    }
    encoded = redact(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    log = redact("".join(output_lines))
    require_sanitized(encoded)
    require_sanitized(log)
    output = Path(args.output_dir).resolve()
    atomic_text(output / f"{args.run_id}.json", encoded)
    atomic_text(output / f"{args.run_id}.log", log)
    print(f"PASS OK-128 evidence: {output / (args.run_id + '.json')}")
    return 0


def load_evidence(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "openkubes.ok128.provisioning-benchmark/v1":
        raise BenchmarkError(f"unsupported evidence schema: {path}")
    return value


def compare_results(flatcar: dict, talos: dict) -> tuple[str, str]:
    runs = {"flatcar": flatcar, "talos": talos}
    if flatcar.get("os") != "flatcar" or talos.get("os") != "talos":
        raise BenchmarkError("comparison requires one Flatcar and one Talos run")
    if flatcar.get("envelope") != talos.get("envelope"):
        raise BenchmarkError("benchmark envelopes differ")
    for repository in ("ok-cluster", "ok-linux"):
        left = flatcar.get("source", {}).get(repository, {}).get("revision")
        right = talos.get("source", {}).get(repository, {}).get("revision")
        if not left or left != right:
            raise BenchmarkError(
                f"{repository} revisions differ or are absent"
            )
    for name, result in runs.items():
        if result.get("exit_code") != 0:
            raise BenchmarkError(f"{name} lifecycle command did not succeed")
        if set(result.get("timeline", {})) != set(MILESTONES):
            raise BenchmarkError(f"{name} timeline is incomplete")
        validate_timeline(
            {
                milestone: result["timeline"][milestone]["timestamp"]
                for milestone in MILESTONES
            }
        )
        if (
            result.get("classification") != "observed-single-run-no-slo"
            or result.get("inputs", {})
            .get("cilium_chart", {})
            .get("sha256")
            != EXPECTED_CHART_SHA256
        ):
            raise BenchmarkError(
                f"{name} result lacks the observed-only classification "
                "or pinned chart identity"
            )
    ordered = sorted(
        runs.values(),
        key=lambda value: value["test_order"],
    )
    if ordered[0]["test_order"] == ordered[1]["test_order"]:
        raise BenchmarkError("test_order values must be unique")
    first_end = parse_time(ordered[0]["timeline"]["command_completed"]["timestamp"])
    second_start = parse_time(ordered[1]["timeline"]["command_started"]["timestamp"])
    if second_start < first_end:
        raise BenchmarkError("benchmark runs overlap; sequential execution required")

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer, lineterminator="\n")
    writer.writerow(["milestone", "flatcar_seconds", "talos_seconds"])
    for milestone in MILESTONES:
        writer.writerow(
            [
                milestone,
                flatcar["timeline"][milestone]["elapsed_seconds"],
                talos["timeline"][milestone]["elapsed_seconds"],
            ]
        )
    writer.writerow(
        [
            "operator_real",
            flatcar["operator_timing_seconds"]["real"],
            talos["operator_timing_seconds"]["real"],
        ]
    )
    for metric in ("scheduled_pods", "running_vmis", "total_vmis"):
        writer.writerow(
            [
                f"management_{metric}_before",
                flatcar["management_load"]["before"][metric],
                talos["management_load"]["before"][metric],
            ]
        )
        writer.writerow(
            [
                f"management_{metric}_after",
                flatcar["management_load"]["after"][metric],
                talos["management_load"]["after"][metric],
            ]
        )

    lines = [
        "# OK-128 observed provisioning comparison",
        "",
        "> Two sequential, controlled single runs. Observations only; no SLO claim.",
        "",
        "| Milestone | Flatcar (s) | Talos (s) |",
        "|---|---:|---:|",
    ]
    for milestone in MILESTONES:
        lines.append(
            f"| `{milestone}` | "
            f"{flatcar['timeline'][milestone]['elapsed_seconds']} | "
            f"{talos['timeline'][milestone]['elapsed_seconds']} |"
        )
    lines.extend(
        [
            f"| operator `real` | {flatcar['operator_timing_seconds']['real']} | "
            f"{talos['operator_timing_seconds']['real']} |",
            "",
            "## Management-cluster load",
            "",
            "| Measurement | Flatcar before/after | Talos before/after |",
            "|---|---:|---:|",
            "| scheduled pods | "
            f"{flatcar['management_load']['before']['scheduled_pods']}/"
            f"{flatcar['management_load']['after']['scheduled_pods']} | "
            f"{talos['management_load']['before']['scheduled_pods']}/"
            f"{talos['management_load']['after']['scheduled_pods']} |",
            "| running VMIs | "
            f"{flatcar['management_load']['before']['running_vmis']}/"
            f"{flatcar['management_load']['after']['running_vmis']} | "
            f"{talos['management_load']['before']['running_vmis']}/"
            f"{talos['management_load']['after']['running_vmis']} |",
            "",
            f"Order: {ordered[0]['os']} then {ordered[1]['os']}.",
            "",
        ]
    )
    return "\n".join(lines), csv_buffer.getvalue()


def compare_command(args: argparse.Namespace) -> int:
    markdown, csv_text = compare_results(
        load_evidence(Path(args.flatcar)),
        load_evidence(Path(args.talos)),
    )
    output = Path(args.output_dir).resolve()
    atomic_text(output / "comparison.md", markdown)
    atomic_text(output / "comparison.csv", csv_text)
    print(f"PASS OK-128 comparison: {output / 'comparison.md'}")
    return 0


def verify_cleanup(args: argparse.Namespace) -> int:
    management = Path(args.management_kubeconfig).expanduser().resolve()
    if not management.is_file():
        raise BenchmarkError(
            f"management kubeconfig does not exist: {management}"
        )
    namespace = kubectl_json_strict_optional(
        management, ["get", "namespace", args.cluster]
    )
    if namespace is not None:
        raise BenchmarkError(f"cluster namespace still exists: {args.cluster}")
    authorization = f"{args.cluster}-golden-image-cloner"
    role = kubectl_json_strict_optional(
        management,
        ["-n", args.golden_namespace, "get", "role", authorization],
    )
    binding = kubectl_json_strict_optional(
        management,
        ["-n", args.golden_namespace, "get", "rolebinding", authorization],
    )
    if role is not None or binding is not None:
        raise BenchmarkError("cluster-owned clone RBAC remains after cleanup")
    golden = kubectl_json_strict_optional(
        management,
        [
            "-n",
            args.golden_namespace,
            "get",
            "persistentvolumeclaim",
            args.golden_claim,
        ],
    )
    if not golden:
        raise BenchmarkError("shared Golden-Image PVC is absent after cleanup")
    metadata = golden.get("metadata", {})
    if metadata.get("uid") != args.golden_uid:
        raise BenchmarkError("Golden-Image PVC UID changed across cleanup")
    if golden.get("status", {}).get("phase") != "Bound":
        raise BenchmarkError("Golden-Image PVC is not Bound after cleanup")
    snapshots = kubectl_json_strict_optional(
        management,
        [
            "-n",
            args.golden_namespace,
            "get",
            "volumesnapshots",
            "-l",
            f"openkubes.io/consumer-cluster={args.cluster}",
        ],
    )
    if snapshots is not None and snapshots.get("items"):
        raise BenchmarkError("cluster-owned CDI snapshots remain after cleanup")
    evidence = {
        "schema": "openkubes.ok128.cleanup-verification/v1",
        "observed_at": utc_now(),
        "cluster": args.cluster,
        "cluster_namespace_absent": True,
        "clone_rbac_absent": True,
        "cluster_owned_snapshots_absent": True,
        "golden_image": {
            "namespace": args.golden_namespace,
            "claim": args.golden_claim,
            "uid": args.golden_uid,
            "phase": "Bound",
            "preserved": True,
        },
    }
    output = Path(args.output_dir).resolve() / f"{args.run_id}-cleanup.json"
    atomic_text(output, json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"PASS OK-128 cleanup evidence: {output}")
    return 0


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser()
    subcommands = main.add_subparsers(dest="action", required=True)
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--os", choices=("flatcar", "talos"), required=True)
    run_parser.add_argument("--cluster", required=True)
    run_parser.add_argument("--management-kubeconfig", required=True)
    run_parser.add_argument("--workload-kubeconfig", required=True)
    run_parser.add_argument("--cilium-chart", required=True)
    run_parser.add_argument("--ok-linux-path", default=ROOT.parent / "ok-linux")
    run_parser.add_argument("--output-dir", default=DEFAULT_EVIDENCE)
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--test-order", type=int, choices=(1, 2), required=True)
    run_parser.add_argument("--post-command-timeout", type=int, default=120)
    run_parser.add_argument("--time-binary", default="/usr/bin/time")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    run_parser.set_defaults(function=run_benchmark)

    preflight = subcommands.add_parser("preflight")
    preflight.add_argument(
        "--os", choices=("flatcar", "talos"), required=True
    )
    preflight.add_argument("--cluster", required=True)
    preflight.add_argument("--management-kubeconfig", required=True)
    preflight.add_argument("--workload-kubeconfig", required=True)
    preflight.add_argument("--cilium-chart", required=True)
    preflight.add_argument("--ok-linux-path", default=ROOT.parent / "ok-linux")
    preflight.set_defaults(function=preflight_command)

    comparison = subcommands.add_parser("compare")
    comparison.add_argument("--flatcar", required=True)
    comparison.add_argument("--talos", required=True)
    comparison.add_argument("--output-dir", default=DEFAULT_EVIDENCE)
    comparison.set_defaults(function=compare_command)

    cleanup = subcommands.add_parser("verify-cleanup")
    cleanup.add_argument("--cluster", required=True)
    cleanup.add_argument("--management-kubeconfig", required=True)
    cleanup.add_argument("--golden-namespace", default="ok-images")
    cleanup.add_argument("--golden-claim", required=True)
    cleanup.add_argument("--golden-uid", required=True)
    cleanup.add_argument("--run-id", required=True)
    cleanup.add_argument("--output-dir", default=DEFAULT_EVIDENCE)
    cleanup.set_defaults(function=verify_cleanup)
    return main


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.function(args)
    except BenchmarkError as error:
        print(f"FAIL OK-128 benchmark: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
