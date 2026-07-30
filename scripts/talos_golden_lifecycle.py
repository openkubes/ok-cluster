#!/usr/bin/env python3
"""Guard the OK-130 Talos Golden-Image consumer lifecycle."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "adoption" / "OK-130" / ".evidence"
sys.path.insert(0, str(ROOT))

from profile_resolvers.talos import (  # noqa: E402
    TalosProfileError,
    resolve_talos_config,
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


def runtime_evidence(args: argparse.Namespace) -> int:
    """Record a read-only warm-provisioning result, separate from publication."""
    config, manifest, kubeconfig = inputs(args)
    validate_manifest(config, manifest)
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
    evidence = {
        "schema_version": 1,
        "suite": "OK-130-talos-golden-image",
        "status": "PASS",
        "mode": "warm-provisioning",
        "cluster": cluster_name,
        "identity": config["os"]["identity"],
        "golden": golden,
        "started_at": started_at,
        "ready_at": ready_at,
        "duration_seconds": round(duration, 3),
        "boot_data_volumes": len(data_volumes),
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
        f"golden_uid={golden['uid']}"
    )
    return 0


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
    after = verify_golden(config, kubeconfig)
    if after != before:
        raise TalosLifecycleError("shared Talos Golden PVC changed on cleanup")
    print(
        f"PASS removed {golden_namespace}/{authorization}; "
        f"preserved golden_uid={after['uid']}"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--runtime-evidence", action="store_true")
    mode.add_argument("--cleanup-authorization", action="store_true")
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--ok-linux-path", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.preflight:
        return preflight(args)
    if args.runtime_evidence:
        return runtime_evidence(args)
    return cleanup_authorization(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
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
