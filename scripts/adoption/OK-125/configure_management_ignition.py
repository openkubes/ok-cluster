#!/usr/bin/env python3
"""Render and reconcile the pinned CABPK/KCP Ignition feature gate.

The ordinary management bootstrap exports the same gate for new installations.
This bounded reconciler exists for an already-installed v1.13.3 provider pair.
It reads no Secret and changes only the feature-gates argument after an atomic
JSON Patch test has proved the complete old value.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs" / "adoption" / "OK-125" / ".evidence"
CAPI_VERSION = "v1.13.3"
CAPK_VERSION = "v0.11.2"
FEATURE_ENV = "EXP_KUBEADM_BOOTSTRAP_FORMAT_IGNITION"
APPLY_ENV = "OK125_APPLY"

PROVIDERS = (
    {
        "role": "bootstrap",
        "flag": "--bootstrap",
        "inventory_namespace": "capi-kubeadm-bootstrap-system",
        "inventory_name": "bootstrap-kubeadm",
        "inventory_type": "BootstrapProvider",
        "deployment_namespace": "capi-kubeadm-bootstrap-system",
        "deployment_name": "capi-kubeadm-bootstrap-controller-manager",
        "image": (
            "registry.k8s.io/cluster-api/"
            "kubeadm-bootstrap-controller:v1.13.3"
        ),
        "feature_false": (
            "--feature-gates=MachinePool=true,"
            "KubeadmBootstrapFormatIgnition=false,"
            "PriorityQueue=true,ReconcilerRateLimiting=true"
        ),
        "feature_true": (
            "--feature-gates=MachinePool=true,"
            "KubeadmBootstrapFormatIgnition=true,"
            "PriorityQueue=true,ReconcilerRateLimiting=true"
        ),
    },
    {
        "role": "control-plane",
        "flag": "--control-plane",
        "inventory_namespace": "capi-kubeadm-control-plane-system",
        "inventory_name": "control-plane-kubeadm",
        "inventory_type": "ControlPlaneProvider",
        "deployment_namespace": "capi-kubeadm-control-plane-system",
        "deployment_name": "capi-kubeadm-control-plane-controller-manager",
        "image": (
            "registry.k8s.io/cluster-api/"
            "kubeadm-control-plane-controller:v1.13.3"
        ),
        "feature_false": (
            "--feature-gates=MachinePool=true,ClusterTopology=false,"
            "KubeadmBootstrapFormatIgnition=false,"
            "PriorityQueue=true,ReconcilerRateLimiting=true,"
            "InPlaceUpdates=false,MachineTaintPropagation=false"
        ),
        "feature_true": (
            "--feature-gates=MachinePool=true,ClusterTopology=false,"
            "KubeadmBootstrapFormatIgnition=true,"
            "PriorityQueue=true,ReconcilerRateLimiting=true,"
            "InPlaceUpdates=false,MachineTaintPropagation=false"
        ),
    },
)

REQUIRED_INVENTORY = {
    ("capi-system", "cluster-api", "CoreProvider"): CAPI_VERSION,
    (
        "capi-kubeadm-bootstrap-system",
        "bootstrap-kubeadm",
        "BootstrapProvider",
    ): CAPI_VERSION,
    (
        "capi-kubeadm-control-plane-system",
        "control-plane-kubeadm",
        "ControlPlaneProvider",
    ): CAPI_VERSION,
    (
        "capk-system",
        "infrastructure-kubevirt",
        "InfrastructureProvider",
    ): CAPK_VERSION,
}


class ValidationError(RuntimeError):
    """The guarded management reconciliation cannot proceed."""


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    expected: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in expected:
        detail = (result.stderr or result.stdout).strip()
        raise ValidationError(
            f"{' '.join(command[:3])} exited {result.returncode}: {detail}"
        )
    return result


def require_tool(value: str) -> str:
    resolved = shutil.which(value) if "/" not in value else value
    if not resolved or not Path(resolved).is_file():
        raise ValidationError(f"required executable not found: {value}")
    return str(Path(resolved).resolve())


def source_state() -> dict[str, object]:
    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "status", "--porcelain"]).stdout.strip())
    contained = bool(
        run(["git", "branch", "-r", "--contains", "HEAD"]).stdout.strip()
    )
    return {"commit": commit, "clean": not dirty, "pushed": contained}


def clusterctl_version(clusterctl: str) -> str:
    output = run([clusterctl, "version"]).stdout
    match = re.search(r'GitVersion:"([^"]+)"', output)
    if not match:
        raise ValidationError("cannot parse clusterctl version")
    version = match.group(1)
    if version != CAPI_VERSION:
        raise ValidationError(
            f"clusterctl must be {CAPI_VERSION}, observed {version}; "
            "set CLUSTERCTL_BIN to the pinned binary"
        )
    return version


def kubectl_json(kubectl: str, kubeconfig: Path, args: list[str]):
    command = [kubectl, "--kubeconfig", str(kubeconfig), *args, "-o", "json"]
    return json.loads(run(command).stdout)


def validate_inventory(items: list[dict]) -> list[dict[str, str]]:
    observed: dict[tuple[str, str, str], str] = {}
    evidence: list[dict[str, str]] = []
    for item in items:
        metadata = item["metadata"]
        key = (metadata["namespace"], metadata["name"], item["type"])
        observed[key] = item["version"]
    for key, version in REQUIRED_INVENTORY.items():
        actual = observed.get(key)
        if actual != version:
            raise ValidationError(
                f"provider {key[0]}/{key[1]} must be {version}, "
                f"observed {actual or 'absent'}"
            )
        evidence.append(
            {
                "namespace": key[0],
                "name": key[1],
                "type": key[2],
                "version": actual,
            }
        )
    return evidence


def generated_deployment(clusterctl: str, provider: dict) -> dict:
    environment = os.environ.copy()
    environment[FEATURE_ENV] = "true"
    output = run(
        [
            clusterctl,
            "generate",
            "provider",
            provider["flag"],
            f"kubeadm:{CAPI_VERSION}",
        ],
        env=environment,
    ).stdout
    documents = [item for item in yaml.safe_load_all(output) if item]
    matches = [
        item
        for item in documents
        if item.get("kind") == "Deployment"
        and item.get("metadata", {}).get("namespace")
        == provider["deployment_namespace"]
        and item.get("metadata", {}).get("name")
        == provider["deployment_name"]
    ]
    if len(matches) != 1:
        raise ValidationError(
            f"expected one rendered {provider['role']} Deployment, "
            f"observed {len(matches)}"
        )
    deployment = matches[0]
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    if container["name"] != "manager" or container["image"] != provider["image"]:
        raise ValidationError(
            f"unexpected rendered {provider['role']} manager identity"
        )
    feature_args = [
        value
        for value in container["args"]
        if value.startswith("--feature-gates=")
    ]
    if feature_args != [provider["feature_true"]]:
        raise ValidationError(
            f"rendered {provider['role']} feature gate differs from the "
            f"pinned {CAPI_VERSION} expectation"
        )
    return deployment


def live_manager(deployment: dict, provider: dict) -> tuple[list[str], int]:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1:
        raise ValidationError(
            f"{provider['role']} Deployment must have exactly one container"
        )
    container = containers[0]
    if container["name"] != "manager" or container["image"] != provider["image"]:
        raise ValidationError(
            f"live {provider['role']} manager identity/version drifted"
        )
    args = container["args"]
    indices = [
        index
        for index, value in enumerate(args)
        if value.startswith("--feature-gates=")
    ]
    if len(indices) != 1:
        raise ValidationError(
            f"live {provider['role']} manager must have one feature-gates arg"
        )
    current = args[indices[0]]
    if current not in (provider["feature_false"], provider["feature_true"]):
        raise ValidationError(
            f"live {provider['role']} feature-gates argument has unexpected drift"
        )
    return args, indices[0]


def build_patch(provider: dict, current: str, arg_index: int) -> list[dict]:
    return [
        {
            "op": "test",
            "path": "/spec/template/spec/containers/0/name",
            "value": "manager",
        },
        {
            "op": "test",
            "path": f"/spec/template/spec/containers/0/args/{arg_index}",
            "value": current,
        },
        {
            "op": "replace",
            "path": f"/spec/template/spec/containers/0/args/{arg_index}",
            "value": provider["feature_true"],
        },
    ]


def self_test() -> None:
    for provider in PROVIDERS:
        patch = build_patch(provider, provider["feature_false"], 3)
        assert patch[1]["value"] == provider["feature_false"]
        assert patch[2]["value"] == provider["feature_true"]
        assert "KubeadmBootstrapFormatIgnition=true" in patch[2]["value"]
        assert "KubeadmBootstrapFormatIgnition=false" not in patch[2]["value"]
    fixture = [
        {
            "metadata": {"namespace": namespace, "name": name},
            "type": provider_type,
            "version": version,
        }
        for (namespace, name, provider_type), version
        in REQUIRED_INVENTORY.items()
    ]
    assert len(validate_inventory(fixture)) == len(REQUIRED_INVENTORY)
    print("PASS management Ignition patch is atomic and bounded")


def write_evidence(result: dict) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "management-ignition.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    apply = os.environ.get(APPLY_ENV, "no")
    if apply not in ("no", "yes"):
        raise ValidationError(f"{APPLY_ENV} must be 'no' or 'yes'")
    kubeconfig_value = os.environ.get("OK125_KUBECONFIG", "")
    if not kubeconfig_value:
        raise ValidationError("OK125_KUBECONFIG must be an explicit path")
    kubeconfig = Path(kubeconfig_value).expanduser().resolve()
    if not kubeconfig.is_file():
        raise ValidationError(f"kubeconfig does not exist: {kubeconfig}")

    kubectl = require_tool(os.environ.get("KUBECTL_BIN", "kubectl"))
    clusterctl = require_tool(os.environ.get("CLUSTERCTL_BIN", "clusterctl"))
    version = clusterctl_version(clusterctl)
    source = source_state()
    if apply == "yes" and (not source["clean"] or not source["pushed"]):
        raise ValidationError(
            "apply requires a clean ok-cluster commit present on an origin branch"
        )

    server = run(
        [
            kubectl,
            "--kubeconfig",
            str(kubeconfig),
            "config",
            "view",
            "--minify",
            "-o",
            "jsonpath={.clusters[0].cluster.server}",
        ]
    ).stdout
    if not server.startswith("https://"):
        raise ValidationError("management API endpoint must use HTTPS")

    inventory = kubectl_json(
        kubectl,
        kubeconfig,
        ["get", "providers.clusterctl.cluster.x-k8s.io", "-A"],
    )
    inventory_evidence = validate_inventory(inventory["items"])
    controller_evidence: list[dict[str, object]] = []
    EVIDENCE.mkdir(parents=True, exist_ok=True)

    for provider in PROVIDERS:
        desired = generated_deployment(clusterctl, provider)
        desired_path = EVIDENCE / f"{provider['role']}-deployment.yaml"
        desired_path.write_text(
            yaml.safe_dump(desired, sort_keys=False),
            encoding="utf-8",
        )
        live = kubectl_json(
            kubectl,
            kubeconfig,
            [
                "-n",
                provider["deployment_namespace"],
                "get",
                "deployment",
                provider["deployment_name"],
            ],
        )
        args, arg_index = live_manager(live, provider)
        current = args[arg_index]
        patch = build_patch(provider, current, arg_index)
        patch_path = EVIDENCE / f"{provider['role']}-patch.json"
        patch_path.write_text(
            json.dumps(patch, indent=2) + "\n",
            encoding="utf-8",
        )

        patch_command = [
            kubectl,
            "--kubeconfig",
            str(kubeconfig),
            "-n",
            provider["deployment_namespace"],
            "patch",
            "deployment",
            provider["deployment_name"],
            "--type=json",
            f"--patch-file={patch_path}",
        ]
        changed = current != provider["feature_true"]
        if changed:
            run([*patch_command, "--dry-run=server", "-o", "name"])
            if apply == "yes":
                run(patch_command)
                run(
                    [
                        kubectl,
                        "--kubeconfig",
                        str(kubeconfig),
                        "-n",
                        provider["deployment_namespace"],
                        "rollout",
                        "status",
                        f"deployment/{provider['deployment_name']}",
                        "--timeout=180s",
                    ]
                )

        observed = kubectl_json(
            kubectl,
            kubeconfig,
            [
                "-n",
                provider["deployment_namespace"],
                "get",
                "deployment",
                provider["deployment_name"],
            ],
        )
        observed_args, observed_index = live_manager(observed, provider)
        enabled = observed_args[observed_index] == provider["feature_true"]
        expected_enabled = apply == "yes" or not changed
        if enabled != expected_enabled:
            raise ValidationError(
                f"{provider['role']} postcondition does not match apply mode"
            )
        controller_evidence.append(
            {
                "role": provider["role"],
                "namespace": provider["deployment_namespace"],
                "deployment": provider["deployment_name"],
                "image": provider["image"],
                "rendered_gate_enabled": True,
                "observed_gate_enabled": enabled,
                "change_required": changed,
                "server_dry_run": "PASS" if changed else "NOT_REQUIRED",
                "applied": apply == "yes" and changed,
            }
        )

    result = {
        "schema_version": 1,
        "suite": "OK-125-management-ignition",
        "status": "PASS" if apply == "yes" else "PREFLIGHT",
        "scope": "management-controller-feature-gate-not-runtime-adoption",
        "management_api": server,
        "source": source,
        "clusterctl_version": version,
        "provider_inventory": inventory_evidence,
        "controllers": controller_evidence,
        "runtime_gates": {
            "G1_kubernetes_node_ready": "NOT_TESTED",
            "G3_provider_scoped_bootstrap_secret": "NOT_TESTED",
        },
    }
    write_evidence(result)
    if apply == "yes":
        print("PASS CABPK and KCP Ignition feature gates are enabled")
    else:
        print(
            "PREFLIGHT rendered and server-dry-run checked; "
            "set OK125_APPLY=yes after review"
        )
    print(f"Evidence: {EVIDENCE.relative_to(ROOT)}/management-ignition.json")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        yaml.YAMLError,
        ValidationError,
    ) as error:
        write_evidence(
            {
                "schema_version": 1,
                "suite": "OK-125-management-ignition",
                "status": "FAIL",
                "detail": str(error),
            }
        )
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
