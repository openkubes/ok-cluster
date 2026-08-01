#!/usr/bin/env python3
"""Fail-closed consumer for the ADR-009 Flatcar/KubeVirt profile."""

from __future__ import annotations

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml


PROFILE_RELATIVE_PATH = Path("profiles/flatcar-kubevirt/profile.yaml")
EXPECTED_PROFILE = {
    "name": "flatcar-kubevirt",
    "status": "production-constrained",
    "contract_ref": "ADR-Platform-016",
    "decision_ref": "docs/adr/ADR-009-flatcar-kubevirt-constrained-support.md",
    "distribution": "flatcar",
    "channel": "stable",
    "flatcar_version": "4593.2.4",
    "architecture": "amd64",
    "provider": "kubevirt",
    "kubernetes_version": "v1.34.1",
    "capi_version": "v1.13.3",
    "capk_version": "v0.11.2",
    "kubevirt_version": "v1.8.1",
    "cilium_version": "1.19.6",
    "image_digest": (
        "sha256:49b72cf26d27d4747d6252c64582f17fdbd7d629993beebbcf997794333a978a"
    ),
    "identity": (
        "sha256:afd862491620adbaeb3c25aa82ae89a3bd748ae5976cf66fbf9613a732ba35bb"
    ),
    "profile_revision": 5,
    "golden_namespace": "ok-images",
    "golden_claim": "flatcar-stable-4593-2-4-amd64-kubevirt",
    "golden_target_storage_class": "ok-storage-block",
    "node_selector": "ok-infra",
}
EXPECTED_CONTROL_PLANE = {
    "replicas": 1,
    "cores": 2,
    "memory": "4Gi",
    "disk": "50Gi",
}
EXPECTED_WORKERS = {
    "replicas": 1,
    "cores": 2,
    "memory": "4Gi",
    "disk": "50Gi",
}
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
EXPECTED_CLONE_TARGET = {
    "storage_class": "ok-storage-block",
    "boot_disk_capacity": "50Gi",
    "provisioner": "driver.longhorn.io",
    "access_mode": "ReadWriteOnce",
    "volume_mode": "Filesystem",
    "reclaim_policy": "Retain",
    "volume_binding_mode": "Immediate",
    "allow_volume_expansion": True,
    "kubevirt_feature_gates": ["ExpandDisks"],
}
EXPECTED_DEMO_PROFILES = {
    "gpu-single-replica": {
        "lifecycle": "demonstration-only",
        "high_availability": False,
        "node_selector": "ok-gpu",
        "clone_target": {
            "storage_class": "ok-storage-block-gpu-test",
            "control_plane_boot_disk_capacity": "20Gi",
            "worker_boot_disk_capacity": "30Gi",
            "provisioner": "driver.longhorn.io",
            "replica_count": 1,
            "node_tag": "openkubes-gpu-demo",
            "access_mode": "ReadWriteOnce",
            "volume_mode": "Filesystem",
            "reclaim_policy": "Delete",
            "volume_binding_mode": "Immediate",
            "allow_volume_expansion": True,
            "kubevirt_feature_gates": ["ExpandDisks"],
        },
    }
}


class FlatcarProfileError(ValueError):
    """The selected config is outside the accepted ADR-009 envelope."""


def validate_cluster_name(name: object) -> str:
    value = str(name or "")
    if len(value) > 63 or not DNS_LABEL.fullmatch(value):
        raise FlatcarProfileError(
            "cluster name must be a lowercase Kubernetes DNS label"
        )
    return value


def load_profile(ok_linux_path: Path) -> dict:
    path = ok_linux_path.resolve() / PROFILE_RELATIVE_PATH
    if not path.is_file():
        raise FlatcarProfileError(f"ok-linux profile is absent: {path}")
    with path.open(encoding="utf-8") as stream:
        profile = yaml.safe_load(stream)
    validate_profile(profile)
    return profile


def validate_profile(profile: dict) -> None:
    metadata = profile.get("metadata", {})
    implementation = profile.get("implementation", {})
    support = profile.get("support_envelope", {})
    boot = profile.get("artifacts", {}).get("boot_image", {})
    runtime = boot.get("runtime_distribution", {})
    kubernetes = profile.get("artifacts", {}).get("kubernetes_payload", {})
    identity = profile.get("identity", {})
    bootstrap = profile.get("bootstrap", {})
    lifecycle = profile.get("lifecycle", {})

    observed = {
        "name": metadata.get("name"),
        "status": metadata.get("status"),
        "contract_ref": profile.get("contract_ref"),
        "decision_ref": profile.get("decision_ref"),
        "distribution": implementation.get("distribution"),
        "channel": implementation.get("channel"),
        "flatcar_version": str(implementation.get("version", "")),
        "architecture": implementation.get("architecture"),
        "provider": implementation.get("provider"),
        "kubernetes_version": kubernetes.get("version"),
        "capi_version": support.get("capi_version"),
        "capk_version": support.get("capk_version"),
        "kubevirt_version": support.get("kubevirt_version"),
        "cilium_version": support.get("cilium_version"),
        "image_digest": boot.get("digest"),
        "identity": identity.get("digest"),
        "profile_revision": identity.get("profile_revision"),
        "golden_namespace": runtime.get("namespace"),
        "golden_claim": runtime.get("claim"),
    }
    expected = {
        key: value
        for key, value in EXPECTED_PROFILE.items()
        if key not in {"golden_target_storage_class", "node_selector"}
    }
    if observed != expected:
        raise FlatcarProfileError(
            "ok-linux Flatcar profile does not match the accepted ADR-009 envelope"
        )
    if (
        profile.get("apiVersion") != "ok-linux.openkubes.io/v1alpha1"
        or profile.get("kind") != "OSImplementationProfile"
        or metadata.get("deployable") is not True
        or support.get("decision") != "constrained"
        or support.get("architecture") != "amd64"
        or support.get("provider") != "kubevirt"
        or support.get("runtime_validated_topology")
        != {"control_plane_replicas": 1, "worker_replicas": 1}
        or support.get("clone_target") != EXPECTED_CLONE_TARGET
        or profile.get("demo_profiles") != EXPECTED_DEMO_PROFILES
        or support.get("continuous_control_plane_api_slo") is not False
        or "arm64" not in support.get("exclusions", [])
    ):
        raise FlatcarProfileError(
            "ok-linux Flatcar support metadata is not fail-closed"
        )
    if (
        bootstrap
        != {
            "format": "ignition",
            "dynamic_data_authority": "cabpk-runtime-secret",
            "provider_transport": "capk-config-drive-secret-reference",
            "virtual_machine_bootstrap_check": "none",
            "authorized_keys_allowed": False,
            "inline_secret_values_allowed": False,
        }
        or lifecycle.get("day2_os_change")
        != "node-replacement-from-versioned-input"
        or lifecycle.get("imperative_guest_mutation_allowed") is not False
        or lifecycle.get("ssh_lifecycle_authority") is not False
        or lifecycle.get("in_place_update_authority") is not False
    ):
        raise FlatcarProfileError(
            "ok-linux Flatcar bootstrap/lifecycle boundary is invalid"
        )


def set_exact(mapping: dict, key: str, expected, label: str) -> None:
    if key in mapping and mapping[key] != expected:
        raise FlatcarProfileError(
            f"{label} must be {expected!r}, observed {mapping[key]!r}"
        )
    mapping[key] = copy.deepcopy(expected)


def exact_mapping(mapping: dict, expected: dict, label: str) -> None:
    unknown = set(mapping) - set(expected)
    if unknown:
        raise FlatcarProfileError(
            f"{label} contains unsupported fields: {sorted(unknown)}"
        )
    for key, value in expected.items():
        set_exact(mapping, key, value, f"{label}.{key}")


def resolve_flatcar_config(cfg: dict, ok_linux_path: Path) -> dict:
    """Materialize the production profile and reject every envelope widening."""
    resolved = copy.deepcopy(cfg)
    if resolved.get("type") != "flatcar":
        raise FlatcarProfileError("Flatcar resolver requires type: flatcar")
    validate_cluster_name(resolved.get("name"))
    allowed_top_level = {
        "name",
        "type",
        "provider",
        "controlPlane",
        "workers",
        "versions",
        "network",
        "nodeSelector",
        "providerProfile",
        "demoProfile",
        "os",
        "bootstrap",
        "upgrade",
    }
    unknown_top_level = set(resolved) - allowed_top_level
    if unknown_top_level:
        raise FlatcarProfileError(
            "Flatcar config contains unsupported fields: "
            f"{sorted(unknown_top_level)}"
        )

    profile = load_profile(ok_linux_path)
    implementation = profile["implementation"]
    boot = profile["artifacts"]["boot_image"]
    kubernetes = profile["artifacts"]["kubernetes_payload"]
    runtime = boot["runtime_distribution"]
    identity = profile["identity"]
    demo_name = resolved.get("demoProfile")
    if demo_name is not None and demo_name not in EXPECTED_DEMO_PROFILES:
        raise FlatcarProfileError(f"unsupported Flatcar demoProfile: {demo_name!r}")
    demo = EXPECTED_DEMO_PROFILES.get(demo_name)

    set_exact(
        resolved,
        "provider",
        EXPECTED_PROFILE["provider"],
        "provider",
    )
    versions = resolved.setdefault("versions", {})
    exact_mapping(
        versions,
        {"kubernetes": EXPECTED_PROFILE["kubernetes_version"]},
        "versions",
    )
    expected_control_plane = copy.deepcopy(EXPECTED_CONTROL_PLANE)
    expected_workers = copy.deepcopy(EXPECTED_WORKERS)
    if demo:
        expected_control_plane["disk"] = demo["clone_target"][
            "control_plane_boot_disk_capacity"
        ]
        expected_workers["disk"] = demo["clone_target"][
            "worker_boot_disk_capacity"
        ]
    control_plane = resolved.setdefault("controlPlane", {})
    exact_mapping(control_plane, expected_control_plane, "controlPlane")
    workers = resolved.setdefault("workers", {})
    exact_mapping(workers, expected_workers, "workers")
    set_exact(
        resolved,
        "nodeSelector",
        demo["node_selector"] if demo else EXPECTED_PROFILE["node_selector"],
        "nodeSelector",
    )
    provider_profile = resolved.setdefault("providerProfile", {})
    expected_provider_profile = {
        "goldenImageStorageClass": EXPECTED_PROFILE[
            "golden_target_storage_class"
        ]
    }
    if demo:
        expected_provider_profile["cloneTargetStorageClass"] = demo[
            "clone_target"
        ]["storage_class"]
    exact_mapping(
        provider_profile,
        expected_provider_profile,
        "providerProfile",
    )

    expected_os = {
        "contractRef": profile["contract_ref"],
        "distribution": implementation["distribution"],
        "profile": profile["metadata"]["name"],
        "version": str(implementation["version"]),
        "architecture": implementation["architecture"],
        "imageDigest": boot["digest"],
        "identity": identity["digest"],
        "profileRevision": identity["profile_revision"],
        "status": profile["metadata"]["status"],
        "deployable": profile["metadata"]["deployable"],
        "supportDecision": profile["decision_ref"],
        "goldenImage": {
            "namespace": runtime["namespace"],
            "claim": runtime["claim"],
            "published": runtime["published"],
            "storageClass": provider_profile["goldenImageStorageClass"],
        },
    }
    os_config = resolved.setdefault("os", {})
    exact_mapping(os_config, expected_os, "os")

    expected_bootstrap = {
        "format": profile["bootstrap"]["format"],
        "virtualMachineBootstrapCheck": profile["bootstrap"][
            "virtual_machine_bootstrap_check"
        ],
    }
    bootstrap = resolved.setdefault("bootstrap", {})
    exact_mapping(bootstrap, expected_bootstrap, "bootstrap")

    upgrade = resolved.setdefault("upgrade", {})
    exact_mapping(
        upgrade,
        {
            "strategy": "blue-green",
            "workloadMigration": {
                "stateless": "gitops",
                "stateful": "app-native",
            },
        },
        "upgrade",
    )
    return resolved


def preflight_new(args: argparse.Namespace) -> int:
    cfg = {
        "name": args.cluster,
        "type": "flatcar",
        "provider": args.provider,
        "controlPlane": {
            "replicas": args.control_plane_replicas,
            "cores": args.control_plane_cores,
            "memory": args.control_plane_memory,
            "disk": args.control_plane_disk,
        },
        "workers": {
            "replicas": args.worker_replicas,
            "cores": args.worker_cores,
            "memory": args.worker_memory,
            "disk": args.worker_disk,
        },
        "versions": {"kubernetes": args.kubernetes_version},
        "nodeSelector": args.node_selector,
        "providerProfile": {
            "goldenImageStorageClass": args.golden_image_storage_class
        },
        "os": {"architecture": args.architecture},
    }
    if args.demo_profile:
        cfg["demoProfile"] = args.demo_profile
        cfg["providerProfile"]["cloneTargetStorageClass"] = (
            "ok-storage-block-gpu-test"
        )
    resolve_flatcar_config(cfg, Path(args.ok_linux_path))
    print("PASS Flatcar scaffold matches the exact ADR-009 envelope")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight-new")
    preflight.add_argument("--ok-linux-path", required=True)
    preflight.add_argument("--cluster", required=True)
    preflight.add_argument("--provider", required=True)
    preflight.add_argument("--architecture", required=True)
    preflight.add_argument("--kubernetes-version", required=True)
    preflight.add_argument("--control-plane-replicas", type=int, required=True)
    preflight.add_argument("--control-plane-cores", type=int, required=True)
    preflight.add_argument("--control-plane-memory", required=True)
    preflight.add_argument("--control-plane-disk", required=True)
    preflight.add_argument("--worker-replicas", type=int, required=True)
    preflight.add_argument("--worker-cores", type=int, required=True)
    preflight.add_argument("--worker-memory", required=True)
    preflight.add_argument("--worker-disk", required=True)
    preflight.add_argument("--node-selector", required=True)
    preflight.add_argument("--golden-image-storage-class", required=True)
    preflight.add_argument("--demo-profile", default="")
    preflight.set_defaults(func=preflight_new)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FlatcarProfileError, OSError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
