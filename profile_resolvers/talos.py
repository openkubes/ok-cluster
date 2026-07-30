#!/usr/bin/env python3
"""Resolve the Talos KubeVirt Golden-Image identity from ok-linux."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import yaml


PROFILE_RELATIVE_PATH = Path("profiles/kubevirt/profile.yaml")


class TalosProfileError(ValueError):
    """Talos KubeVirt input is not represented by the owning ok-linux profile."""


def load_profile(ok_linux_path: Path) -> dict:
    path = ok_linux_path.resolve() / PROFILE_RELATIVE_PATH
    if not path.is_file():
        raise TalosProfileError(f"ok-linux Talos profile is absent: {path}")
    with path.open(encoding="utf-8") as stream:
        profile = yaml.safe_load(stream)
    if not isinstance(profile, dict):
        raise TalosProfileError("ok-linux Talos profile is not a mapping")
    return profile


def identity_material(talos: dict, artifact: dict) -> str:
    return "|".join(
        (
            "talos",
            str(talos["version"]),
            str(talos["schematic_id"]),
            str(artifact["architecture"]),
            str(artifact["filename"]),
            f"sha256:{artifact['sha256']}",
        )
    )


def golden_claim(talos: dict, artifact: dict) -> str:
    version = str(talos["version"]).lower().replace(".", "-")
    return (
        f"talos-{version}-{str(talos['schematic_id'])[:12]}-"
        f"{str(artifact['sha256'])[:12]}-{artifact['architecture']}"
    )


def resolve_talos_config(cfg: dict, ok_linux_path: Path) -> dict:
    """Materialize only provider-consumer data for the KubeVirt Talos path."""
    resolved = copy.deepcopy(cfg)
    if resolved.get("type") != "talos":
        raise TalosProfileError("Talos resolver requires type: talos")
    if resolved.get("provider", "kubevirt") != "kubevirt":
        return resolved

    profile = load_profile(ok_linux_path)
    talos = profile.get("talos", {})
    artifact = talos.get("boot_artifact", {})
    golden = artifact.get("golden_image", {})
    required = (
        "version",
        "schematic_id",
    )
    if any(not talos.get(key) for key in required):
        raise TalosProfileError("ok-linux Talos version/schematic is incomplete")
    if (
        artifact.get("architecture") != "amd64"
        or artifact.get("platform") != "openstack"
        or artifact.get("format") != "qcow2"
        or artifact.get("filename") != "openstack-amd64.qcow2"
        or not artifact.get("sha256")
        or not artifact.get("identity")
        or golden.get("namespace") != "ok-images"
        or golden.get("storage_class") != "ok-storage-block"
    ):
        raise TalosProfileError(
            "ok-linux Talos boot artifact is outside the OK-130 boundary"
        )
    expected_url = (
        "https://factory.talos.dev/image/"
        f"{talos['schematic_id']}/{talos['version']}/"
        "openstack-amd64.qcow2"
    )
    if artifact.get("url") != expected_url:
        raise TalosProfileError("Talos artifact URL is not canonical")
    if golden.get("claim") != golden_claim(talos, artifact):
        raise TalosProfileError(
            "Talos Golden PVC name does not encode its immutable identity"
        )
    identity = "sha256:" + hashlib.sha256(
        identity_material(talos, artifact).encode()
    ).hexdigest()
    if identity != artifact["identity"]:
        raise TalosProfileError("Talos artifact identity is invalid")

    versions = resolved.setdefault("versions", {})
    if versions.get("talos", talos["version"]) != talos["version"]:
        raise TalosProfileError(
            "versions.talos has no reviewed Golden-Image identity"
        )
    versions["talos"] = talos["version"]
    os_cfg = resolved.setdefault("os", {})
    if os_cfg.get("profile", "kubevirt") != "kubevirt":
        raise TalosProfileError("only the kubevirt Talos profile is supported")
    if (
        os_cfg.get("schematic_id", talos["schematic_id"])
        != talos["schematic_id"]
    ):
        raise TalosProfileError(
            "os.schematic_id has no reviewed Golden-Image identity"
        )
    os_cfg.update(
        {
            "distribution": "ok-linux",
            "profile": "kubevirt",
            "schematic_id": talos["schematic_id"],
            "architecture": artifact["architecture"],
            "imageDigest": f"sha256:{artifact['sha256']}",
            "identity": artifact["identity"],
            "goldenImage": {
                "namespace": golden["namespace"],
                "claim": golden["claim"],
                "published": True,
                "storageClass": golden["storage_class"],
            },
        }
    )
    return resolved
