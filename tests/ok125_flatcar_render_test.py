#!/usr/bin/env python3
"""Deterministic, render-only evidence for the gated OK-125 Flatcar profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import render as renderer  # noqa: E402


FIXTURE = ROOT / "tests" / "fixtures" / "ok125-flatcar" / "cluster-config.yaml"
EVIDENCE = ROOT / "docs" / "adoption" / "OK-125" / ".evidence"
EXPECTED_CLUSTER = "ok125-flatcar"
CHECKS: list[dict[str, str]] = []


def check(condition: bool, message: str) -> None:
    status = "PASS" if condition else "FAIL"
    CHECKS.append({"check": message, "status": status})
    print(f"{status} {message}", file=sys.stdout if condition else sys.stderr)


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def materialize_config(candidate: dict, fixture: dict) -> dict:
    implementation = candidate["implementation"]
    boot = candidate["artifacts"]["boot_image"]
    kubernetes = candidate["artifacts"]["kubernetes_payload"]
    bootstrap = candidate["bootstrap"]
    provider_profile = fixture["providerProfile"]

    cfg = dict(fixture)
    cfg.pop("providerProfile")
    cfg["versions"] = {"kubernetes": kubernetes["version"]}
    cfg["os"] = {
        "contractRef": candidate["contract_ref"],
        "distribution": implementation["distribution"],
        "profile": candidate["metadata"]["name"],
        "version": str(implementation["version"]),
        "architecture": implementation["architecture"],
        "imageDigest": boot["digest"],
        "identity": candidate["identity"]["digest"],
        "candidateStatus": candidate["metadata"]["status"],
        "deployable": candidate["metadata"]["deployable"],
        "goldenImage": {
            "namespace": boot["runtime_distribution"]["namespace"],
            "claim": boot["runtime_distribution"]["claim"],
            "published": boot["runtime_distribution"]["published"],
            "storageClass": provider_profile["goldenImageStorageClass"],
        },
    }
    cfg["bootstrap"] = {
        "format": bootstrap["format"],
        "virtualMachineBootstrapCheck": bootstrap[
            "virtual_machine_bootstrap_check"
        ],
    }
    return cfg


def directory_bytes(path: Path) -> dict[str, bytes]:
    return {
        str(item.relative_to(path)): item.read_bytes()
        for item in sorted(path.rglob("*"))
        if item.is_file()
    }


def objects(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [doc for doc in yaml.safe_load_all(stream) if doc]


def by_kind(docs: list[dict], kind: str) -> list[dict]:
    return [doc for doc in docs if doc.get("kind") == kind]


def nested_values(value, key: str):
    if isinstance(value, dict):
        for child_key, child in value.items():
            if child_key == key:
                yield child
            yield from nested_values(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from nested_values(child, key)


def validate_manifest(manifest: Path, cfg: dict) -> None:
    docs = objects(manifest)
    kinds = [doc["kind"] for doc in docs]
    check(
        kinds
        == [
            "Namespace",
            "Role",
            "RoleBinding",
            "Cluster",
            "KubevirtCluster",
            "KubevirtMachineTemplate",
            "KubeadmControlPlane",
            "KubevirtMachineTemplate",
            "KubeadmConfigTemplate",
            "MachineDeployment",
        ],
        "render contains the bounded CAPI/CAPK object set",
    )
    clone_role = by_kind(docs, "Role")[0]
    clone_binding = by_kind(docs, "RoleBinding")[0]
    check(
        clone_role["metadata"]["namespace"]
        == cfg["os"]["goldenImage"]["namespace"]
        and clone_role["rules"]
        == [
            {
                "apiGroups": ["cdi.kubevirt.io"],
                "resources": ["datavolumes/source"],
                "verbs": ["create"],
            }
        ],
        "CDI clone authority is limited to the golden-image namespace",
    )
    check(
        clone_binding["subjects"]
        == [
            {
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": EXPECTED_CLUSTER,
            }
        ]
        and clone_binding["roleRef"]["kind"] == "Role",
        "CDI clone authority binds only the disposable consumer identity",
    )

    identity = cfg["os"]["identity"]
    identity_short = identity.removeprefix("sha256:")[:12]
    machine_templates = by_kind(docs, "KubevirtMachineTemplate")
    check(
        len(machine_templates) == 2
        and all(
            template["metadata"]["name"].endswith(identity_short)
            for template in machine_templates
        ),
        "immutable machine template names include the OS identity",
    )
    check(
        all(
            template["spec"]["template"]["spec"][
                "virtualMachineBootstrapCheck"
            ]["checkStrategy"]
            == "none"
            for template in machine_templates
        ),
        "CAPK bootstrap readiness does not depend on SSH",
    )

    expected_source = {
        "namespace": cfg["os"]["goldenImage"]["namespace"],
        "name": cfg["os"]["goldenImage"]["claim"],
    }
    pvc_sources = list(nested_values(docs, "pvc"))
    check(
        len(pvc_sources) == 2
        and all(source == expected_source for source in pvc_sources),
        "both VM roles clone the platform-owned golden PVC",
    )

    control_plane = by_kind(docs, "KubeadmControlPlane")[0]
    worker = by_kind(docs, "KubeadmConfigTemplate")[0]
    bootstrap_specs = [
        control_plane["spec"]["kubeadmConfigSpec"],
        worker["spec"]["template"]["spec"],
    ]
    additional_configs = [
        spec["ignition"]["containerLinuxConfig"]["additionalConfig"]
        for spec in bootstrap_specs
    ]
    check(
        all(spec["format"] == "ignition" for spec in bootstrap_specs),
        "control-plane and worker bootstrap use Ignition",
    )
    check(
        all(
            "kubeadm.service" in config
            and "Requires=containerd.service" in config
            and "Wants=kubelet.service" in config
            and "Requires=containerd.service kubelet.service" not in config
            and "OnFailure=ok125-kubeadm-failure.service" in config
            and (
                "Environment=PATH=/opt/bin:/usr/local/sbin:"
                "/usr/local/bin:/usr/sbin:/usr/bin"
            )
            in config
            and "TimeoutStartSec=0" in config
            and "StandardError=journal+console" in config
            and "OK125_KUBEADM_SUCCEEDED" in config
            and "name: ok125-kubeadm-failure.service" in config
            and "--property=ExecMainStatus" in config
            and "journalctl -u kubeadm.service" in config
            and "error execution phase" in config
            and "grep -Eiv" in config
            and "private[ -]?key" in config
            and "\\[" not in config
            and "StandardOutput=journal+console" not in config
            for config in additional_configs
        ),
        (
            "kubeadm has an unbounded first boot and failure-only, "
            "redacted serial diagnostics"
        ),
    )
    check(
        all(
            "name: kubelet.service" in config
            and "ExecStart=/opt/bin/kubelet" in config
            and (
                'Environment="KUBELET_KUBECONFIG_ARGS='
                "--bootstrap-kubeconfig=/etc/kubernetes/"
                "bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/"
                'kubelet.conf"'
            )
            in config
            and "EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env"
            in config
            and "Restart=always" in config
            for config in additional_configs
        ),
        "control-plane and worker declare the Flatcar kubelet service",
    )

    rendered_text = manifest.read_text(encoding="utf-8")
    forbidden = (
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
    check(
        "${" not in rendered_text
        and not any(term in rendered_text for term in forbidden),
        "render contains no inline secret, public artifact, or remote-shell input",
    )
    check(
        not list(nested_values(docs, "users")),
        "render contains no bootstrap user or authorized key",
    )

    labelled = [
        doc
        for doc in docs
        if doc.get("kind") != "Namespace"
        and "labels" in doc.get("metadata", {})
    ]
    check(
        labelled
        and all(
            doc["metadata"]["labels"].get("openkubes.io/deployable") == "false"
            and doc["metadata"]["labels"].get("openkubes.io/adoption-status")
            == "adoption-gated"
            for doc in labelled
        ),
        "every candidate lifecycle object remains visibly non-deployable",
    )
    namespace = by_kind(docs, "Namespace")[0]
    check(
        namespace["metadata"]["annotations"]["openkubes.io/golden-image-published"]
        == "true",
        "render consumes the recorded platform-owned golden image",
    )

    cluster = by_kind(docs, "Cluster")[0]
    check(
        cluster["spec"]["infrastructureRef"]["kind"] == "KubevirtCluster"
        and cluster["metadata"]["labels"]["openkubes.io/provider"] == "kubevirt",
        "provider label is derived consistently from the KubeVirt profile",
    )
    infrastructure = by_kind(docs, "KubevirtCluster")[0]
    check(
        infrastructure["spec"]["controlPlaneServiceTemplate"]["metadata"][
            "annotations"
        ]["metallb.universe.tf/loadBalancerIPs"]
        == cfg["network"]["endpoint"],
        "KubeVirt API endpoint uses the proven MetalLB address annotation",
    )
    check(
        control_plane["spec"]["kubeadmConfigSpec"]["initConfiguration"][
            "skipPhases"
        ]
        == ["addon/kube-proxy"],
        "Flatcar Cilium profile owns service routing without kube-proxy",
    )
    machine_deployment = by_kind(docs, "MachineDeployment")[0]
    check(
        machine_deployment["spec"]["template"]["spec"]["infrastructureRef"][
            "name"
        ].endswith(identity_short),
        "worker lifecycle references the identity-bound infrastructure template",
    )


def validate_cilium_profile(path: Path, cfg: dict) -> None:
    values = load_yaml(path)
    check(
        values["k8sServiceHost"] == cfg["network"]["endpoint"]
        and values["k8sServicePort"] == 6443,
        "Flatcar Cilium profile uses the declared KubeVirt API endpoint",
    )
    check(
        values["ipam"]["mode"] == "kubernetes"
        and values["kubeProxyReplacement"] is True
        and values["routingMode"] == "tunnel"
        and values["tunnelProtocol"] == "vxlan",
        "Flatcar Cilium networking is explicit and profile-scoped",
    )
    check(
        values["cgroup"]["autoMount"]["enabled"] is True
        and values["cgroup"]["hostRoot"] == "/sys/fs/cgroup",
        "Flatcar Cilium cgroup handling does not inherit Talos settings",
    )


def validate_ordinary_path_is_closed() -> None:
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-s",
            "require-type",
            f"CLUSTER={EXPECTED_CLUSTER}",
            "TYPE=flatcar",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode != 0 and "not one of" in (result.stdout + result.stderr),
        "ordinary make new type allowlist still rejects Flatcar",
    )


def validate_source_profile(ok_linux: Path) -> None:
    result = subprocess.run(
        ["make", "--no-print-directory", "-s", "ok125-static"],
        cwd=ok_linux,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0,
        "ok-linux source profile passes its owning offline validator",
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise ValueError(f"ok-linux ok125-static failed:\n{detail}")


def write_result(status: str, digest: str, files: list[str]) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1,
        "suite": "OK-125-render",
        "status": status,
        "scope": "offline-render-only-not-runtime-adoption",
        "cluster": EXPECTED_CLUSTER,
        "manifest_digest": digest,
        "files": files,
        "checks": CHECKS,
    }
    (EVIDENCE / "render.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", default=EXPECTED_CLUSTER)
    args = parser.parse_args()
    if args.cluster != EXPECTED_CLUSTER:
        raise SystemExit(
            f"ERROR: OK-125 render is bounded to CLUSTER={EXPECTED_CLUSTER}"
        )

    ok_linux = Path(
        os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux")
    ).resolve()
    candidate_path = (
        ok_linux
        / "docs"
        / "adoption"
        / "OK-125"
        / "flatcar-kubevirt-candidate.yaml"
    )
    validate_source_profile(ok_linux)
    candidate = load_yaml(candidate_path)
    fixture = load_yaml(FIXTURE)

    check(
        candidate["metadata"]["deployable"] is False
        and candidate["metadata"]["status"] == "adoption-gated",
        "ok-linux source profile is still adoption-gated",
    )
    check(
        candidate["artifacts"]["boot_image"]["runtime_distribution"][
            "published"
        ]
        is True
        and candidate["artifacts"]["kubernetes_payload"]["published"] is True
        and candidate["metadata"]["deployable"] is False,
        "published artifact is consumed without production promotion",
    )
    cfg = materialize_config(candidate, fixture)
    check(
        cfg["os"]["contractRef"] == "ADR-Platform-016"
        and cfg["type"] == "flatcar"
        and cfg["provider"] == "kubevirt",
        "shared contract reference and profile-specific selection stay separate",
    )

    validate_ordinary_path_is_closed()

    with tempfile.TemporaryDirectory(
        prefix=".ok125-render-a-",
        dir=ROOT,
    ) as first_name, tempfile.TemporaryDirectory(
        prefix=".ok125-render-b-",
        dir=ROOT,
    ) as second_name:
        first = Path(first_name)
        second = Path(second_name)
        renderer.render_cluster(args.cluster, first, cfg)
        renderer.render_cluster(args.cluster, second, cfg)
        first_bytes = directory_bytes(first)
        second_bytes = directory_bytes(second)
        check(
            first_bytes == second_bytes,
            "identical declarative inputs render byte-identical output",
        )

        manifest = first / "cluster-v2.yaml"
        validate_manifest(manifest, cfg)
        validate_cilium_profile(first / "cilium-values.yaml", cfg)
        manifest_digest = "sha256:" + hashlib.sha256(
            manifest.read_bytes()
        ).hexdigest()

        rendered_evidence = EVIDENCE / "render"
        if rendered_evidence.exists():
            shutil.rmtree(rendered_evidence)
        rendered_evidence.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(first, rendered_evidence)

    status = (
        "PASS"
        if CHECKS and all(item["status"] == "PASS" for item in CHECKS)
        else "FAIL"
    )
    write_result(status, manifest_digest, sorted(first_bytes))
    print(f"MANIFEST {manifest_digest}")
    print(f"EVIDENCE {EVIDENCE.relative_to(ROOT)}/")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError, OSError, yaml.YAMLError) as error:
        CHECKS.append(
            {
                "check": "renderer execution",
                "status": "FAIL",
                "detail": str(error),
            }
        )
        write_result("FAIL", "", [])
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
