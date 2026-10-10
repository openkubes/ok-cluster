#!/usr/bin/env python3
"""Offline acceptance checks for OK-178 workload user namespaces."""

from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import shutil
from string import Template
import subprocess
import sys
import tempfile
import uuid

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import render as renderer  # noqa: E402


DEFAULT_MAX = 11255
BASE_PATH = "/var/openebs/ok178-test"
PLACEHOLDER = "${WORKLOAD_USER_NAMESPACE_PATCHES}"
CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((condition, message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def yaml_docs(text: str) -> list[dict]:
    return [item for item in yaml.safe_load_all(text) if item]


def talos_specs(text: str) -> tuple[dict, dict]:
    resources = yaml_docs(text)
    control_plane = next(
        item["spec"]["controlPlaneConfig"]["controlplane"]
        for item in resources
        if item.get("kind") == "TalosControlPlane"
    )
    worker = next(
        item["spec"]["template"]["spec"]
        for item in resources
        if item.get("kind") == "TalosConfigTemplate"
    )
    return control_plane, worker


def enabled_config(*, maximum: int = DEFAULT_MAX, path: str = BASE_PATH) -> dict:
    cfg = copy.deepcopy(load(ROOT / "ok-ai" / "cluster-config.yaml"))
    cfg["name"] = "ok178-structural-test"
    cfg["workloadUserNamespaces"] = {
        "enabled": True,
        "maxUserNamespaces": maximum,
        "provisionerBasePath": path,
    }
    return cfg


def expected_ops(maximum: int = DEFAULT_MAX, path: str = BASE_PATH) -> list[dict]:
    return [
        {
            "op": "add",
            "path": "/machine/sysctls",
            "value": {"user.max_user_namespaces": str(maximum)},
        },
        {
            "op": "add",
            "path": "/machine/kubelet/extraMounts",
            "value": [
                {
                    "destination": path,
                    "type": "bind",
                    "source": path,
                    "options": ["bind", "rshared", "rw"],
                }
            ],
        },
    ]


def reject(cfg: dict, reason: str, label: str) -> None:
    try:
        renderer.validate_workload_user_namespaces(cfg)
    except SystemExit as exc:
        actual = str(exc)
        passed = reason in actual
        check(passed, f"negative {label}: {actual}")
    else:
        check(False, f"negative {label}: accepted; expected {reason}")


def negative_contract_checks() -> None:
    base = {"name": "bad", "type": "talos", "provider": "kubevirt"}
    cases: list[tuple[object, str, str]] = [
        ([], "must be a mapping", "malformed block"),
        ({}, "enabled must be a boolean", "missing enabled"),
        ({"enabled": "true"}, "enabled must be a boolean", "string enabled"),
        ({"enabled": 1}, "enabled must be a boolean", "integer enabled"),
        ({"enabled": True}, "provisionerBasePath is required", "enabled missing path"),
        (
            {"enabled": True, "provisionerBasePath": BASE_PATH, "surprise": True},
            "unknown: surprise",
            "unknown key",
        ),
        (
            {"enabled": True, "maxUserNamespaces": True, "provisionerBasePath": BASE_PATH},
            "maxUserNamespaces must be a positive integer",
            "boolean maximum",
        ),
        (
            {"enabled": True, "maxUserNamespaces": "11255", "provisionerBasePath": BASE_PATH},
            "maxUserNamespaces must be a positive integer",
            "string maximum",
        ),
        (
            {"enabled": True, "maxUserNamespaces": 11255.0, "provisionerBasePath": BASE_PATH},
            "maxUserNamespaces must be a positive integer",
            "float maximum",
        ),
        (
            {"enabled": True, "maxUserNamespaces": 0, "provisionerBasePath": BASE_PATH},
            "maxUserNamespaces must be a positive integer",
            "zero maximum",
        ),
        (
            {"enabled": True, "maxUserNamespaces": -1, "provisionerBasePath": BASE_PATH},
            "maxUserNamespaces must be a positive integer",
            "negative maximum",
        ),
        (
            {"enabled": True, "provisionerBasePath": "var/openebs/workspaces"},
            "normalized absolute child of /var",
            "relative path",
        ),
        (
            {"enabled": True, "provisionerBasePath": "/opt/openebs/workspaces"},
            "normalized absolute child of /var",
            "non-var path",
        ),
        (
            {"enabled": True, "provisionerBasePath": "/var/openebs/../workspaces"},
            "normalized absolute child of /var",
            "traversal path",
        ),
        (
            {"enabled": False, "maxUserNamespaces": False},
            "maxUserNamespaces must be a positive integer",
            "disabled invalid maximum",
        ),
        (
            {"enabled": False, "provisionerBasePath": "relative"},
            "normalized absolute child of /var",
            "disabled invalid path",
        ),
        (
            {"enabled": False, "provisionerBasePath": None},
            "provisionerBasePath must be a path",
            "disabled null path",
        ),
        (
            {"enabled": True, "provisionerBasePath": "/var/openebs\nworkspaces"},
            "must not contain control characters",
            "newline path",
        ),
        (
            {"enabled": True, "provisionerBasePath": "/var/openebs\x00workspaces"},
            "must not contain control characters",
            "NUL path",
        ),
    ]
    for block, reason, label in cases:
        cfg = copy.deepcopy(base)
        cfg["workloadUserNamespaces"] = block
        reject(cfg, reason, label)

    for cluster_type, provider, reason, label in (
        ("ubuntu", "kubevirt", "supported only for Talos on KubeVirt", "unsupported type enabled"),
        ("ubuntu", "kubevirt", "supported only for Talos on KubeVirt", "unsupported type disabled"),
        ("talos", "openstack", "supported only for Talos on KubeVirt", "unsupported provider enabled"),
        ("talos", "openstack", "supported only for Talos on KubeVirt", "unsupported provider disabled"),
    ):
        cfg = copy.deepcopy(base)
        cfg["type"] = cluster_type
        cfg["provider"] = provider
        cfg["workloadUserNamespaces"] = {
            "enabled": not label.endswith("disabled"),
            "provisionerBasePath": BASE_PATH,
        }
        reject(cfg, reason, label)

    non_string_key = copy.deepcopy(base)
    non_string_key["workloadUserNamespaces"] = {
        "enabled": True,
        "provisionerBasePath": BASE_PATH,
        7: "invalid",
    }
    reject(non_string_key, "keys must be strings", "non-string key")


def template_render_checks() -> str:
    cfg = enabled_config()
    renderer.validate_workload_user_namespaces(cfg)
    context = renderer.build_context(cfg)
    expected = expected_ops()
    kubevirt_render = ""
    for relative in (
        Path("templates/talos/cluster-base.yaml.tpl"),
        Path("templates/talos/providers/kubevirt/cluster-base.yaml.tpl"),
    ):
        template_text = (ROOT / relative).read_text(encoding="utf-8")
        check(
            template_text.count(PLACEHOLDER) == 1,
            f"{relative} has exactly one worker patch placeholder",
        )
        legacy_text = template_text.replace(PLACEHOLDER, "")
        legacy_render = renderer.apply_node_selector(
            Template(legacy_text).safe_substitute(context), context["NODE_SELECTOR"]
        )
        rendered = renderer.apply_node_selector(
            Template(template_text).safe_substitute(context), context["NODE_SELECTOR"]
        )
        legacy_cp, legacy_worker = talos_specs(legacy_render)
        control_plane, worker = talos_specs(rendered)
        check(
            control_plane["configPatches"] == legacy_cp["configPatches"],
            f"{relative} leaves control-plane patches byte-structurally untouched",
        )
        check(
            worker["configPatches"][:-2] == legacy_worker["configPatches"]
            and worker["configPatches"][-2:] == expected,
            f"{relative} preserves worker patches and appends exact user-namespace patches",
        )
        if "providers/kubevirt" in str(relative):
            kubevirt_render = rendered

    defaulted = enabled_config()
    del defaulted["workloadUserNamespaces"]["maxUserNamespaces"]
    renderer.validate_workload_user_namespaces(defaulted)
    default_context = renderer.build_context(defaulted)
    check(
        str(DEFAULT_MAX) in default_context["WORKLOAD_USER_NAMESPACE_PATCHES"],
        "enabled block defaults maxUserNamespaces to 11255",
    )

    custom = enabled_config(maximum=22411)
    custom_context = renderer.build_context(custom)
    custom_text = Template(
        (ROOT / "templates/talos/cluster-base.yaml.tpl").read_text(encoding="utf-8")
    ).safe_substitute(custom_context)
    _, custom_worker = talos_specs(custom_text)
    check(
        custom_worker["configPatches"][-2:] == expected_ops(maximum=22411),
        "custom maxUserNamespaces renders the exact requested value",
    )

    for block, label in (
        ({"enabled": False}, "minimal disabled block"),
        (
            {
                "enabled": False,
                "maxUserNamespaces": DEFAULT_MAX,
                "provisionerBasePath": BASE_PATH,
            },
            "fully specified disabled block",
        ),
    ):
        disabled = enabled_config()
        disabled["workloadUserNamespaces"] = block
        renderer.validate_workload_user_namespaces(disabled)
        check(
            renderer.build_context(disabled)["WORKLOAD_USER_NAMESPACE_PATCHES"] == "",
            f"{label} renders no patches",
        )

    yaml_sensitive = enabled_config(path="/var/a: b")
    renderer.validate_workload_user_namespaces(yaml_sensitive)
    sensitive_context = renderer.build_context(yaml_sensitive)
    sensitive_text = Template(
        (ROOT / "templates/talos/cluster-base.yaml.tpl").read_text(encoding="utf-8")
    ).safe_substitute(sensitive_context)
    _, sensitive_worker = talos_specs(sensitive_text)
    check(
        sensitive_worker["configPatches"][-1]["value"][0]["source"] == "/var/a: b",
        "YAML-sensitive valid /var path renders as the exact scalar",
    )
    return kubevirt_render


def template_dirs(cfg: dict) -> list[Path]:
    cluster_type = cfg.get("type", "ubuntu")
    directories = [ROOT / "templates" / cluster_type]
    if cluster_type == "talos-mgmt":
        directories.extend(
            [
                ROOT / "templates" / "talos-mgmt" / "providers" / cfg.get("provider", "kubevirt")
            ]
        )
        directories.insert(0, ROOT / "templates" / "talos")
    elif cluster_type == "talos":
        provider_dir = ROOT / "templates" / "talos" / "providers" / cfg.get("provider", "kubevirt")
        directories = directories + [provider_dir] if cfg.get("provider", "kubevirt") == "kubevirt" else [provider_dir]
    return directories


def default_byte_identity_checks() -> None:
    compared = 0
    expected = 0
    for config_path in sorted(ROOT.glob("ok-*/cluster-config.yaml")):
        cfg = load(config_path)
        absent = copy.deepcopy(cfg)
        absent.pop("workloadUserNamespaces", None)
        context = renderer.build_context(absent)
        legacy_context = dict(context)
        legacy_context.pop("WORKLOAD_USER_NAMESPACE_PATCHES", None)
        templates: dict[str, Path] = {}
        for directory in template_dirs(absent):
            for template_path in directory.glob("*.tpl"):
                templates[template_path.name] = template_path
        expected += len(templates)
        with tempfile.TemporaryDirectory(prefix=".ok178-default-", dir=ROOT) as tmp:
            output = Path(tmp) / "absent"
            renderer.render_cluster(absent["name"], output, absent)
            for template_path in sorted(templates.values(), key=lambda path: path.name):
                template_text = template_path.read_text(encoding="utf-8")
                legacy_template = template_text.replace(PLACEHOLDER, "")
                legacy = Template(legacy_template).safe_substitute(legacy_context)
                legacy = renderer.apply_node_selector(legacy, context["NODE_SELECTOR"])
                actual = (output / template_path.stem).read_text(encoding="utf-8")
                check(
                    actual == legacy,
                    f"default render is byte-identical for {config_path.parent.name}/{template_path.stem}",
                )
                compared += 1

            if absent.get("type") == "talos" and absent.get("provider", "kubevirt") == "kubevirt":
                disabled = copy.deepcopy(absent)
                disabled["workloadUserNamespaces"] = {
                    "enabled": False,
                    "maxUserNamespaces": DEFAULT_MAX,
                    "provisionerBasePath": BASE_PATH,
                }
                disabled_output = Path(tmp) / "disabled"
                renderer.render_cluster(disabled["name"], disabled_output, disabled)
                for template_path in templates.values():
                    check(
                        (disabled_output / template_path.stem).read_bytes()
                        == (output / template_path.stem).read_bytes(),
                        f"disabled render is byte-identical for {config_path.parent.name}/{template_path.stem}",
                    )
    check(
        expected > 0 and compared == expected,
        f"default byte-identity guard covers every rendered artifact ({compared})",
    )


def anonymous_fd(data: bytes, name: str) -> tuple[int, str]:
    if not hasattr(os, "memfd_create"):
        raise RuntimeError("anonymous memfd support is required")
    descriptor = os.memfd_create(name, flags=0)
    os.write(descriptor, data)
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.set_inheritable(descriptor, True)
    return descriptor, f"/proc/self/fd/{descriptor}"


def run_with_fds(argv: list[str], descriptors: list[int]) -> bytes:
    try:
        return subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            pass_fds=tuple(descriptors),
        ).stdout
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def talos_validation_check(rendered: str) -> None:
    version = subprocess.run(
        ["talosctl", "version", "--client"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
        text=True,
    ).stdout
    check(
        re.search(r"(?m)^\s*Tag:\s+v1\.9\.5\s*$", version) is not None,
        "talosctl client is exactly v1.9.5",
    )
    _, worker = talos_specs(rendered)
    actual_ops = worker["configPatches"][-2:]
    patch_fd, patch_path = anonymous_fd(
        yaml.safe_dump(actual_ops, sort_keys=False).encode(), "ok178-patch"
    )
    generated = run_with_fds(
        [
            "talosctl",
            "gen",
            "config",
            "ok178-validation",
            "https://192.0.2.10:6443",
            "--talos-version",
            "v1.9",
            "--output-types",
            "worker",
            "--output",
            "-",
            "--with-cluster-discovery=false",
            "--with-docs=false",
            "--with-examples=false",
            "--config-patch-worker",
            "@" + patch_path,
        ],
        [patch_fd],
    )
    generated_cfg = yaml.safe_load(generated)
    check(
        generated_cfg["machine"]["sysctls"]["user.max_user_namespaces"] == str(DEFAULT_MAX),
        "talosctl generated config retains user.max_user_namespaces",
    )
    check(
        generated_cfg["machine"]["kubelet"]["extraMounts"] == expected_ops()[1]["value"],
        "talosctl generated config retains the exact kubelet bind mount",
    )
    config_fd, config_path = anonymous_fd(generated, "ok178-worker-config")
    run_with_fds(
        [
            "talosctl",
            "validate",
            "--config",
            config_path,
            "--mode",
            "cloud",
            "--strict",
        ],
        [config_fd],
    )
    check(True, "talosctl v1.9.5 strict cloud validation accepts the generated worker config")


def make_smoke_check() -> None:
    # Valid path bytes must survive both GNU Make expansion and shell parsing.
    scaffold_path = '/var/ok178-$HOME`printf injected`"quoted\'path'
    cluster = f"ok178-test-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    cluster_dir = ROOT / cluster
    invalid_cluster = cluster + "-invalid"
    invalid_dir = ROOT / invalid_cluster
    if cluster_dir.exists() or invalid_dir.exists():
        raise RuntimeError("refusing to reuse an existing smoke-test cluster directory")
    with tempfile.TemporaryDirectory(prefix="ok178-shim-") as tmp:
        temp = Path(tmp)
        marker = temp / "kubectl-invocations"
        shim = temp / "kubectl"
        shim.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> {marker}\n"
            "echo 'OK-178 test forbids kubectl access' >&2\n"
            "exit 97\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        kubeconfig = temp / "forbidden-kubeconfig"
        kubeconfig.write_text("forbidden: true\n", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{temp}:{env['PATH']}",
                "INFRA_KUBECONFIG": str(kubeconfig),
                "OKB_KUBECONFIG": str(kubeconfig),
                "START_IP": "192.168.100.249",
            }
        )
        try:
            for cluster_type, provider in (("ubuntu", "kubevirt"), ("talos", "openstack")):
                disabled = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "render.py"),
                        "validate-workload-user-namespaces-env",
                        "--type",
                        cluster_type,
                        "--provider",
                        provider,
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                check(
                    disabled.returncode == 0,
                    f"disabled scaffold default remains valid for {cluster_type}/{provider}",
                )
            invalid = subprocess.run(
                [
                    "make",
                    "new",
                    f"CLUSTER={invalid_cluster}",
                    "TYPE=talos",
                    "WORKLOAD_USER_NAMESPACES=true",
                    "MAX_USER_NAMESPACES=0",
                    f"PROVISIONER_BASE_PATH={BASE_PATH}",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            check(
                invalid.returncode != 0
                and "workloadUserNamespaces.maxUserNamespaces must be a positive integer"
                in invalid.stdout
                and not invalid_dir.exists(),
                "make new rejects invalid user namespaces before creating a cluster directory",
            )
            created = subprocess.run(
                [
                    "make",
                    "new",
                    f"CLUSTER={cluster}",
                    "TYPE=talos",
                    "WORKLOAD_USER_NAMESPACES=true",
                    f"PROVISIONER_BASE_PATH={scaffold_path}",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            check(created.returncode == 0, "make new succeeds offline with the enabled block")
            if created.returncode != 0:
                print(created.stdout)
                return
            persisted = load(cluster_dir / "cluster-config.yaml")
            check(
                persisted["workloadUserNamespaces"]
                == {
                    "enabled": True,
                    "maxUserNamespaces": DEFAULT_MAX,
                    "provisionerBasePath": scaffold_path,
                },
                "make new persists the exact enabled block and default",
            )
            rerendered = subprocess.run(
                ["make", "render", f"CLUSTER={cluster}"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            check(rerendered.returncode == 0, "make render consumes the persisted block offline")
            manifest = (cluster_dir / "cluster-base.yaml").read_text(encoding="utf-8")
            _, worker = talos_specs(manifest)
            check(
                worker["configPatches"][-2:] == expected_ops(path=scaffold_path),
                "make new/render preserves literal shell-significant path bytes in worker patches",
            )
            persisted["workloadUserNamespaces"] = {"enabled": False}
            (cluster_dir / "cluster-config.yaml").write_text(
                yaml.safe_dump(persisted, sort_keys=False), encoding="utf-8"
            )
            disabled_render = subprocess.run(
                ["make", "render", f"CLUSTER={cluster}"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            disabled_manifest = (cluster_dir / "cluster-base.yaml").read_text(
                encoding="utf-8"
            )
            disabled_cp, disabled_worker = talos_specs(disabled_manifest)
            all_disabled_patches = (
                disabled_cp["configPatches"] + disabled_worker["configPatches"]
            )
            check(
                disabled_render.returncode == 0
                and not any(
                    patch.get("path")
                    in {"/machine/sysctls", "/machine/kubelet/extraMounts"}
                    for patch in all_disabled_patches
                ),
                "make render removes both patches when the persisted block is disabled",
            )
            check(marker.exists(), "rejecting kubectl shim intercepted every attempted API probe")
        finally:
            shutil.rmtree(cluster_dir, ignore_errors=True)
            shutil.rmtree(invalid_dir, ignore_errors=True)
    check(not cluster_dir.exists() and not invalid_dir.exists(), "throwaway cluster directories are removed")


def main() -> int:
    # Negative checks intentionally run first: green behavior is not trusted until
    # each contract guard has been observed rejecting its targeted violation.
    negative_contract_checks()
    rendered = template_render_checks()
    default_byte_identity_checks()
    talos_validation_check(rendered)
    make_smoke_check()
    failures = [message for passed, message in CHECKS if not passed]
    print(f"\nOK-178 workload user namespaces: {len(CHECKS) - len(failures)}/{len(CHECKS)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
