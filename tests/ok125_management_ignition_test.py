#!/usr/bin/env python3
"""Offline contract checks for the OK-125 management-controller path."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import render as renderer  # noqa: E402


TEMPLATE = ROOT / "templates" / "talos-mgmt" / "bootstrap-mgmt.sh.tpl"
RECONCILER = (
    ROOT
    / "scripts"
    / "adoption"
    / "OK-125"
    / "configure_management_ignition.py"
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def main() -> int:
    text = TEMPLATE.read_text(encoding="utf-8")
    check(
        "export EXP_KUBEADM_BOOTSTRAP_FORMAT_IGNITION=true" in text,
        "management bootstrap enables the upstream Ignition gate",
    )
    check(
        "--core cluster-api:v1.13.3" in text
        and "--bootstrap talos,kubeadm:v1.13.3" in text
        and "--control-plane talos,kubeadm:v1.13.3" in text,
        "CAPI and kubeadm providers are version-pinned alongside Talos",
    )
    check(
        "capi-kubeadm-bootstrap-controller-manager" in text
        and "capi-kubeadm-control-plane-controller-manager" in text,
        "management bootstrap waits for both kubeadm controllers",
    )
    check(
        "ADR-Platform-016" not in text,
        "management provider mechanics do not redefine the OS contract",
    )
    config = yaml.safe_load(
        (ROOT / "ok-mgmt" / "cluster-config.yaml").read_text(encoding="utf-8")
    )
    with tempfile.TemporaryDirectory(
        prefix=".ok125-management-render-",
        dir=ROOT,
    ) as output_name:
        output = Path(output_name)
        renderer.render_cluster("ok-mgmt", output, config)
        rendered = output / "bootstrap-mgmt.sh"
        syntax = subprocess.run(
            ["bash", "-n", str(rendered)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        check(
            syntax.returncode == 0
            and "--infrastructure kubevirt" in rendered.read_text(
                encoding="utf-8"
            ),
            "management bootstrap renders provider selection with valid shell",
        )
    result = subprocess.run(
        ["python3", str(RECONCILER), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0
        and "PASS management Ignition patch is atomic and bounded"
        in result.stdout,
        "existing-provider reconciliation is atomically guarded",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
