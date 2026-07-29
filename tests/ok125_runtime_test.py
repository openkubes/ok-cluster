#!/usr/bin/env python3
"""Offline safety checks for the guarded OK-125 G1/G3 runtime."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    ROOT / "scripts" / "adoption" / "OK-125" / "runtime.py"
)
REPLACEMENT = (
    ROOT / "scripts" / "adoption" / "OK-125" / "replacement.py"
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def main() -> int:
    result = subprocess.run(
        ["python3", str(RUNTIME), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        result.returncode == 0
        and "PASS runtime scope, identity, and Cilium artifact are pinned"
        in result.stdout,
        "runtime is bounded to the disposable identity",
    )
    source = RUNTIME.read_text(encoding="utf-8")
    check(
        'CLUSTER = "ok125-flatcar"' in source
        and 'WORKLOAD_KUBECONFIG = Path("/private/tmp/' in source,
        "runtime cannot target an ordinary cluster or repo kubeconfig",
    )
    check(
        "OK125_CLEANUP" in source
        and "openkubes.io/adoption-status" in source
        and "openkubes.io/deployable" in source,
        "cleanup requires explicit confirmation and ownership labels",
    )
    check(
        "dataKeys" in source
        and "base64.b64decode" in source
        and "sensitive_stdout=True" in source,
        "Secret evidence is metadata-only and workload access stays ephemeral",
    )
    check(
        "condition_is_true(config, \"Ready\")" in source
        and 'get("status", {}).get("ready")' not in source,
        "bootstrap readiness uses CAPI v1beta2 Conditions",
    )
    replacement = subprocess.run(
        ["python3", str(REPLACEMENT), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    check(
        replacement.returncode == 0
        and "PASS G2 identities and failure scope are pinned"
        in replacement.stdout,
        "replacement runtime is identity-bound and deliberately unhealthy",
    )
    replacement_source = REPLACEMENT.read_text(encoding="utf-8")
    check(
        "minimum_ready_nodes" in replacement_source
        and "SuccessfulDrainNode" in replacement_source
        and "api_unavailable_windows" in replacement_source
        and "more than 120 seconds" in replacement_source
        and "safety_revert_requested" in replacement_source
        and 'f"virt-launcher-{failed[0][\'name\']}-"' in replacement_source
        and "imperative_guest_mutation" in replacement_source
        and "secret_values_captured" in replacement_source,
        "G2 preserves healthy capacity and forbids guest mutation or secret evidence",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
