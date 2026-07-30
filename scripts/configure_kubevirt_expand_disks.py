#!/usr/bin/env python3
"""Guardedly enable KubeVirt ExpandDisks on the pinned infrastructure cluster."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import time
from pathlib import Path


EXPECTED_VERSION = "v1.8.1"
FEATURE_GATE = "ExpandDisks"


class ConfigurationError(RuntimeError):
    """The bounded KubeVirt configuration cannot be reconciled safely."""


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ConfigurationError(
            f"{' '.join(command[:5])} exited {result.returncode}: {detail}"
        )
    return result


def kubectl_json(kubeconfig: Path, arguments: list[str]) -> dict:
    return json.loads(
        run(
            [
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                *arguments,
                "-o",
                "json",
            ]
        ).stdout
    )


def validate_installation(item: dict) -> None:
    status = item.get("status", {})
    if (
        status.get("phase") != "Deployed"
        or status.get("observedKubeVirtVersion") != EXPECTED_VERSION
        or status.get("targetKubeVirtVersion") != EXPECTED_VERSION
    ):
        raise ConfigurationError(
            f"KubeVirt must be Deployed at exact version {EXPECTED_VERSION}"
        )


def desired_configuration(item: dict) -> tuple[dict, bool]:
    validate_installation(item)
    configuration = copy.deepcopy(item.get("spec", {}).get("configuration", {}))
    developer = configuration.setdefault("developerConfiguration", {})
    gates = developer.get("featureGates")
    if gates is None:
        gates = []
    if not isinstance(gates, list) or not all(
        isinstance(value, str) for value in gates
    ):
        raise ConfigurationError("KubeVirt featureGates must be a string list")
    if FEATURE_GATE in gates:
        return configuration, False
    developer["featureGates"] = [*gates, FEATURE_GATE]
    return configuration, True


def reconcile(kubeconfig: Path, apply: bool) -> dict:
    inventory = kubectl_json(kubeconfig, ["get", "kubevirt.kubevirt.io", "-A"])
    items = inventory.get("items", [])
    if len(items) != 1:
        raise ConfigurationError(
            f"expected one KubeVirt installation, observed {len(items)}"
        )
    item = items[0]
    configuration, changed = desired_configuration(item)
    metadata = item["metadata"]
    result = {
        "namespace": metadata["namespace"],
        "name": metadata["name"],
        "version": EXPECTED_VERSION,
        "feature_gate": FEATURE_GATE,
        "changed": changed,
        "mutation_attempted": False,
    }
    if not changed:
        return result
    if not apply:
        raise ConfigurationError(
            "ExpandDisks is absent; re-run with --apply after approval"
        )
    operation = (
        "replace" if "configuration" in item.get("spec", {}) else "add"
    )
    patch = [
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": metadata["resourceVersion"],
        },
        {
            "op": operation,
            "path": "/spec/configuration",
            "value": configuration,
        },
    ]
    run(
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "-n",
            metadata["namespace"],
            "patch",
            "kubevirt.kubevirt.io",
            metadata["name"],
            "--type=json",
            "--patch",
            json.dumps(patch, separators=(",", ":")),
        ]
    )
    result["mutation_attempted"] = True
    for _ in range(60):
        current = kubectl_json(
            kubeconfig,
            [
                "-n",
                metadata["namespace"],
                "get",
                "kubevirt.kubevirt.io",
                metadata["name"],
            ],
        )
        gates = (
            current.get("spec", {})
            .get("configuration", {})
            .get("developerConfiguration", {})
            .get("featureGates")
            or []
        )
        if (
            FEATURE_GATE in gates
            and current.get("status", {}).get("phase") == "Deployed"
        ):
            validate_installation(current)
            return result
        time.sleep(5)
    raise ConfigurationError(
        "timed out waiting for KubeVirt ExpandDisks reconciliation"
    )


def self_test() -> int:
    base = {
        "metadata": {
            "name": "kubevirt",
            "namespace": "kubevirt",
            "resourceVersion": "42",
        },
        "spec": {
            "configuration": {
                "developerConfiguration": {
                    "featureGates": ["Snapshot"],
                    "pvcTolerateLessSpaceUpToPercent": 10,
                }
            }
        },
        "status": {
            "phase": "Deployed",
            "observedKubeVirtVersion": EXPECTED_VERSION,
            "targetKubeVirtVersion": EXPECTED_VERSION,
        },
    }
    desired, changed = desired_configuration(base)
    assert changed
    assert desired["developerConfiguration"]["featureGates"] == [
        "Snapshot",
        FEATURE_GATE,
    ]
    assert desired["developerConfiguration"][
        "pvcTolerateLessSpaceUpToPercent"
    ] == 10
    converged = copy.deepcopy(base)
    converged["spec"]["configuration"] = desired
    again, changed_again = desired_configuration(converged)
    assert not changed_again and again == desired
    print("PASS KubeVirt ExpandDisks reconciliation is bounded and idempotent")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kubeconfig")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.kubeconfig:
        raise ConfigurationError("--kubeconfig is required")
    kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    if not kubeconfig.is_file():
        raise ConfigurationError(f"kubeconfig is absent: {kubeconfig}")
    result = reconcile(kubeconfig, args.apply)
    print(
        "PASS KubeVirt ExpandDisks "
        f"namespace={result['namespace']} changed={result['changed']} "
        f"mutation_attempted={result['mutation_attempted']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConfigurationError, KeyError, OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
