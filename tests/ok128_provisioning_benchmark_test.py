#!/usr/bin/env python3
"""Offline tests for the guarded OK-128 provisioning observer."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import provisioning_benchmark as benchmark  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def expect_failure(function, message: str) -> None:
    try:
        function()
    except benchmark.BenchmarkError:
        check(True, message)
    else:
        check(False, message)


def fixture(os_name: str, order: int, offset: int) -> dict:
    timeline = {}
    values = (0, 1, 20, 30, 40, 50, 55, 60, 61)
    started = datetime(2026, 7, 30, 10, offset, tzinfo=timezone.utc)
    for name, seconds in zip(benchmark.MILESTONES, values):
        timestamp = (started + timedelta(seconds=seconds)).isoformat()
        timeline[name] = {
            "timestamp": timestamp.replace("+00:00", "Z"),
            "elapsed_seconds": seconds,
        }
    return {
        "schema": "openkubes.ok128.provisioning-benchmark/v1",
        "os": os_name,
        "exit_code": 0,
        "test_order": order,
        "envelope": {
            "provider": "kubevirt",
            "architecture": "amd64",
            "kubernetes": "v1.34.1",
            "expected_nodes": 2,
        },
        "timeline": timeline,
        "operator_timing_seconds": {"real": 61.2, "user": 1.1, "sys": 0.4},
        "classification": "observed-single-run-no-slo",
        "inputs": {
            "cilium_chart": {
                "sha256": benchmark.EXPECTED_CHART_SHA256
            }
        },
        "management_load": {
            "before": {
                "scheduled_pods": 20,
                "running_vmis": 0,
                "total_vmis": 0,
            },
            "after": {
                "scheduled_pods": 24,
                "running_vmis": 2,
                "total_vmis": 2,
            },
        },
        "source": {
            "ok-cluster": {"revision": "a" * 40},
            "ok-linux": {"revision": "b" * 40},
        },
    }


def main() -> int:
    parsed = benchmark.parse_posix_time("real 12.34\nuser 1.20\nsys 0.40\n")
    check(
        parsed == {"real": 12.34, "user": 1.2, "sys": 0.4},
        "POSIX operator timing records real/user/sys",
    )
    expect_failure(
        lambda: benchmark.parse_posix_time("real 1.0\n"),
        "incomplete operator timing fails closed",
    )

    raw = (
        "token: abc123\n--password secret\n"
        '{"client-key-data": "base64-secret"}\n'
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
    )
    sanitized = benchmark.redact(raw)
    benchmark.require_sanitized(sanitized)
    check(
        "abc123" not in sanitized
        and " secret" not in sanitized
        and "base64-secret" not in sanitized
        and "PRIVATE KEY" not in sanitized,
        "logs redact common kubeconfig, CLI, and PEM secrets",
    )
    expect_failure(
        lambda: benchmark.require_sanitized("token: still-secret\n"),
        "secret scan fails closed before evidence publication",
    )

    config = {
        "name": "bench-flatcar",
        "type": "flatcar",
        "provider": "kubevirt",
        "architecture": "amd64",
        "controlPlane": {
            "replicas": 1,
            "cores": 2,
            "memory": "4Gi",
            "disk": "20Gi",
        },
        "workers": {
            "replicas": 1,
            "cores": 2,
            "memory": "4Gi",
            "disk": "20Gi",
        },
        "nodeSelector": "ok-infra",
    }
    envelope = benchmark.validate_envelope(config, "flatcar", "bench-flatcar")
    check(
        envelope["expected_nodes"] == 2,
        "controlled 1+1 amd64 KubeVirt envelope is explicit",
    )
    invalid = copy.deepcopy(config)
    invalid["workers"]["replicas"] = 2
    expect_failure(
        lambda: benchmark.validate_envelope(
            invalid, "flatcar", "bench-flatcar"
        ),
        "non-comparable cluster shape fails closed",
    )
    benchmark.validate_command(
        "flatcar", ["make", "--no-print-directory", "install-flatcar"]
    )
    expect_failure(
        lambda: benchmark.validate_command(
            "talos", ["make", "install-flatcar"]
        ),
        "observer refuses a lifecycle target belonging to the other OS",
    )

    milestones = {"command_started": "2026-07-30T10:00:00Z"}
    cluster = {
        "metadata": {"creationTimestamp": "2026-07-30T10:00:01Z"},
        "status": {
            "conditions": [
                {
                    "type": "Available",
                    "status": "True",
                    "lastTransitionTime": "2026-07-30T10:01:00Z",
                }
            ]
        },
    }
    nodes = {
        "items": [
            {
                "metadata": {
                    "labels": {
                        "node-role.kubernetes.io/control-plane": ""
                    }
                },
                "status": {
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "True",
                            "lastTransitionTime": "2026-07-30T10:00:30Z",
                        }
                    ]
                },
            },
            {
                "metadata": {"labels": {}},
                "status": {
                    "conditions": [
                        {
                            "type": "Ready",
                            "status": "True",
                            "lastTransitionTime": "2026-07-30T10:00:40Z",
                        }
                    ]
                },
            },
        ]
    }
    benchmark.update_milestones(
        milestones,
        cluster,
        {
            "nodes": nodes,
            "cilium_daemonset": {
                "status": {
                    "desiredNumberScheduled": 2,
                    "numberAvailable": 2,
                }
            },
            "cilium_operator": {"status": {"availableReplicas": 1}},
        },
        "2026-07-30T10:00:55Z",
    )
    check(
        set(milestones) == set(benchmark.MILESTONES) - {"command_completed"}
        and milestones["first_node_ready"].endswith("30Z")
        and milestones["all_nodes_ready"].endswith("40Z"),
        "all eight observable Kubernetes milestones are extracted",
    )
    reordered = {
        "command_started": "2026-07-30T10:00:00Z",
        "capi_cluster_created": "2026-07-30T10:00:01Z",
        "api_reachable_control_plane_registered": "2026-07-30T10:00:30Z",
        "first_node_ready": "2026-07-30T10:00:25Z",
        "all_nodes_ready": "2026-07-30T10:00:40Z",
        "cilium_daemonset_available": "2026-07-30T10:00:55Z",
        "cilium_operator_available": "2026-07-30T10:00:54Z",
        "capi_cluster_available": "2026-07-30T10:00:35Z",
        "command_completed": "2026-07-30T10:01:00Z",
    }
    benchmark.validate_timeline(reordered)
    check(
        True,
        "server transitions and observer milestones need not follow list order",
    )
    outside = dict(reordered)
    outside["capi_cluster_created"] = "2026-07-30T09:59:59Z"
    expect_failure(
        lambda: benchmark.validate_timeline(outside),
        "milestones outside command bounds fail closed",
    )

    flatcar = fixture("flatcar", 1, 0)
    talos = fixture("talos", 2, 2)
    markdown, csv_text = benchmark.compare_results(flatcar, talos)
    check(
        "no SLO claim" in markdown
        and "operator_real" in csv_text
        and "capi_cluster_available" in csv_text,
        "comparison emits explicit observed-only Markdown and CSV",
    )
    overlap = copy.deepcopy(talos)
    overlap["timeline"]["command_started"]["timestamp"] = (
        "2026-07-30T10:00:30Z"
    )
    expect_failure(
        lambda: benchmark.compare_results(flatcar, overlap),
        "overlapping runs fail the sequential-order gate",
    )
    mismatch = copy.deepcopy(talos)
    mismatch["envelope"]["expected_nodes"] = 3
    expect_failure(
        lambda: benchmark.compare_results(flatcar, mismatch),
        "envelope mismatch fails comparison",
    )

    with tempfile.TemporaryDirectory(prefix=".ok128-test-", dir=ROOT) as temp:
        output = Path(temp)
        benchmark.atomic_text(output / "evidence.json", json.dumps(flatcar))
        check(
            (output / "evidence.json").is_file(),
            "sanitized evidence is atomically published",
        )
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    runbook = (
        ROOT / "docs" / "adoption" / "OK-128" / "benchmark-runbook.md"
    ).read_text(encoding="utf-8")
    check(
        "ok128-benchmark-preflight:" in makefile
        and "ok128-benchmark-flatcar:" in makefile
        and "ok128-benchmark-talos:" in makefile
        and "OK128_BENCHMARK_APPLY=yes" in runbook,
        "read-only preflight and guarded OS lifecycle wrappers are documented",
    )
    observer = (
        ROOT / "scripts" / "provisioning_benchmark.py"
    ).read_text(encoding="utf-8")
    check(
        '"lifecycle_command_completed"' in observer
        and "MILESTONES[:-1]" in observer
        and "refusing overwrite" in observer,
        "wrapper completion is distinct and run evidence is immutable",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
