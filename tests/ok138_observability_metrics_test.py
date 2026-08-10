#!/usr/bin/env python3
"""Offline positive and negative tests for the OK-138 metrics-only installer."""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_observability_metrics.py"
SPEC = importlib.util.spec_from_file_location("metrics_verifier", VERIFIER)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def expect_rejected(function, expected: str, message: str) -> None:
    try:
        function()
    except verifier.VerificationError as error:
        check(expected in str(error), f"{message}: {error}")
    else:
        raise AssertionError(f"guard accepted violation: {message}")


def values(grafana_enabled: bool = False) -> dict:
    return {
        "kube-prometheus-stack": {
            "fullnameOverride": "ok-observability",
            "grafana": {"enabled": grafana_enabled},
        }
    }


def prometheus_document() -> dict:
    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "Prometheus",
        "metadata": {"name": "ok-observability-prometheus"},
    }


def alertmanager_document() -> dict:
    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "Alertmanager",
        "metadata": {"name": "ok-observability-alertmanager"},
    }


def metrics_documents(*extra: dict) -> list[dict]:
    return [prometheus_document(), alertmanager_document(), *extra]


class FakePortForward:
    def __init__(self) -> None:
        self.returncode = None

    def poll(self):
        return self.returncode

    def communicate(self):
        return "", ""

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


SERVICE = {"spec": {"ports": [{"name": "http-web", "port": 9090}]}}
UP_TARGET = {
    "health": "up",
    "labels": {"namespace": "zot", "job": "zot", "instance": "zot:5000"},
    "discoveredLabels": {
        "__meta_kubernetes_namespace": "zot",
        "__meta_kubernetes_service_name": "zot",
    },
    "scrapePool": "serviceMonitor/zot/zot/0",
    "scrapeUrl": "http://zot.zot.svc:5000/metrics",
}
DOWN_TARGET = {**UP_TARGET, "health": "down"}


def api_payload(target, result=None):
    targets = {
        "status": "success",
        "data": {"activeTargets": [target]},
    }
    query = {
        "status": "success",
        "data": {"resultType": "vector", "result": result or []},
    }
    return targets, query


def run_live_with(responses, monotonic_values):
    with (
        mock.patch.object(verifier, "kubectl_json", return_value=SERVICE),
        mock.patch.object(verifier, "available_port", return_value=19090),
        mock.patch.object(verifier.subprocess, "Popen", return_value=FakePortForward()),
        mock.patch.object(verifier, "api_json", side_effect=responses),
        mock.patch.object(verifier.time, "monotonic", side_effect=monotonic_values),
        mock.patch.object(verifier.time, "sleep", return_value=None),
    ):
        verifier.live_check(
            "ok-observability",
            "ok-observability-prometheus",
            "zot",
            "zot",
            r"zot_.+",
            1,
        )


def make_recipe(name: str) -> str:
    lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith(name + ":"))
    body = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(("\t", " ")):
            break
        body.append(line)
    return "\n".join(body)


def main() -> int:
    expect_rejected(
        lambda: verifier.render_guard([], values()),
        "no Prometheus",
        "render guard rejects missing Prometheus",
    )
    expect_rejected(
        lambda: verifier.render_guard(metrics_documents(), values(True)),
        "must be boolean false",
        "render guard rejects enabled Grafana structurally",
    )
    expect_rejected(
        lambda: verifier.render_guard([prometheus_document()], values()),
        "no Alertmanager",
        "render guard rejects missing Alertmanager",
    )
    forbidden = {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "search"},
        "spec": {
            "template": {
                "spec": {"containers": [{"name": "db", "image": "opensearch:2"}]}
            }
        },
    }
    expect_rejected(
        lambda: verifier.render_guard(metrics_documents(forbidden), values()),
        "forbidden metrics-only workload",
        "render guard rejects OpenSearch workload structurally",
    )
    credential_secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "ok-observability-credentials"},
    }
    expect_rejected(
        lambda: verifier.render_guard(
            metrics_documents(credential_secret), values()
        ),
        "forbidden credential Secret",
        "render guard rejects the observability credential Secret",
    )
    credential_reference = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "metrics-consumer"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "consumer",
                            "image": "example.invalid/consumer",
                            "envFrom": [
                                {
                                    "secretRef": {
                                        "name": "ok-observability-credentials"
                                    }
                                }
                            ],
                        }
                    ]
                }
            }
        },
    }
    expect_rejected(
        lambda: verifier.render_guard(
            metrics_documents(credential_reference), values()
        ),
        "forbidden credential Secret",
        "render guard rejects a reference to the observability credential Secret",
    )
    verifier.render_guard(metrics_documents(), values())
    check(True, "render guard accepts metrics-and-alerting output")

    down_targets, _ = api_payload(DOWN_TARGET)
    expect_rejected(
        lambda: run_live_with([down_targets], [0, 0, 2]),
        "no active health=up target",
        "live verifier rejects a down zot target",
    )
    wrong_service = {
        **UP_TARGET,
        "discoveredLabels": {
            **UP_TARGET["discoveredLabels"],
            "__meta_kubernetes_service_name": "another-service",
        },
    }
    wrong_service_targets, _ = api_payload(wrong_service)
    expect_rejected(
        lambda: run_live_with([wrong_service_targets], [0, 0, 2]),
        "service=zot",
        "live verifier rejects another service in the zot namespace",
    )
    up_targets, empty_query = api_payload(UP_TARGET)
    expect_rejected(
        lambda: run_live_with(
            [up_targets, empty_query],
            [0, 0, 2],
        ),
        "no finite sample",
        "live verifier rejects an empty zot metric query",
    )
    sample = {
        "metric": {"__name__": "zot_requests_total", "instance": "zot:5000"},
        "value": [1786350000.0, "7"],
    }
    up_targets, real_query = api_payload(UP_TARGET, [sample])
    run_live_with([up_targets, real_query], [0, 0])
    check(True, "live verifier accepts an up zot target and real zot sample")

    standard_recipe = make_recipe("install-observability")
    metrics_recipe = make_recipe("install-observability-metrics")
    assignments = (
        "CLUSTER",
        "KUBECONFIG_PATH",
        "OK_OBSERVABILITY_PATH",
        "OK_OBSERVABILITY_REF",
        "OBSERVABILITY_VALUES",
        "OBSERVABILITY_HELM_VALUES",
        "OBSERVABILITY_SECRET_SOURCE",
        "OBSERVABILITY_SECRET_SOURCES",
        "VAULT_ADDR",
        "VAULT_TLS_SERVER_NAME",
        "VAULT_CA_SECRET",
        "KV_MOUNT",
        "KV_PATH",
        "VAULT_ROLE",
        "VSO_SERVICE_ACCOUNT",
        "REFRESH_AFTER",
        "CONTRACT_TEST_TIMEOUT",
        "CONTRACT_TEST_RECEIVER_CAPTURE_URL",
    )
    check(
        all(f"{name}=" in standard_recipe and f"{name}=" in metrics_recipe for name in assignments)
        and "OBSERVABILITY_COMPONENTS=metrics" in metrics_recipe,
        "metrics Make target preserves standard variable passing and selects metrics",
    )

    installer = (ROOT / "install-observability.sh").read_text(encoding="utf-8")
    check(
        'OBSERVABILITY_COMPONENTS="${OBSERVABILITY_COMPONENTS:-standard}"'
        in installer
        and "standard|metrics" in installer,
        "component enum defaults an unset value to standard",
    )
    check(
        'NAMESPACE="${OBSERVABILITY_NAMESPACE:-ok-observability}"' in installer
        and 'RELEASE="${OBSERVABILITY_RELEASE:-ok-observability-standard}"'
        in installer
        and "metrics mode requires OBSERVABILITY_NAMESPACE=ok-observability"
        in installer
        and "metrics mode requires OBSERVABILITY_RELEASE=ok-observability-standard"
        in installer,
        "metrics mode pins the standard namespace and release identity",
    )
    check(
        'metrics_values+=( -f "$OBSERVABILITY_HELM_VALUES" )' in installer
        and 'kubectl -n "$NAMESPACE" apply -f "$PROMETHEUS_RULES"' in installer
        and 'apply -f "${OK_OBSERVABILITY_PATH}/dashboards/"' in installer,
        "metrics layers Provider Values and rules while standard retains dashboards",
    )
    check(
        "[1/6]" in installer
        and "[2/6]" in installer
        and "[3/6]" in installer
        and "[4/6]" in installer
        and "[5/6]" in installer
        and "[6/6]" in installer
        and 'GATE="${OK_OBSERVABILITY_PATH}/tests/contract-test.sh"' in installer,
        "standard mode retains all six steps and the full contract gate",
    )

    with tempfile.NamedTemporaryFile() as kubeconfig:
        environment = dict(
            os.environ,
            CLUSTER="offline-test",
            KUBECONFIG_PATH=kubeconfig.name,
            OK_OBSERVABILITY_PATH=str(ROOT.parent / "ok-observability"),
            OK_OBSERVABILITY_MODE="worktree",
            OBSERVABILITY_COMPONENTS="invalid",
        )
        invalid_component = subprocess.run(
            ["bash", str(ROOT / "install-observability.sh")],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        invalid_component.returncode == 2
        and "is not one of: standard metrics" in invalid_component.stdout,
        "component enum rejects an invalid value before any cluster access",
    )

    syntax = subprocess.run(
        ["bash", "-n", str(ROOT / "install-observability.sh")],
        check=False,
        capture_output=True,
        text=True,
    )
    check(syntax.returncode == 0, "installer has valid Bash syntax")
    ast.parse(VERIFIER.read_text(encoding="utf-8"), filename=str(VERIFIER))
    check(True, "metrics verifier has valid Python syntax")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
