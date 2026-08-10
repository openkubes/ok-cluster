#!/usr/bin/env python3
"""Structural and live checks for the scoped observability metrics install."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml


FORBIDDEN_WORKLOAD_TOKENS = ("grafana", "opensearch")
WORKLOAD_KINDS = {"Deployment", "StatefulSet"}


class VerificationError(RuntimeError):
    """Raised when a metrics-only invariant is not satisfied."""


def scalar_strings(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from scalar_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from scalar_strings(child)
    elif isinstance(value, str):
        yield value


def render_guard(
    documents: list[dict[str, Any]],
    values: dict[str, Any],
    forbidden_secret: str = "ok-observability-credentials",
) -> None:
    stack = values.get("kube-prometheus-stack")
    if not isinstance(stack, dict):
        raise VerificationError(
            "metrics values have no kube-prometheus-stack mapping"
        )
    grafana = stack.get("grafana")
    if not isinstance(grafana, dict) or grafana.get("enabled") is not False:
        raise VerificationError(
            "kube-prometheus-stack.grafana.enabled must be boolean false"
        )

    prometheus_objects = [
        document
        for document in documents
        if isinstance(document, dict) and document.get("kind") == "Prometheus"
    ]
    if not prometheus_objects:
        raise VerificationError("render contains no Prometheus custom resource")
    alertmanager_objects = [
        document
        for document in documents
        if isinstance(document, dict) and document.get("kind") == "Alertmanager"
    ]
    if not alertmanager_objects:
        raise VerificationError("render contains no Alertmanager custom resource")

    forbidden: list[str] = []
    for document in documents:
        if not isinstance(document, dict) or document.get("kind") not in WORKLOAD_KINDS:
            continue
        identity = " ".join(scalar_strings(document)).lower()
        matches = [token for token in FORBIDDEN_WORKLOAD_TOKENS if token in identity]
        if matches:
            name = document.get("metadata", {}).get("name", "<unnamed>")
            forbidden.append(
                f"{document.get('kind')}/{name} ({', '.join(matches)})"
            )
    if forbidden:
        raise VerificationError(
            "render contains forbidden metrics-only workload(s): "
            + ", ".join(forbidden)
        )

    secret_references: list[str] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = str(document.get("kind", "<unknown>"))
        name = str(document.get("metadata", {}).get("name", "<unnamed>"))
        if forbidden_secret in scalar_strings(document):
            secret_references.append(f"{kind}/{name}")
    if secret_references:
        raise VerificationError(
            f"render creates or references forbidden credential Secret {forbidden_secret}: "
            + ", ".join(secret_references)
        )

    names = sorted(
        str(document.get("metadata", {}).get("name", "<unnamed>"))
        for document in prometheus_objects
    )
    alertmanager_names = sorted(
        str(document.get("metadata", {}).get("name", "<unnamed>"))
        for document in alertmanager_objects
    )
    print(
        "PASS metrics render: Prometheus="
        + ",".join(names)
        + "; Alertmanager="
        + ",".join(alertmanager_names)
        + "; Grafana disabled; no Grafana/OpenSearch Deployment or StatefulSet"
    )


def kubectl_json(arguments: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        ["kubectl", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise VerificationError(f"kubectl {' '.join(arguments)} failed: {detail}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError("kubectl returned invalid JSON for Prometheus Service") from error
    if not isinstance(value, dict):
        raise VerificationError("kubectl returned a non-object for Prometheus Service")
    return value


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def api_json(base_url: str, path: str, parameters: dict[str, str] | None = None):
    query = "" if not parameters else "?" + urllib.parse.urlencode(parameters)
    with urllib.request.urlopen(base_url + path + query, timeout=3) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise VerificationError(f"Prometheus API did not return success for {path}")
    return payload


def target_namespace(target: dict[str, Any]) -> str | None:
    labels = target.get("labels") or {}
    discovered = target.get("discoveredLabels") or {}
    return labels.get("namespace") or discovered.get("__meta_kubernetes_namespace")


def target_service(target: dict[str, Any]) -> str | None:
    discovered = target.get("discoveredLabels") or {}
    return discovered.get("__meta_kubernetes_service_name")


def target_discriminator(target: dict[str, Any]) -> str:
    labels = target.get("labels") or {}
    fields = {
        "job": labels.get("job"),
        "instance": labels.get("instance"),
        "scrapePool": target.get("scrapePool"),
        "scrapeUrl": target.get("scrapeUrl"),
    }
    return " ".join(f"{key}={value}" for key, value in fields.items() if value)


def first_real_sample(results: list[dict[str, Any]], metric_pattern: re.Pattern[str]):
    for result in results:
        metric = result.get("metric") or {}
        metric_name = metric.get("__name__")
        value = result.get("value")
        if not isinstance(metric_name, str) or not metric_pattern.fullmatch(metric_name):
            continue
        if not isinstance(value, list) or len(value) != 2:
            continue
        try:
            numeric_value = float(value[1])
        except (TypeError, ValueError):
            continue
        if math.isfinite(numeric_value):
            return metric_name, str(value[1]), metric
    return None


def live_check(
    namespace: str,
    service: str,
    target_ns: str,
    target_svc: str,
    metric_regex: str,
    timeout: int,
) -> None:
    service_object = kubectl_json(
        ["-n", namespace, "get", "service", service, "-o", "json"]
    )
    ports = service_object.get("spec", {}).get("ports") or []
    if not any(
        port.get("port") == 9090 or port.get("name") in {"http-web", "web"}
        for port in ports
        if isinstance(port, dict)
    ):
        raise VerificationError(
            f"Service/{service} exposes no structurally identifiable Prometheus port"
        )

    local_port = available_port()
    process = subprocess.Popen(
        [
            "kubectl",
            "-n",
            namespace,
            "port-forward",
            f"service/{service}",
            f"{local_port}:9090",
            "--address=127.0.0.1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{local_port}"
    deadline = time.monotonic() + timeout
    selected_target = None
    sample = None
    query = f'{{__name__=~"{metric_regex}"}}'
    pattern = re.compile(metric_regex)
    last_error = "Prometheus API did not become ready"
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                detail = stderr.strip() or stdout.strip()
                raise VerificationError(f"Prometheus port-forward stopped: {detail}")
            try:
                payload = api_json(base_url, "/api/v1/targets", {"state": "active"})
                targets = payload.get("data", {}).get("activeTargets") or []
                selected_target = next(
                    (
                        target
                        for target in targets
                        if isinstance(target, dict)
                        and target.get("health") == "up"
                        and target_namespace(target) == target_ns
                        and target_service(target) == target_svc
                    ),
                    None,
                )
                if selected_target is None:
                    last_error = (
                        "no active health=up target discovered for "
                        f"namespace={target_ns} service={target_svc}"
                    )
                else:
                    payload = api_json(base_url, "/api/v1/query", {"query": query})
                    result_type = payload.get("data", {}).get("resultType")
                    results = payload.get("data", {}).get("result") or []
                    if result_type != "vector":
                        last_error = f"zot metric query returned resultType={result_type!r}"
                    else:
                        sample = first_real_sample(results, pattern)
                        if sample is not None:
                            break
                        last_error = "zot metric query returned no finite sample"
            except (OSError, urllib.error.URLError, json.JSONDecodeError, VerificationError) as error:
                last_error = str(error)
            time.sleep(2)
        if selected_target is None or sample is None:
            raise VerificationError(last_error)

        metric_name, metric_value, metric_labels = sample
        label_discriminator = ",".join(
            f"{key}={value}"
            for key, value in sorted(metric_labels.items())
            if key != "__name__"
        )
        print(
            f"PASS target namespace={target_ns} service={target_svc} health=up "
            f"{target_discriminator(selected_target)}"
        )
        print(
            f"PASS sample metric={metric_name} value={metric_value} "
            f"labels={label_discriminator or '<none>'}"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="command", required=True)
    render = subcommands.add_parser("render-guard")
    render.add_argument("--values", type=Path, required=True)
    render.add_argument(
        "--forbidden-secret", default="ok-observability-credentials"
    )
    live = subcommands.add_parser("live")
    live.add_argument("--namespace", default="ok-observability")
    live.add_argument("--service", default="ok-observability-prometheus")
    live.add_argument("--target-namespace", default="zot")
    live.add_argument("--target-service", default="zot")
    live.add_argument("--metric-regex", default=r"zot_.+")
    live.add_argument("--timeout", type=int, default=180)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "render-guard":
            with arguments.values.open(encoding="utf-8") as stream:
                values = yaml.safe_load(stream) or {}
            if not isinstance(values, dict):
                raise VerificationError("metrics values document is not a mapping")
            documents = [
                document
                for document in yaml.safe_load_all(sys.stdin)
                if document is not None
            ]
            render_guard(documents, values, arguments.forbidden_secret)
        else:
            live_check(
                arguments.namespace,
                arguments.service,
                arguments.target_namespace,
                arguments.target_service,
                arguments.metric_regex,
                arguments.timeout,
            )
    except (OSError, yaml.YAMLError, VerificationError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
