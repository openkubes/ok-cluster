#!/usr/bin/env python3
"""Observe a guarded Talos identity replacement without owning the lifecycle."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


class ReplacementError(RuntimeError):
    """The replacement did not preserve the reviewed runtime contract."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def transient_workload_api_error(detail: str) -> bool:
    return any(
        term in detail.lower()
        for term in (
            "connection refused",
            "was refused",
            "i/o timeout",
            "context deadline exceeded",
            "tls handshake timeout",
            "server was unable to return a response",
        )
    )


def kubectl_json(kubeconfig: Path, arguments: list[str]) -> dict:
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), *arguments, "-o", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ReplacementError(
            f"kubectl read failed: {result.stderr.strip() or result.returncode}"
        )
    return json.loads(result.stdout)


def node_role(node: dict) -> str:
    labels = node.get("metadata", {}).get("labels", {})
    return (
        "control-plane"
        if "node-role.kubernetes.io/control-plane" in labels
        else "worker"
    )


def ready(node: dict) -> bool:
    return any(
        condition.get("type") == "Ready"
        and condition.get("status") == "True"
        for condition in node.get("status", {}).get("conditions", [])
    )


def snapshot(
    management: Path, workload: Path, cluster: str
) -> dict:
    nodes = kubectl_json(workload, ["get", "nodes"]).get("items", [])
    machines = kubectl_json(
        management, ["-n", cluster, "get", "machines"]
    ).get("items", [])
    return {
        "observed_at": now(),
        "nodes": [
            {
                "name": node["metadata"]["name"],
                "uid": node["metadata"]["uid"],
                "role": node_role(node),
                "ready": ready(node),
                "os_image": node.get("status", {})
                .get("nodeInfo", {})
                .get("osImage", ""),
            }
            for node in nodes
        ],
        "machines": [
            {
                "name": machine["metadata"]["name"],
                "uid": machine["metadata"]["uid"],
                "node_ref": machine.get("status", {})
                .get("nodeRef", {})
                .get("name"),
                "phase": machine.get("status", {}).get("phase"),
            }
            for machine in machines
        ],
    }


def signature(value: dict) -> str:
    return json.dumps(
        {"nodes": value["nodes"], "machines": value["machines"]},
        sort_keys=True,
    )


def verify_timeline(
    observations: list[dict],
    old_version: str,
    new_version: str,
    new_identity_short: str,
) -> dict:
    if not observations:
        raise ReplacementError("replacement timeline is empty")
    initial = observations[0]["nodes"]
    old = {
        node["uid"]: node
        for node in initial
        if old_version in node["os_image"]
    }
    if (
        len(old) != 2
        or {node["role"] for node in old.values()}
        != {"control-plane", "worker"}
        or not all(node["ready"] for node in old.values())
        or not all(old_version in node["os_image"] for node in old.values())
    ):
        raise ReplacementError("initial 1+1 old Talos baseline is invalid")
    for observation in observations:
        if not any(
            node["ready"] and node["role"] == "control-plane"
            for node in observation["nodes"]
        ):
            raise ReplacementError(
                "no Ready control-plane Node during replacement"
            )
        current_uids = {node["uid"] for node in observation["nodes"]}
        for uid, old_node in old.items():
            if uid not in current_uids and not any(
                node["ready"]
                and node["role"] == old_node["role"]
                and new_version in node["os_image"]
                for node in observation["nodes"]
            ):
                raise ReplacementError(
                    f"old {old_node['role']} disappeared before replacement"
                )
    final = observations[-1]["nodes"]
    if (
        len(final) != 2
        or {node["role"] for node in final} != {"control-plane", "worker"}
        or not all(node["ready"] for node in final)
        or not all(new_version in node["os_image"] for node in final)
        or not all(new_identity_short in node["name"] for node in final)
        or {node["uid"] for node in final} & set(old)
    ):
        raise ReplacementError("final 1+1 new Talos state is invalid")
    return {
        "old_node_uids": sorted(old),
        "new_node_uids": sorted(node["uid"] for node in final),
        "control_plane_ready_in_every_observation": True,
        "role_replacement_ready_before_old_absent": True,
    }


def write_evidence(path: Path, evidence: dict) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--management-kubeconfig", required=True)
    parser.add_argument("--workload-kubeconfig", required=True)
    parser.add_argument("--old-version", required=True)
    parser.add_argument("--new-version", required=True)
    parser.add_argument("--new-identity-short", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--max-api-unavailable-seconds", type=float, default=120)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        raise ReplacementError("lifecycle command is required")
    management = Path(args.management_kubeconfig).expanduser().resolve()
    workload = Path(args.workload_kubeconfig).expanduser().resolve()
    if not management.is_file() or not workload.is_file():
        raise ReplacementError("explicit kubeconfigs are required")

    observations = [snapshot(management, workload, args.cluster)]
    api_unavailable_windows: list[dict] = []
    active_api_window: dict | None = None
    process = subprocess.Popen(args.command)
    deadline = time.monotonic() + args.timeout_seconds
    last = signature(observations[-1])
    while time.monotonic() < deadline:
        try:
            current = snapshot(management, workload, args.cluster)
        except ReplacementError as error:
            detail = str(error)
            if not transient_workload_api_error(detail):
                process.terminate()
                raise
            if active_api_window is None:
                active_api_window = {
                    "started_at": now(),
                    "started_monotonic": time.monotonic(),
                    "samples": 0,
                    "last_error": detail,
                }
            active_api_window["samples"] += 1
            active_api_window["last_error"] = detail
            if process.poll() not in (None, 0):
                raise ReplacementError(
                    f"lifecycle command exited {process.returncode}"
                )
            time.sleep(2)
            continue
        if active_api_window is not None:
            ended_monotonic = time.monotonic()
            api_unavailable_windows.append(
                {
                    "started_at": active_api_window["started_at"],
                    "ended_at": now(),
                    "duration_seconds": round(
                        ended_monotonic
                        - active_api_window["started_monotonic"],
                        3,
                    ),
                    "samples": active_api_window["samples"],
                    "last_error": active_api_window["last_error"],
                }
            )
            active_api_window = None
        current_signature = signature(current)
        if current_signature != last:
            observations.append(current)
            last = current_signature
        final_nodes = current["nodes"]
        converged = (
            len(final_nodes) == 2
            and all(node["ready"] for node in final_nodes)
            and all(args.new_version in node["os_image"] for node in final_nodes)
            and all(
                args.new_identity_short in node["name"] for node in final_nodes
            )
        )
        if process.poll() is not None and converged:
            break
        if process.poll() not in (None, 0):
            raise ReplacementError(
                f"lifecycle command exited {process.returncode}"
            )
        time.sleep(2)
    else:
        raise ReplacementError("replacement timed out")
    if process.wait() != 0:
        raise ReplacementError(f"lifecycle command exited {process.returncode}")
    if signature(observations[-1]) != current_signature:
        observations.append(current)
    proof = verify_timeline(
        observations,
        args.old_version,
        args.new_version,
        args.new_identity_short,
    )
    max_api_unavailable = max(
        (
            window["duration_seconds"]
            for window in api_unavailable_windows
        ),
        default=0,
    )
    continuity_passed = not api_unavailable_windows
    within_guard = max_api_unavailable <= args.max_api_unavailable_seconds
    evidence = {
        "schema": "openkubes.ok130.talos-replacement/v2",
        "status": (
            "PASS"
            if continuity_passed
            else (
                "PASS_WITH_TRANSIENT_API_INTERRUPTION"
                if within_guard
                else "FAIL_API_UNAVAILABLE_TOO_LONG"
            )
        ),
        "cluster": args.cluster,
        "old_version": args.old_version,
        "new_version": args.new_version,
        "new_identity_short": args.new_identity_short,
        "command": args.command,
        "completed_at": now(),
        "proof": proof,
        "api_continuity": {
            "passed": continuity_passed,
            "maximum_allowed_unavailable_seconds": (
                args.max_api_unavailable_seconds
            ),
            "maximum_observed_unavailable_seconds": max_api_unavailable,
            "windows": api_unavailable_windows,
        },
        "observations": observations,
        "public_import_count": 0,
        "secret_values_recorded": False,
    }
    output = Path(args.output)
    write_evidence(output, evidence)
    print(f"{evidence['status']} Talos replacement evidence: {output.resolve()}")
    return 0 if within_guard else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReplacementError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL Talos replacement: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
