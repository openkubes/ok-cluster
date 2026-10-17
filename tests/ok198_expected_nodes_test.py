#!/usr/bin/env python3
"""Offline CLI tests for OK-198 expected-node readiness."""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "talos_golden_lifecycle.py"
CLUSTER = "ok198-test"
CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((bool(condition), message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json
import os
import sys
import time

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(["kubectl", *args]) + "\n")

scenario_path = os.environ["FAKE_SCENARIO"]
with open(scenario_path, encoding="utf-8") as stream:
    scenario = json.load(stream)

if scenario.get("hang"):
    time.sleep(60)
if scenario.get("api_failure"):
    sys.stderr.write("Error from server (Forbidden): expected-node test denial\n")
    sys.exit(1)

kubeconfig = args[args.index("--kubeconfig") + 1]
filtered = list(args)
del filtered[filtered.index("--kubeconfig"):filtered.index("--kubeconfig") + 2]
resource = ""
if "get" in filtered:
    index = filtered.index("get")
    if index + 1 < len(filtered):
        resource = filtered[index + 1].lower()

if resource in ("node", "nodes") and "-o" not in filtered:
    print("cp-0 Ready control-plane")
    sys.exit(0)

kind = "machines" if "machine" in resource else "nodes" if resource in ("node", "nodes") else ""
if not kind:
    sys.stderr.write("unsupported fake kubectl request: " + " ".join(args) + "\n")
    sys.exit(2)

if kind == "machines" and os.path.realpath(kubeconfig) != scenario["management_kubeconfig"]:
    sys.stderr.write("machines queried with the wrong kubeconfig\n")
    sys.exit(2)
if kind == "nodes" and os.path.realpath(kubeconfig) != scenario["workload_kubeconfig"]:
    sys.stderr.write("nodes queried with the wrong kubeconfig\n")
    sys.exit(2)

state_path = scenario["counter_path"]
try:
    with open(state_path, encoding="utf-8") as stream:
        counters = json.load(stream)
except FileNotFoundError:
    counters = {"machines": 0, "nodes": 0}

index = counters[kind]
counters[kind] += 1
temporary = state_path + ".tmp"
with open(temporary, "w", encoding="utf-8") as stream:
    json.dump(counters, stream)
os.replace(temporary, state_path)

phases = scenario["phases"]
phase = phases[min(index, len(phases) - 1)]
if phase.get("hang"):
    time.sleep(60)
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": phase[kind]}))
'''


def condition(ready: bool) -> list[dict[str, str]]:
    return [{"type": "Ready", "status": "True" if ready else "False"}]


def node(name: str, ready: bool = True, *, deleting: bool = False) -> dict:
    metadata: dict[str, str] = {"name": name}
    if deleting:
        metadata["deletionTimestamp"] = "2026-10-12T00:00:00Z"
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": metadata,
        "status": {"conditions": condition(ready)},
    }


def machine(
    name: str,
    role: str,
    node_name: str | None = None,
    *,
    deployment: str = "workers-a",
    deleting: bool = False,
    failed: bool = False,
) -> dict:
    labels = {"cluster.x-k8s.io/cluster-name": CLUSTER}
    if role == "control-plane":
        labels["cluster.x-k8s.io/control-plane"] = ""
    else:
        labels["cluster.x-k8s.io/deployment-name"] = deployment
    metadata: dict[str, object] = {"name": name, "namespace": CLUSTER, "labels": labels}
    if deleting:
        metadata["deletionTimestamp"] = "2026-10-12T00:00:00Z"
    status: dict[str, object] = {}
    if node_name is not None:
        status["nodeRef"] = {"name": node_name}
    if failed:
        status.update({"phase": "Failed", "failureReason": "test failure"})
    return {
        "apiVersion": "cluster.x-k8s.io/v1beta1",
        "kind": "Machine",
        "metadata": metadata,
        "spec": {"clusterName": CLUSTER},
        "status": status,
    }


class Sandbox:
    def __init__(
        self,
        base: Path,
        control_planes: int = 1,
        deployments: tuple[tuple[str, int], ...] = (("workers-a", 1),),
    ) -> None:
        self.base = base
        self.bin = base / "bin"
        self.cluster_dir = base / CLUSTER
        self.management = base / "management.kubeconfig"
        self.workload = base / "workload.kubeconfig"
        self.log = base / "calls.jsonl"
        self.scenario = base / "scenario.json"
        self.counter = base / "counter.json"
        self.bin.mkdir(parents=True)
        self.cluster_dir.mkdir()
        self.management.write_text("# fake management kubeconfig\n", encoding="utf-8")
        self.workload.write_text("# fake workload kubeconfig\n", encoding="utf-8")
        self.log.write_text("", encoding="utf-8")
        executable = self.bin / "kubectl"
        executable.write_text(FAKE_KUBECTL, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        self.render(control_planes, deployments)

    def render(
        self,
        control_planes: int,
        deployments: tuple[tuple[str, int], ...],
    ) -> None:
        documents: list[dict] = [
            {
                "apiVersion": "cluster.x-k8s.io/v1beta1",
                "kind": "Cluster",
                "metadata": {"name": CLUSTER, "namespace": CLUSTER},
                "spec": {
                    "controlPlaneRef": {
                        "apiGroup": "controlplane.cluster.x-k8s.io",
                        "kind": "TalosControlPlane",
                        "name": f"{CLUSTER}-control-plane",
                        "namespace": CLUSTER,
                    }
                },
            },
            {
                "apiVersion": "controlplane.cluster.x-k8s.io/v1alpha3",
                "kind": "TalosControlPlane",
                "metadata": {"name": f"{CLUSTER}-control-plane", "namespace": CLUSTER},
                "spec": {"replicas": control_planes},
            },
        ]
        documents.extend(
            {
                "apiVersion": "cluster.x-k8s.io/v1beta1",
                "kind": "MachineDeployment",
                "metadata": {"name": name, "namespace": CLUSTER},
                "spec": {"clusterName": CLUSTER, "replicas": replicas},
            }
            for name, replicas in deployments
        )
        (self.cluster_dir / "cluster-base.yaml").write_text(
            yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8"
        )

    def run(
        self,
        phases: list[dict[str, list[dict]]],
        *,
        timeout: float = 2.6,
        poll: float = 0.02,
        process_timeout: float = 5.0,
        api_failure: bool = False,
        hang: bool = False,
    ) -> subprocess.CompletedProcess[str] | None:
        self.log.write_text("", encoding="utf-8")
        self.counter.unlink(missing_ok=True)
        self.scenario.write_text(
            json.dumps({
                "management_kubeconfig": str(self.management.resolve()),
                "workload_kubeconfig": str(self.workload.resolve()),
                "counter_path": str(self.counter),
                "phases": phases,
                "api_failure": api_failure,
                "hang": hang,
            }),
            encoding="utf-8",
        )
        command = [
            sys.executable,
            str(SCRIPT),
            "--wait-expected-nodes",
            "--cluster-dir", str(self.cluster_dir),
            "--cluster", CLUSTER,
            "--kubeconfig", str(self.management),
            "--workload-kubeconfig", str(self.workload),
            "--ok-linux-path", str(ROOT.parent / "ok-linux"),
            "--expected-nodes-timeout-seconds", str(timeout),
            "--expected-nodes-poll-seconds", str(poll),
        ]
        try:
            return subprocess.run(
                command,
                env={
                    **os.environ,
                    "PATH": f"{self.bin}:{os.environ['PATH']}",
                    "FAKE_LOG": str(self.log),
                    "FAKE_SCENARIO": str(self.scenario),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=process_timeout,
            )
        except subprocess.TimeoutExpired:
            return None

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def make_failure(self, phase: dict[str, list[dict]]) -> subprocess.CompletedProcess[str]:
        fake_make = self.bin / "make"
        fake_make.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_make.chmod(0o755)
        self.scenario.write_text(
            json.dumps({
                "management_kubeconfig": str(self.management.resolve()),
                "workload_kubeconfig": str(self.workload.resolve()),
                "counter_path": str(self.counter),
                "phases": [phase],
                "api_failure": False,
                "hang": False,
            }),
            encoding="utf-8",
        )
        self.counter.unlink(missing_ok=True)
        return subprocess.run(
            [
                "/usr/bin/make", "-C", str(ROOT), "--no-print-directory",
                "bootstrap-post-apply", f"CLUSTER={CLUSTER}",
                f"MAKE={fake_make}",
                f"CLUSTERS_DIR={self.base}",
                f"TALOS_INFRA_KUBECONFIG={self.management}",
                f"GUEST_KUBECONFIG_DIR={self.base}",
                f"OK_LINUX_PATH={ROOT.parent / 'ok-linux'}",
                "TALOS_EXPECTED_NODES_TIMEOUT_SECONDS=2.3",
                "TALOS_EXPECTED_NODES_POLL_SECONDS=0.05",
            ],
            env={
                **os.environ,
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "FAKE_LOG": str(self.log),
                "FAKE_SCENARIO": str(self.scenario),
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )


def ready_phase(control_planes: int, deployments: tuple[tuple[str, int], ...]) -> dict:
    machines: list[dict] = []
    nodes: list[dict] = []
    for index in range(control_planes):
        name = f"cp-{index}"
        machines.append(machine(f"machine-{name}", "control-plane", name))
        nodes.append(node(name))
    for deployment, replicas in deployments:
        for index in range(replicas):
            name = f"{deployment}-{index}"
            machines.append(machine(f"machine-{name}", "worker", name, deployment=deployment))
            nodes.append(node(name))
    return {"machines": machines, "nodes": nodes}


def successful(result: subprocess.CompletedProcess[str] | None) -> bool:
    return bool(
        result is not None
        and result.returncode == 0
        and "READY all expected nodes are registered and Ready" in result.stdout
    )


def positive_tests(base: Path) -> None:
    single = Sandbox(base / "single")
    result = single.run([ready_phase(1, (("workers-a", 1),))])
    calls = single.calls()
    check(successful(result), "single control-plane and worker become Ready")
    check(
        any("machine" in " ".join(call).lower() for call in calls)
        and any("nodes" in call or "node" in call for call in calls),
        "readiness queries both management Machines and workload Nodes",
    )

    ha = Sandbox(base / "ha", control_planes=3, deployments=(("workers-a", 2),))
    result = ha.run([ready_phase(3, (("workers-a", 2),))])
    check(successful(result), "three control-plane and two worker HA render becomes Ready")

    late = Sandbox(base / "late")
    phase0 = ready_phase(1, ())
    phase1 = ready_phase(1, ())
    phase1["machines"].append(machine("machine-worker", "worker", "worker-0"))
    phase1["nodes"].append(node("worker-0", False))
    phase2 = ready_phase(1, ())
    phase2["machines"].append(machine("machine-worker", "worker", "worker-0"))
    phase2["nodes"].append(node("worker-0", True))
    result = late.run([phase0, phase0, phase1, phase1, phase2], timeout=2.8)
    counters = json.loads(late.counter.read_text(encoding="utf-8"))
    check(
        successful(result) and counters["machines"] >= 3 and counters["nodes"] >= 3,
        "late worker is observed missing, NotReady, then Ready before success",
    )

    lines = [] if result is None else [
        line for line in result.stdout.splitlines() if line.startswith("role=")
    ]
    check(
        len(lines) == 6
        and sum("role=worker/workers-a expected=1 registered=0" in line for line in lines) == 1
        and sum("role=worker/workers-a expected=1 registered=1 ready=0" in line for line in lines) == 1
        and sum("role=worker/workers-a expected=1 registered=1 ready=1" in line for line in lines) == 1,
        "progress prints one line per role only when the complete snapshot changes",
    )

    deployments = (("gpu-workers", 1), ("general-workers", 2))
    multiple = Sandbox(base / "multiple", deployments=deployments)
    result = multiple.run([ready_phase(1, deployments)])
    check(successful(result), "all rendered MachineDeployments are independently required")

    zero_workers = Sandbox(base / "zero-workers", deployments=(("workers-a", 0),))
    result = zero_workers.run([ready_phase(1, (("workers-a", 0),))])
    check(successful(result), "zero-replica worker profile succeeds with its control plane Ready")


def missing_worker_test(base: Path) -> None:
    missing = Sandbox(base / "missing")
    phase = ready_phase(1, ())
    started = time.monotonic()
    result = missing.run([phase], timeout=2.6, poll=0.03, process_timeout=5.0)
    elapsed = time.monotonic() - started
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0 and elapsed < 5.0
        and "role=worker/workers-a expected=1 registered=0 ready=0" in stderr
        and "machines_not_created=1" in stderr,
        "missing worker times out boundedly with named-role counts and Machines not created",
    )
    check(
        result is not None
        and "READY all expected nodes" not in result.stdout + result.stderr,
        "timeout never emits readiness success",
    )

    check(
        stderr.startswith("FAIL timed out waiting for expected nodes: worker/workers-a: 0 of 1 expected nodes registered;")
        and "management API:" not in stderr and "workload API:" not in stderr,
        "complete missing-worker snapshot leads with shortfall without an API-error cause",
    )
    final_timeout = Sandbox(base / "final-poll-timeout", deployments=(("workers-a", 2),))
    result = final_timeout.run(
        [ready_phase(1, (("workers-a", 1),)), {"hang": True}],
        timeout=2.8, poll=0.03, process_timeout=5.0,
    )
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and stderr.startswith("FAIL timed out waiting for expected nodes: worker/workers-a: 1 of 2 expected nodes registered;")
        and "machines_not_created=1" in stderr
        and "role=control-plane expected=1 registered=1 ready=1" in stderr
        and "; last API error: management API:" in stderr and "timed out after" in stderr,
        "final poll timeout preserves the last complete worker shortfall as the leading cause",
    )

    no_ref = Sandbox(base / "named-no-node-ref")
    phase = ready_phase(1, ())
    phase["machines"].append(machine("worker-without-node", "worker"))
    result = no_ref.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "missing_nodes=[worker-without-node]" in stderr,
        "registered Machine without nodeRef is named in timeout diagnostics",
    )


def identity_test(base: Path) -> None:
    unrelated = Sandbox(base / "unrelated")
    phase = ready_phase(1, ())
    phase["machines"].append(machine("machine-worker", "worker", "expected-worker"))
    phase["nodes"].append(node("unrelated-ready"))
    result = unrelated.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "missing_nodes=[expected-worker]" in stderr
        and "ready=0" in stderr,
        "unrelated Ready Node cannot satisfy a Machine identity",
    )


def not_ready_test(base: Path) -> None:
    not_ready = Sandbox(base / "not-ready-cp", deployments=())
    phase = ready_phase(1, ())
    phase["nodes"] = [node("cp-0", False)]
    result = not_ready.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "role=control-plane expected=1 registered=1 ready=0" in stderr
        and "not_ready_nodes=[cp-0]" in stderr,
        "registered NotReady control plane cannot satisfy readiness",
    )


def inactive_test(base: Path) -> None:
    inactive = Sandbox(base / "inactive")
    phase = ready_phase(1, ())
    phase["machines"].extend([
        machine("deleting-worker", "worker", "deleted-node", deleting=True),
        machine("failed-worker", "worker", "failed-node", failed=True),
    ])
    phase["nodes"].extend([node("deleted-node"), node("failed-node")])
    result = inactive.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "role=worker/workers-a expected=1 registered=0 ready=0" in stderr
        and "deleting-worker(deleting)" in stderr
        and "failed-worker(failed)" in stderr,
        "deleting and failed Machines do not satisfy expected replicas",
    )


def duplicate_test(base: Path) -> None:
    duplicate = Sandbox(base / "duplicate")
    phase = ready_phase(1, ())
    phase["machines"].extend([
        machine("worker-a", "worker", "shared-node"),
        machine("worker-b", "worker", "shared-node"),
    ])
    phase["nodes"].append(node("shared-node"))
    result = duplicate.run([phase])
    combined = "" if result is None else result.stdout + result.stderr
    check(
        result is not None and result.returncode != 0 and "shared-node" in combined
        and "duplicate" in combined.lower(),
        "duplicate Machine nodeRef identity fails closed",
    )


def api_error_test(base: Path) -> None:
    api = Sandbox(base / "api-error")
    result = api.run(
        [ready_phase(1, (("workers-a", 1),))],
        timeout=2.6,
        poll=0.03,
        api_failure=True,
    )
    combined = "" if result is None else result.stdout + result.stderr
    check(
        result is not None and result.returncode != 0
        and "FAIL timed out waiting for expected nodes: management API:" in combined
        and "expected-node test denial" in combined,
        "management or workload API errors remain actionable at timeout",
    )

    insufficient = Sandbox(base / "insufficient-poll-budget")
    result = insufficient.run([ready_phase(1, ())], timeout=1.0)
    check(
        result is not None and result.returncode != 0 and not insufficient.calls()
        and "API snapshot was not completed" in result.stderr,
        "less than two seconds of remaining budget starts no API poll",
    )

    hung = Sandbox(base / "hung-kubectl")
    started = time.monotonic()
    result = hung.run(
        [ready_phase(1, (("workers-a", 1),))],
        timeout=2.6,
        poll=0.03,
        process_timeout=5.0,
        hang=True,
    )
    combined = "" if result is None else result.stdout + result.stderr
    check(
        result is not None and result.returncode != 0
        and time.monotonic() - started < 5.0 and "timed out" in combined,
        "hung kubectl is killed within the overall expected-node deadline",
    )


def multiple_deployment_deficiency_test(base: Path) -> None:
    deployments = (("gpu-workers", 1), ("general-workers", 1))
    box = Sandbox(base, deployments=deployments)
    phase = ready_phase(1, (("gpu-workers", 1),))
    result = box.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "role=worker/general-workers expected=1 registered=0 ready=0" in stderr,
        "one Ready MachineDeployment cannot hide a deficient peer deployment",
    )


def surplus_test(base: Path) -> None:
    box = Sandbox(base)
    phase = ready_phase(1, (("workers-a", 2),))
    result = box.run([phase], timeout=2.6, poll=0.03)
    stderr = result.stderr if result is not None else ""
    check(
        result is not None and result.returncode != 0
        and "role=worker/workers-a expected=1 registered=2 ready=2" in stderr,
        "surplus active workers cannot satisfy the exact rendered replica contract",
    )


def negative_tests(base: Path) -> None:
    missing_worker_test(base / "missing-worker")
    identity_test(base / "identity")
    not_ready_test(base / "not-ready")
    inactive_test(base / "inactive-machine")
    duplicate_test(base / "duplicate-ref")
    api_error_test(base / "api-error")
    multiple_deployment_deficiency_test(base / "multiple-deficiency")
    surplus_test(base / "surplus")


def validation_and_make_tests(base: Path) -> None:
    malformed = Sandbox(base / "malformed")
    (malformed.cluster_dir / "cluster-base.yaml").write_text(
        "apiVersion: v1\nkind: Cluster\nspec: [\n", encoding="utf-8"
    )
    result = malformed.run([{"machines": [], "nodes": []}])
    check(
        result is not None and result.returncode != 0 and not malformed.calls(),
        "malformed rendered YAML fails before API access",
    )

    integration = Sandbox(base / "make")
    phase = ready_phase(1, ())
    result = integration.make_failure(phase)
    check(
        result.returncode != 0
        and "Talos cluster ok198-test bootstrapped with Cilium" not in result.stdout,
        "bootstrap-post-apply suppresses its success line when expected-node wait fails",
    )

    invalid = Sandbox(base / "invalid-time")
    result = invalid.run([ready_phase(1, (("workers-a", 1),))], timeout=math.nan)
    check(
        result is not None and result.returncode != 0 and not invalid.calls(),
        "non-finite expected-node timeout is rejected before API access",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        choices=(
            "positive", "count-only", "ignore-worker", "not-ready",
            "timeout", "edge", "validation", "surplus",
        ),
        help="run one mutation discriminator instead of the complete module",
    )
    args = parser.parse_args()
    base = Path(tempfile.mkdtemp(prefix="ok198-"))
    try:
        cases = {
            "positive": lambda: positive_tests(base / "positive"),
            "surplus": lambda: surplus_test(base / "surplus"),
            "count-only": lambda: identity_test(base / "count-only"),
            "ignore-worker": lambda: missing_worker_test(base / "ignore-worker"),
            "not-ready": lambda: not_ready_test(base / "not-ready"),
            "timeout": lambda: missing_worker_test(base / "timeout"),
            "edge": lambda: (
                inactive_test(base / "inactive"),
                duplicate_test(base / "duplicate"),
                api_error_test(base / "api-error"),
                multiple_deployment_deficiency_test(base / "multiple-deficiency"),
            ),
            "validation": lambda: validation_and_make_tests(base / "validation"),
        }
        if args.case:
            cases[args.case]()
        else:
            positive_tests(base / "positive")
            negative_tests(base / "negative")
            validation_and_make_tests(base / "validation")
    except Exception as error:
        print(f"FAIL OK-198 harness error: {error}", file=sys.stderr)
        return_code = 1
    else:
        failed = [message for condition, message in CHECKS if not condition]
        if failed:
            print(f"FAIL {len(failed)} OK-198 checks failed", file=sys.stderr)
            return_code = 1
        else:
            return_code = 0
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if return_code:
        return return_code
    print(f"PASS all {len(CHECKS)} OK-198 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
