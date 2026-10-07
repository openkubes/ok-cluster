#!/usr/bin/env python3
"""Offline tests for the OK-186 Talos lifecycle hardening.

Runs the real Makefile targets against fake kubectl/clusterctl/helm binaries,
with HOME pointing at an empty directory so the default ~/.kube files are
absent, and exercises the clone-RBAC teardown cleanup with mocked kubectl.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ok130-talos" / "cluster-config.yaml"
CLUSTER = "ok130-talos"
sys.path.insert(0, str(ROOT))

from scripts import talos_golden_lifecycle as lifecycle  # noqa: E402


CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((bool(condition), message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


FAKE_KUBECTL = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["kubectl", *args]) + "\n")
if "get" in args and "clusters.cluster.x-k8s.io" in args:
    mode = os.environ.get("FAKE_CLUSTER", "present")
    if mode == "absent":
        sys.stderr.write('Error from server (NotFound): clusters.cluster.x-k8s.io "x" not found\n')
        sys.exit(1)
    if mode == "forbidden":
        sys.stderr.write("Error from server (Forbidden): clusters is forbidden\n")
        sys.exit(1)
    print("cluster.cluster.x-k8s.io/x")
elif any("volumeName" in arg for arg in args):
    if not os.environ.get("FAKE_NAMESPACE_GONE"):
        print("pv-1")
elif any(".metadata.uid" in arg for arg in args):
    if not os.environ.get("FAKE_NAMESPACE_GONE"):
        print("uid-1,", end="")
elif "get" in args and "pvc" in args:
    print("cp-0 Bound")
elif "get" in args and "dv" in args:
    print("cp-0 Succeeded\nworker-0 Succeeded")
elif "get" in args and "nodes" in args:
    if any("osImage" in arg for arg in args):
        print("Talos (v1.9.6)")
    else:
        print("cp-0 Ready control-plane")
"""

FAKE_CLUSTERCTL = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["clusterctl", *sys.argv[1:]]) + "\n")
if os.environ.get("FAKE_CLUSTERCTL") == "fail":
    sys.stderr.write("Error: failed to get kubeconfig: secret not found\n")
    sys.exit(1)
print("apiVersion: v1\nkind: Config\nclusters: []")
"""

FAKE_LIFECYCLE = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["talos_golden_lifecycle", *sys.argv[1:]]) + "\n")
if os.environ.get("FAKE_CLEANUP") == "fail":
    sys.stderr.write("role read failed: Error from server (Forbidden)\n")
    sys.exit(1)
print("PASS clone RBAC (fake)")
"""

FAKE_HELM = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["helm", *sys.argv[1:]]) + "\n")
"""


class Sandbox:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.home = base / "home"
        self.bin = base / "bin"
        self.clusters = base / "clusters"
        self.out = base / "out"
        self.infra = base / "mgmt" / "infra.yaml"
        self.log = base / "calls.jsonl"
        for directory in (self.home, self.bin, self.clusters / CLUSTER, self.infra.parent):
            directory.mkdir(parents=True)
        shutil.copy(FIXTURE, self.clusters / CLUSTER / "cluster-config.yaml")
        (self.clusters / CLUSTER / "cluster-base.yaml").write_text("# fixture\n")
        self.infra.write_text("# fake management kubeconfig\n")
        for name, body in (
            ("kubectl", FAKE_KUBECTL),
            ("clusterctl", FAKE_CLUSTERCTL),
            ("helm", FAKE_HELM),
        ):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)

    def make(self, *targets: str, dry_run: bool = False, **env: str):
        self.log.write_text("")
        command = [
            "make", "-C", str(ROOT), "--no-print-directory",
            *(["-n"] if dry_run else []),
            *targets,
            f"CLUSTER={CLUSTER}",
            f"CLUSTERS_DIR={self.clusters}",
            f"TALOS_INFRA_KUBECONFIG={self.infra}",
            f"GUEST_KUBECONFIG_DIR={self.out}",
        ]
        result = subprocess.run(
            command,
            env={
                **os.environ,
                "HOME": str(self.home),
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "FAKE_LOG": str(self.log),
                **env,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls


def kubeconfig_args(calls: list[list[str]]) -> set[str]:
    return {
        call[call.index("--kubeconfig") + 1]
        for call in calls
        if "--kubeconfig" in call
    }


def make_tests(box: Sandbox) -> None:
    guest = box.out / f"{CLUSTER}.yaml"

    # Overrides are honoured with the default ~/.kube files absent.
    result, calls = box.make("kubeconfig")
    check(
        result.returncode == 0 and guest.is_file()
        and "kind: Config" in guest.read_text(),
        "kubeconfig writes the guest kubeconfig to GUEST_KUBECONFIG_DIR",
    )
    check(
        guest.is_file() and stat.S_IMODE(guest.stat().st_mode) == 0o600,
        "guest kubeconfig is written with mode 0600",
    )
    check(
        kubeconfig_args(calls) == {str(box.infra)},
        "clusterctl reads the management kubeconfig from TALOS_INFRA_KUBECONFIG",
    )
    check(
        not any(box.home.iterdir()),
        "nothing is read from or written to the default ~/.kube",
    )

    # A clusterctl failure is visible, fails the target and keeps the old file.
    guest.write_text("previous\n")
    result, _ = box.make("kubeconfig", FAKE_CLUSTERCTL="fail")
    check(
        result.returncode != 0 and "secret not found" in result.stderr,
        "kubeconfig failure exits non-zero and shows the clusterctl error",
    )
    check(
        guest.read_text() == "previous\n"
        and not list(box.out.glob(f".{CLUSTER}.yaml.*")),
        "a failed kubeconfig leaves the previous file and no temp file behind",
    )

    # bootstrap-resume refuses without a Cluster object, before touching anything.
    for mode, message in (("absent", "NotFound"), ("forbidden", "Forbidden")):
        result, calls = box.make("bootstrap-resume", FAKE_CLUSTER=mode)
        check(
            result.returncode != 0
            and "not found on the management cluster" in result.stdout
            and message in result.stdout
            and not any("annotate" in call for call in calls)
            and not any(call[0] == "clusterctl" for call in calls),
            f"bootstrap-resume refuses when the Cluster read fails ({mode})",
        )

    # bootstrap-resume runs only the post-apply steps.
    result, calls = box.make("bootstrap-resume", dry_run=True)
    resume_plan = result.stdout
    result, control = box.make("bootstrap", dry_run=True)
    bootstrap_plan = result.stdout
    check(
        "cluster-base.yaml" in bootstrap_plan
        and "talos_golden_lifecycle.py" in bootstrap_plan,
        "control: bootstrap plan applies cluster-base and runs the golden preflight",
    )
    check(
        "cluster-base.yaml" not in resume_plan
        and "talos_golden_lifecycle.py" not in resume_plan
        and "annotate pvc" in resume_plan
        and "get kubeconfig" in resume_plan
        and "helm upgrade --install cilium" in resume_plan
        and "wait --for=condition=Ready nodes" in resume_plan,
        "bootstrap-resume plan: annotate, kubeconfig, Cilium, wait; no apply, no preflight",
    )

    chart = ROOT / ".tools" / "cilium-1.19.6.tgz"
    if not chart.is_file():
        check(False, "bootstrap-resume live-fake run needs `make prepare-cilium-chart`")
        return
    guest.unlink()
    result, calls = box.make("bootstrap-resume")
    check(
        result.returncode == 0
        and not any("apply" in call for call in calls)
        and any("annotate" in call for call in calls)
        and any(call[:2] == ["helm", "upgrade"] for call in calls)
        and any("wait" in call for call in calls),
        "bootstrap-resume completes with fakes and never calls kubectl apply",
    )
    check(
        kubeconfig_args(calls) == {str(box.infra), str(guest)}
        and not any(box.home.iterdir()),
        "bootstrap-resume uses only the overridden kubeconfig paths",
    )


def make_defaults() -> None:
    result = subprocess.run(
        ["make", "-C", str(ROOT), "--no-print-directory", "-n", "kubeconfig",
         f"CLUSTER={CLUSTER}"],
        env={**os.environ, "HOME": "/home/ok186"},
        capture_output=True, text=True, check=False,
    )
    check(
        '--kubeconfig "/home/ok186/.kube/ok-infra.yaml"' in result.stdout
        and 'mv -f "$tmp" "/home/ok186/.kube/ok130-talos.yaml"' in result.stdout,
        "defaults unchanged: ~/.kube/ok-infra.yaml in, ~/.kube/<cluster>.yaml out",
    )


def cleanup_tests() -> None:
    config = {
        "name": CLUSTER,
        "os": {
            "identity": "sha256:" + "a" * 64,
            "goldenImage": {"namespace": "ok-golden", "claim": "golden"},
        },
    }
    owned = {
        "metadata": {
            "labels": {
                "openkubes.io/type": "talos",
                "openkubes.io/consumer-cluster": CLUSTER,
                "openkubes.io/os-identity": "a" * 12,
            }
        }
    }

    def run(responses: dict[str, tuple[int, str, str]]):
        deletes: list[str] = []

        def fake_kubectl(_kubeconfig, arguments, expected=(0,)):
            verb, kind = arguments[2], arguments[3]
            if verb == "delete":
                deletes.append(kind)
                return subprocess.CompletedProcess(arguments, 0, "", "")
            code, out, err = responses[kind]
            if code not in expected:
                raise lifecycle.TalosLifecycleError(err)
            return subprocess.CompletedProcess(arguments, code, out, err)

        args = argparse.Namespace(data_volume_uids="")
        with mock.patch.object(lifecycle, "inputs", return_value=(config, Path("m"), Path("k"))), \
             mock.patch.object(lifecycle, "validate_manifest"), \
             mock.patch.object(lifecycle, "verify_golden", return_value={"uid": "g"}), \
             mock.patch.object(lifecycle, "kubectl", side_effect=fake_kubectl):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                try:
                    code = lifecycle.cleanup_authorization(args)
                except lifecycle.TalosLifecycleError as error:
                    return "error", str(error), deletes
            return code, stdout.getvalue(), deletes

    not_found = (1, "", 'Error from server (NotFound): roles "x" not found')
    present = (0, json.dumps(owned), "")

    code, out, deletes = run({"role": not_found, "rolebinding": not_found})
    check(
        code == 0 and out.count("SKIP") == 2 and "FAIL" not in out and not deletes,
        "second teardown: already-absent clone RBAC is a SKIP with exit 0",
    )
    code, out, deletes = run({"role": present, "rolebinding": not_found})
    check(
        code == 0 and deletes == ["role"] and "already_absent=['rolebinding']" in out,
        "partial teardown: deletes what remains, skips what is gone",
    )
    code, out, deletes = run({"role": present, "rolebinding": present})
    check(
        code == 0 and deletes == ["rolebinding", "role"],
        "first teardown: deletes both RoleBinding and Role",
    )
    code, out, deletes = run(
        {"role": (1, "", "Error from server (Forbidden): roles is forbidden"),
         "rolebinding": present}
    )
    check(
        code == "error" and "Forbidden" in out and not deletes,
        "a real read error fails the cleanup and deletes nothing",
    )


def teardown_tests(box: Sandbox) -> None:
    """Run the real teardown recipe with the lifecycle script replaced by a fake."""
    scripts = box.base / "script-dir" / "scripts"
    scripts.mkdir(parents=True)
    fake = scripts / "talos_golden_lifecycle.py"
    fake.write_text(FAKE_LIFECYCLE)
    rendered = box.clusters / CLUSTER
    config = yaml.safe_load((rendered / "cluster-config.yaml").read_text())
    config["os"]["goldenImage"] = {"namespace": "ok-golden", "claim": "golden"}
    (rendered / "cluster-config.yaml").write_text(yaml.safe_dump(config))
    script_dir = f"SCRIPT_DIR={box.base / 'script-dir'}"

    def cleanup_calls(calls):
        return [call for call in calls if call[0] == "talos_golden_lifecycle"]

    result, calls = box.make("teardown", script_dir, CONFIRM="yes", FAKE_CLEANUP="fail")
    check(
        result.returncode != 0
        and "incomplete" in result.stdout
        and rendered.is_dir()
        and (rendered / ".teardown-data-volume-uids").read_text() == "uid-1,"
        and any(call[-3:-1] == ["pv", "pv-1"] for call in calls),
        "failed cleanup: exit non-zero, render dir and DataVolume UIDs kept, PVs still cleaned",
    )
    result, calls = box.make("teardown", script_dir, CONFIRM="yes", FAKE_NAMESPACE_GONE="1")
    retry = cleanup_calls(calls)
    check(
        result.returncode == 0
        and len(retry) == 1
        and retry[0][retry[0].index("--data-volume-uids") + 1] == "uid-1,"
        and not rendered.exists(),
        "retry after namespace deletion reuses the saved DataVolume UIDs and completes",
    )
    result, calls = box.make("teardown", script_dir, CONFIRM="yes", FAKE_NAMESPACE_GONE="1")
    check(
        result.returncode == 0
        and "SKIP local render directory" in result.stdout
        and "Traceback" not in result.stderr
        and not cleanup_calls(calls),
        "teardown with the render dir already gone: SKIP, exit 0, no traceback",
    )


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="ok186-"))
    make_tests(Sandbox(base))
    teardown_tests(Sandbox(base / "teardown"))
    make_defaults()
    cleanup_tests()
    failed = [message for condition, message in CHECKS if not condition]
    if failed:
        print(f"FAIL {len(failed)} OK-186 checks failed; sandbox kept at {base}",
              file=sys.stderr)
        return 1
    shutil.rmtree(base)
    print(f"PASS all {len(CHECKS)} OK-186 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
