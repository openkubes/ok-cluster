#!/usr/bin/env python3
"""Offline tests for the OK-186 Talos lifecycle hardening.

Runs the real Makefile targets against fake kubectl/clusterctl/helm binaries,
with HOME pointing at an empty directory so the default ~/.kube files are
absent, and exercises the clone-RBAC teardown cleanup with mocked kubectl.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ok130-talos" / "cluster-config.yaml"
CLUSTER = "ok130-talos"
sys.path.insert(0, str(ROOT))

import render  # noqa: E402
from scripts import talos_golden_lifecycle as lifecycle  # noqa: E402


CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((bool(condition), message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


FAKE_KUBECTL = r"""#!/usr/bin/env python3
import json, os, sys

raw = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["kubectl", *raw]) + "\n")

if "FAKE_STATE" not in os.environ:
    if "get" in raw and "nodes" in raw:
        print("cp-0 Ready control-plane")
    sys.exit(0)

state_path = os.environ["FAKE_STATE"]
if "FAKE_STATE_MAP" in os.environ:
    state_path = json.loads(os.environ["FAKE_STATE_MAP"])[raw[raw.index("--kubeconfig") + 1]]
with open(state_path) as stream:
    state = json.load(stream)

args = list(raw)
namespace = "default"
i = 0
while i < len(args):
    if args[i] == "--kubeconfig":
        del args[i:i + 2]
    elif args[i] in ("-n", "--namespace"):
        namespace = args[i + 1]
        del args[i:i + 2]
    else:
        i += 1

verb = next((value for value in ("get", "create", "patch", "delete", "annotate", "wait") if value in args), "")
vi = args.index(verb) if verb else -1
kind = args[vi + 1].lower() if vi >= 0 and len(args) > vi + 1 else ""
name = args[vi + 2] if vi >= 0 and len(args) > vi + 2 and not args[vi + 2].startswith("-") else ""
aliases = {
    "clusters.cluster.x-k8s.io": "cluster", "cluster": "cluster", "cluster/" + name: "cluster",
    "namespaces": "namespace", "namespace": "namespace",
    "datavolumes": "datavolumes", "dv": "datavolumes",
    "persistentvolumeclaims": "pvc", "pvc": "pvc",
    "persistentvolumes": "pv", "pv": "pv",
    "roles": "role", "role": "role",
    "rolebindings": "rolebinding", "rolebinding": "rolebinding",
    "volumesnapshots": "volumesnapshot", "volumesnapshot": "volumesnapshot",
    "volumes.longhorn.io": "longhorn",
    "configmaps": "configmap", "configmap": "configmap",
    "nodes": "node", "node": "node",
}
resource = aliases.get(kind, kind)
if verb in ("annotate", "wait"):
    sys.exit(0)
delete_options = None
if verb == "delete" and "--raw" in args:
    raw_path = args[args.index("--raw") + 1]
    parts = [part for part in raw_path.split("/") if part]
    name = parts[-1]
    plural = parts[-2]
    if parts[:3] == ["api", "v1", "namespaces"] and len(parts) == 4:
        resource = "namespace"
    else:
        resource = {
            "clusters": "cluster", "roles": "role", "rolebindings": "rolebinding",
            "volumesnapshots": "volumesnapshot", "persistentvolumes": "pv",
            "volumes": "longhorn",
        }.get(plural, plural)
    delete_options = json.load(sys.stdin)
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(json.dumps(["kubectl-stdin", delete_options]) + "\n")

def save():
    tmp = state_path + ".tmp"
    with open(tmp, "w") as stream:
        json.dump(state, stream, sort_keys=True)
    os.replace(tmp, state_path)

def fail(message, code=1):
    save()
    sys.stderr.write(message + "\n")
    sys.exit(code)

fault_key = f"{verb}:{resource}"
remaining = int(state.get("faults", {}).get(fault_key, 0))
if remaining:
    state["faults"][fault_key] = remaining - 1
    fail(f"Error from server (InternalError): injected {fault_key} failure")
delayed = state.get("fault_after", {}).get(fault_key)
if delayed is not None:
    delayed = int(delayed) - 1
    state["fault_after"][fault_key] = delayed
    if delayed == 0:
        fail(f"Error from server (Forbidden): injected delayed {fault_key} failure")
    save()

def not_found():
    fail(f'Error from server (NotFound): {resource} "{name}" not found')

def emit(obj):
    output = args[args.index("-o") + 1] if "-o" in args else ""
    if output == "name":
        print(f"{resource}/{obj['metadata']['name']}")
    else:
        print(json.dumps(obj, sort_keys=True))

def named(items, wanted):
    return next((item for item in items if item.get("metadata", {}).get("name") == wanted), None)

if verb == "get":
    obj = None
    if "--no-headers" in args and resource == "pvc":
        if any("custom-columns" in value for value in args):
            print("cp-0\nworker-0")
        else:
            print("cp-0 Bound\nworker-0 Bound")
        sys.exit(0)
    if "--no-headers" in args and resource == "datavolumes":
        print("cp-0 Succeeded\nworker-0 Succeeded")
        sys.exit(0)
    if resource == "machines.cluster.x-k8s.io":
        print(json.dumps({"items": state.get("machines", [])}))
        sys.exit(0)
    if resource == "node":
        if "-o" in args and args[args.index("-o") + 1] == "json":
            print(json.dumps({"items": state.get("nodes", [])}))
        elif any("osImage" in value for value in args):
            print("Talos (v1.9.6)")
        else:
            print("cp-0 Ready control-plane")
        sys.exit(0)
    if resource == "cluster":
        obj = state.get("cluster")
    elif resource == "namespace":
        obj = ({"metadata": {"uid": state.get("plane_uid")}}
               if name == "kube-system" else state.get("namespace"))
    elif resource == "configmap":
        obj = state.get("configmaps", {}).get(name)
    elif resource == "role":
        obj = state.get("role")
    elif resource == "rolebinding":
        obj = state.get("rolebinding")
    elif resource == "pvc" and name:
        if namespace == state["golden"]["metadata"]["namespace"] and name == state["golden"]["metadata"]["name"]:
            obj = state["golden"]
        else:
            obj = named(state.get("pvcs", []), name)
    elif resource in ("datavolumes", "pvc", "volumesnapshot", "pv", "longhorn"):
        key = {"datavolumes": "datavolumes", "pvc": "pvcs", "volumesnapshot": "snapshots", "pv": "pvs", "longhorn": "longhorns"}[resource]
        items = state.get(key, [])
        if name:
            obj = named(items, name)
        else:
            emit({"apiVersion": "v1", "items": items})
            sys.exit(0)
    if obj is None:
        not_found()
    emit(obj)
    sys.exit(0)

if verb == "create" and resource == "configmap":
    if name in state.setdefault("configmaps", {}):
        fail(f'Error from server (AlreadyExists): configmaps "{name}" already exists')
    literal = next(value for value in args if value.startswith("--from-literal=record.json="))
    record = literal.split("=", 2)[2]
    state["configmaps"][name] = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace, "uid": "ledger-uid", "resourceVersion": "1"},
        "data": {"record.json": record},
    }
    save()
    emit(state["configmaps"][name])
    sys.exit(0)

if verb == "patch" and resource == "configmap":
    obj = state.get("configmaps", {}).get(name)
    if obj is None:
        not_found()
    patch = json.loads(args[args.index("-p") + 1])
    if patch.get("metadata", {}).get("resourceVersion") != obj["metadata"].get("resourceVersion"):
        fail("Error from server (Conflict): configmap resourceVersion changed")
    obj.setdefault("data", {}).update(patch.get("data", {}))
    obj["metadata"]["resourceVersion"] = str(int(obj["metadata"]["resourceVersion"]) + 1)
    save()
    emit(obj)
    sys.exit(0)

if verb == "delete":
    current = None
    if resource == "cluster": current = state.get("cluster")
    elif resource == "namespace": current = state.get("namespace")
    elif resource == "role": current = state.get("role")
    elif resource == "rolebinding": current = state.get("rolebinding")
    elif resource == "volumesnapshot": current = named(state.get("snapshots", []), name)
    elif resource == "pv": current = named(state.get("pvs", []), name)
    elif resource == "longhorn": current = named(state.get("longhorns", []), name)
    race = state.get("race_on_delete", {}).pop(resource, None)
    if race and current is not None:
        metadata = current.setdefault("metadata", {})
        metadata["resourceVersion"] = str(int(metadata.get("resourceVersion", "0")) + 100)
        if race == "replace_uid":
            metadata["uid"] = f"replacement-{resource}-uid"
        elif race == "change_ownership":
            metadata.setdefault("labels", {})["cdi.kubevirt.io/OwnedByUID"] = "foreign-dv-uid"
        save()
    if delete_options is not None:
        if current is None:
            not_found()
        preconditions = delete_options.get("preconditions", {})
        metadata = current.get("metadata", {})
        if ((preconditions.get("uid") is not None and preconditions.get("uid") != metadata.get("uid"))
                or (preconditions.get("resourceVersion") is not None
                    and preconditions.get("resourceVersion") != metadata.get("resourceVersion"))):
            fail("Error from server (Conflict): delete precondition failed")
    if resource == "cluster":
        state["cluster"] = None
        if state.get("spawn_dv_after_cluster_delete"):
            golden = state["golden"]["metadata"]
            state["datavolumes"].append({"metadata": {"name": "late", "uid": "dv-late"}, "spec": {"source": {"pvc": {"namespace": golden["namespace"], "name": golden["name"]}}}})
            state["pvcs"].append({"metadata": {"name": "late"}, "spec": {"volumeName": "pv-late"}})
            state["pvs"].append({"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pv-late", "uid": "pv-late-uid", "resourceVersion": "61"}, "spec": {"persistentVolumeReclaimPolicy": "Retain"}})
            state["longhorns"].append({"apiVersion": "longhorn.io/v1beta2", "kind": "Volume", "metadata": {"name": "pv-late", "namespace": "longhorn-system", "uid": "lh-late-uid", "resourceVersion": "62"}})
            state["spawn_dv_after_cluster_delete"] = False
    elif resource == "namespace":
        state["namespace"] = None
        state["datavolumes"] = []
        state["pvcs"] = []
    elif resource == "role":
        state["role"] = None
    elif resource == "rolebinding":
        state["rolebinding"] = None
    elif resource == "volumesnapshot":
        state["snapshots"] = [item for item in state.get("snapshots", []) if item["metadata"]["name"] != name]
    elif resource == "pv":
        state["pvs"] = [item for item in state.get("pvs", []) if item["metadata"]["name"] != name]
    elif resource == "longhorn":
        state["longhorns"] = [item for item in state.get("longhorns", []) if item["metadata"]["name"] != name]
    if state.get("mutate_golden_after_delete") and resource in ("role", "rolebinding", "volumesnapshot"):
        state["golden"]["metadata"]["uid"] = "golden-recreated-uid"
    save()
    committed = int(state.get("commit_faults", {}).get(fault_key, 0))
    if committed:
        state["commit_faults"][fault_key] = committed - 1
        fail(f"transport closed after committed {fault_key}")
    print(f"{resource} \"{name}\" deleted")
    sys.exit(0)

fail("unsupported fake kubectl request: " + " ".join(args), 2)
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

FAKE_HELM = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(["helm", *sys.argv[1:]]) + "\n")
"""


class Sandbox:
    def __init__(self, base: Path, *, golden: bool = True) -> None:
        self.base = base
        self.home = base / "home"
        self.bin = base / "bin"
        self.clusters = base / "clusters"
        self.out = base / "out"
        self.infra = base / "mgmt" / "infra.yaml"
        self.log = base / "calls.jsonl"
        self.state_path = base / "remote.json"
        for directory in (self.home, self.bin, self.clusters / CLUSTER, self.infra.parent):
            directory.mkdir(parents=True)
        if golden:
            raw = yaml.safe_load(FIXTURE.read_text())
            # Fixture rendering must never query the operator's management
            # kubeconfig before the subprocess fake PATH/HOME are installed.
            with mock.patch.object(render, "live_metallb_allocations", return_value={}):
                config = render.resolve_config(raw, CLUSTER)
            with open(os.devnull, "w") as sink:
                old_stdout = sys.stdout
                old_script_dir = render.SCRIPT_DIR
                try:
                    sys.stdout = sink
                    render.SCRIPT_DIR = self.clusters
                    render.render_cluster(CLUSTER, self.clusters / CLUSTER, config)
                finally:
                    sys.stdout = old_stdout
                    render.SCRIPT_DIR = old_script_dir
        else:
            config = {"name": CLUSTER, "type": "ubuntu"}
            (self.clusters / CLUSTER / "cluster-config.yaml").write_text(
                yaml.safe_dump(config)
            )
            (self.clusters / CLUSTER / "cluster-base.yaml").write_text(
                "apiVersion: cluster.x-k8s.io/v1beta1\nkind: Cluster\n"
                f"metadata:\n  name: {CLUSTER}\n  namespace: {CLUSTER}\n"
                "spec: {}\n"
            )
        self.infra.write_text("# fake management kubeconfig\n")
        for name, body in (
            ("kubectl", FAKE_KUBECTL),
            ("clusterctl", FAKE_CLUSTERCTL),
            ("helm", FAKE_HELM),
        ):
            path = self.bin / name
            path.write_text(body)
            path.chmod(0o755)
        self.write_state(self.initial_state())

    @property
    def rendered(self) -> Path:
        return self.clusters / CLUSTER

    def initial_state(self) -> dict:
        config = yaml.safe_load((self.rendered / "cluster-config.yaml").read_text())
        docs = list(yaml.safe_load_all((self.rendered / "cluster-base.yaml").read_text()))
        cluster = next(item for item in docs if item and item.get("kind") == "Cluster")
        cluster["metadata"]["uid"] = "cluster-original-uid"
        cluster["metadata"]["resourceVersion"] = "10"
        cluster["status"] = {"phase": "Provisioning"}
        golden_cfg = config.get("os", {}).get("goldenImage", {})
        golden_namespace = golden_cfg.get("namespace", "ok-images")
        golden_claim = golden_cfg.get("claim", "unused")
        identity = config.get("os", {}).get("identity", "")
        digest = config.get("os", {}).get("imageDigest", "")
        role = next((item for item in docs if item and item.get("kind") == "Role"), None)
        rolebinding = next(
            (item for item in docs if item and item.get("kind") == "RoleBinding"), None
        )
        state = {
            "cluster": cluster,
            "namespace": {
                "apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": CLUSTER, "uid": "namespace-original-uid", "resourceVersion": "11"},
            },
            "golden": {
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": golden_claim, "namespace": golden_namespace,
                    "uid": "golden-original-uid", "resourceVersion": "12",
                    "annotations": {
                        "ok-linux.openkubes.io/image-sha256": digest,
                        "ok-linux.openkubes.io/os-identity": identity,
                    },
                },
                "spec": {"storageClassName": "ok-storage-block"},
                "status": {"phase": "Bound"},
            },
            "role": role,
            "rolebinding": rolebinding,
            "datavolumes": [
                {"metadata": {"name": "cp-0", "uid": "dv-owned-1"}, "spec": {"source": {"pvc": {"namespace": golden_namespace, "name": golden_claim}}}},
                {"metadata": {"name": "worker-0", "uid": "dv-owned-2"}, "spec": {"source": {"pvc": {"namespace": golden_namespace, "name": golden_claim}}}},
            ],
            "pvcs": [
                {"metadata": {"name": "cp-0"}, "spec": {"volumeName": "pv-owned-1"}},
                {"metadata": {"name": "worker-0"}, "spec": {"volumeName": "pv-owned-2"}},
            ],
            "pvs": [
                {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pv-owned-1", "uid": "pv-uid-1", "resourceVersion": "31"}, "spec": {"persistentVolumeReclaimPolicy": "Retain"}},
                {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "pv-owned-2", "uid": "pv-uid-2", "resourceVersion": "32"}, "spec": {"persistentVolumeReclaimPolicy": "Retain"}},
            ],
            "longhorns": [
                {"apiVersion": "longhorn.io/v1beta2", "kind": "Volume", "metadata": {"name": "pv-owned-1", "namespace": "longhorn-system", "uid": "lh-uid-1", "resourceVersion": "41"}},
                {"apiVersion": "longhorn.io/v1beta2", "kind": "Volume", "metadata": {"name": "pv-owned-2", "namespace": "longhorn-system", "uid": "lh-uid-2", "resourceVersion": "42"}},
            ],
            "snapshots": [
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
                    "metadata": {"name": "owned-snapshot", "namespace": golden_namespace, "uid": "snapshot-owned-uid", "resourceVersion": "51", "labels": {
                        "app": "containerized-data-importer",
                        "cdi.kubevirt.io/OwnedByUID": "dv-owned-1",
                    }},
                    "spec": {"source": {"persistentVolumeClaimName": golden_claim}},
                },
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
                    "metadata": {"name": "foreign-snapshot", "namespace": golden_namespace, "uid": "snapshot-foreign-uid", "resourceVersion": "52", "labels": {
                        "app": "containerized-data-importer",
                        "cdi.kubevirt.io/OwnedByUID": "foreign-dv-uid",
                    }},
                    "spec": {"source": {"persistentVolumeClaimName": golden_claim}},
                },
            ],
            "machines": [
                {"metadata": {"name": "cp-0", "namespace": CLUSTER, "labels": {
                    "cluster.x-k8s.io/cluster-name": CLUSTER,
                    "cluster.x-k8s.io/control-plane": "",
                }}, "status": {"nodeRef": {"name": "cp-0"}}},
                {"metadata": {"name": "worker-0", "namespace": CLUSTER, "labels": {
                    "cluster.x-k8s.io/cluster-name": CLUSTER,
                    "cluster.x-k8s.io/deployment-name": f"{CLUSTER}-workers",
                }}, "status": {"nodeRef": {"name": "worker-0"}}},
            ],
            "nodes": [
                {"metadata": {"name": name}, "status": {"conditions": [
                    {"type": "Ready", "status": "True"}
                ]}} for name in ("cp-0", "worker-0")
            ],
            "configmaps": {}, "faults": {},
        }
        for key in ("role", "rolebinding"):
            item = state[key]
            if item:
                item.setdefault("metadata", {})["uid"] = f"{key}-uid"
                item["metadata"]["resourceVersion"] = "20"
        return state

    def read_state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def write_state(self, state: dict) -> None:
        self.state_path.write_text(json.dumps(state, sort_keys=True))

    def mutate(self, function) -> None:
        state = self.read_state()
        function(state)
        self.write_state(state)

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
                "FAKE_STATE": str(self.state_path),
                **env,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def lifecycle(self, mode: str, *extra: str, **env: str):
        self.log.write_text("")
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "talos_golden_lifecycle.py"),
                mode, "--cluster", CLUSTER, "--cluster-dir", str(self.rendered),
                "--kubeconfig", str(self.infra), "--ok-linux-path", str(ROOT.parent / "ok-linux"),
                *( ["--confirm", "yes"] if mode == "--teardown" else [] ),
                *extra,
            ],
            env={
                **os.environ, "HOME": str(self.home),
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "FAKE_LOG": str(self.log), "FAKE_STATE": str(self.state_path),
                **env,
            },
            capture_output=True, text=True, check=False,
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
        " apply -f " not in resume_plan
        and "--resume-preconditions" in resume_plan
        and "--preflight" not in resume_plan
        and "annotate pvc" in resume_plan
        and "get kubeconfig" in resume_plan
        and "helm upgrade --install cilium" in resume_plan
        and "--wait-expected-nodes" in resume_plan,
        "bootstrap-resume plan: annotate, kubeconfig, Cilium, wait; no apply, no preflight",
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


def ledger(state: dict) -> dict | None:
    item = state.get("configmaps", {}).get(f"ok-cluster-teardown-{CLUSTER}")
    return json.loads(item["data"]["record.json"]) if item else None


def named_state(items: list[dict], name: str) -> dict | None:
    return next((item for item in items if item.get("metadata", {}).get("name") == name), None)


def mutation_calls(calls: list[list[str]]) -> list[list[str]]:
    return [
        call for call in calls
        if any(verb in call for verb in ("create", "patch", "delete", "apply", "annotate"))
    ]


def teardown_fault_retry(base: Path, resource: str) -> None:
    box = Sandbox(base)
    box.mutate(lambda state: state.setdefault("commit_faults", {}).__setitem__(f"delete:{resource}", 1))
    result, _ = box.lifecycle("--teardown")
    state = box.read_state()
    check(
        result.returncode != 0 and "torn down (including" not in result.stdout
        and box.rendered.is_dir() and ledger(state) is not None
        and ledger(state)["complete"] is False,
        f"committed {resource} delete error: nonzero, no success, local and durable retry state retained",
    )
    result, _ = box.lifecycle("--teardown")
    check(
        result.returncode == 0 and "torn down (including" in result.stdout
        and not box.rendered.exists() and ledger(box.read_state())["complete"] is True,
        f"committed {resource} delete error: retry completes from durable state",
    )


def retained_delete_failure_tests(base: Path) -> None:
    for resource in ("cluster", "namespace"):
        box = Sandbox(base / f"retained-{resource}")
        box.mutate(lambda state, key=resource: state.setdefault("faults", {}).__setitem__(f"delete:{key}", 1))
        before = box.read_state()
        result, calls = box.lifecycle("--teardown")
        state = box.read_state()
        check(
            result.returncode != 0 and state[resource] is not None
            and ledger(state)["complete"] is False and box.rendered.exists()
            and "torn down (including" not in result.stdout,
            f"failed {resource} delete: resource, render and incomplete durable state are retained",
        )
        check(
            state["pvs"] == before["pvs"]
            and state["longhorns"] == before["longhorns"]
            and ledger(state)["persistent_volumes"] == ["pv-owned-1", "pv-owned-2"]
            and not any(
                "delete" in call and (
                    "volumes.longhorn.io" in call
                    or any("/persistentvolumes/" in arg for arg in call if isinstance(arg, str))
                    or "pv" in call
                )
                for call in calls
            ),
            f"failed {resource} delete: no PV or Longhorn delete issued; PV inventory retained for retry",
        )
        result, _ = box.lifecycle("--teardown")
        check(
            result.returncode == 0 and ledger(box.read_state())["complete"] is True,
            f"failed {resource} delete: retry completes",
        )


def completed_recreation_test(base: Path) -> None:
    old = Sandbox(base / "old")
    first, _ = old.lifecycle("--teardown")
    receipt = old.read_state()["configmaps"]
    box = Sandbox(base / "new")
    def recreate(state: dict) -> None:
        state["configmaps"] = receipt
        for key in ("cluster", "namespace"):
            state[key]["metadata"]["uid"] = f"new-{key}-uid"
        for key in ("pvs", "longhorns", "datavolumes", "snapshots"):
            for item in state[key]:
                item["metadata"]["uid"] = "new-" + item["metadata"]["uid"]
        state["snapshots"][0]["metadata"]["labels"]["cdi.kubevirt.io/OwnedByUID"] = "new-dv-owned-1"
    box.mutate(recreate)
    result, calls = box.lifecycle("--teardown")
    record = ledger(box.read_state())
    patches = [
        json.loads(call[call.index("-p") + 1])
        for call in calls if "patch" in call and "configmap" in call
    ]
    writes = [json.loads(patch["data"]["record.json"]) for patch in patches]
    delete_uids = [
        call[1]["preconditions"]["uid"]
        for call in calls if call and call[0] == "kubectl-stdin"
    ]
    check(
        first.returncode == 0 and result.returncode == 0
        and record["complete"] is True
        and record["cluster"]["uid"] == "new-cluster-uid"
        and record["namespace_uid"] == "new-namespace-uid"
        and record["data_volume_uids"] == ["new-dv-owned-1", "new-dv-owned-2"]
        and writes and writes[0]["complete"] is False
        and writes[0]["cluster"]["uid"] == "new-cluster-uid"
        and patches[0]["metadata"]["resourceVersion"]
        == receipt[f"ok-cluster-teardown-{CLUSTER}"]["metadata"]["resourceVersion"]
        and {"new-cluster-uid", "new-namespace-uid"}.issubset(delete_uids)
        and all(uid.startswith("new-") or uid in ("role-uid", "rolebinding-uid") for uid in delete_uids)
        and not any("create" in call and "configmap" in call for call in calls),
        "completed receipt + recreated resources: fresh guarded record, only new resource UIDs deleted, exit zero",
    )


def teardown_tests(base: Path) -> None:
    teardown_fault_retry(base / "cluster-delete", "cluster")
    teardown_fault_retry(base / "namespace-delete", "namespace")
    retained_delete_failure_tests(base)
    completed_recreation_test(base / "completed-recreation")

    partial = Sandbox(base / "partial-golden")
    partial.mutate(lambda state: state.setdefault("faults", {}).__setitem__("delete:role", 1))
    result, _ = partial.lifecycle("--teardown")
    state = partial.read_state()
    check(
        result.returncode != 0 and state["role"] is not None
        and state["rolebinding"] is None and ledger(state)["complete"] is False,
        "partial Golden cleanup: failure retains the remaining Role and incomplete durable record",
    )
    result, _ = partial.lifecycle("--teardown")
    check(
        result.returncode == 0 and partial.read_state()["role"] is None,
        "partial Golden cleanup: retry removes only the remaining authorization",
    )

    pv_fault = Sandbox(base / "pv-fault")
    pv_fault.mutate(lambda state: state.setdefault("faults", {}).__setitem__("delete:pv", 1))
    result, _ = pv_fault.lifecycle("--teardown")
    state = pv_fault.read_state()
    check(
        result.returncode != 0 and named_state(state["pvs"], "pv-owned-1") is not None
        and ledger(state)["complete"] is False,
        "failed PV delete: nonzero with failed PV and incomplete durable record retained",
    )
    result, _ = pv_fault.lifecycle("--teardown")
    check(
        result.returncode == 0 and ledger(pv_fault.read_state())["complete"] is True,
        "failed PV delete: retry completes while already-clean resources skip",
    )

    repeated = Sandbox(base / "repeated")
    result, _ = repeated.lifecycle("--teardown")
    first_state = repeated.read_state()
    check(
        result.returncode == 0
        and [item["metadata"]["name"] for item in first_state["snapshots"]] == ["foreign-snapshot"]
        and ledger(first_state)["complete"] is True,
        "snapshot ownership: owned CDI snapshot removed and foreign UID snapshot preserved",
    )
    result, calls = repeated.lifecycle("--teardown")
    check(
        result.returncode == 0 and "SKIP Talos cluster" in result.stdout
        and not mutation_calls(calls),
        "repeated teardown: completed durable receipt returns SKIP without mutation",
    )

    remote = Sandbox(base / "remote-only")
    remote.mutate(lambda state: state.setdefault("faults", {}).__setitem__("delete:role", 1))
    result, _ = remote.lifecycle("--teardown")
    pending = remote.read_state()
    shutil.rmtree(remote.rendered)
    check(
        result.returncode != 0 and pending["namespace"] is None
        and pending["role"] is not None and len(pending["snapshots"]) == 2
        and ledger(pending)["complete"] is False
        and not remote.rendered.exists()
        and not (remote.rendered / ".teardown-data-volume-uids").exists(),
        "remote retry setup: clone RBAC and snapshot remain with local render and UID file absent",
    )
    result, _ = remote.lifecycle("--teardown")
    recovered = remote.read_state()
    check(
        result.returncode == 0 and ledger(recovered)["complete"] is True
        and recovered["role"] is None and recovered["rolebinding"] is None
        and [item["metadata"]["name"] for item in recovered["snapshots"]] == ["foreign-snapshot"],
        "remote retry: durable ConfigMap alone removes remaining clone RBAC and snapshots",
    )

    lost = Sandbox(base / "lost")
    shutil.rmtree(lost.rendered)
    result, calls = lost.lifecycle("--teardown")
    check(
        result.returncode != 0 and "both absent" in result.stderr
        and "PASS" not in result.stdout and "SKIP" not in result.stdout
        and not mutation_calls(calls),
        "lost provenance: absent local config and durable record fails closed without success or mutation",
    )

    changed = Sandbox(base / "golden-changed")
    changed.mutate(lambda state: state.__setitem__("mutate_golden_after_delete", True))
    result, _ = changed.lifecycle("--teardown")
    check(
        result.returncode != 0 and "Golden PVC changed" in result.stderr
        and ledger(changed.read_state())["complete"] is False
        and changed.rendered.exists(),
        "Golden identity before/after mismatch: teardown fails and retains retry state",
    )

    labels = Sandbox(base / "role-labels")
    labels.mutate(lambda state: state["role"]["metadata"]["labels"].__setitem__("openkubes.io/consumer-cluster", "foreign"))
    result, calls = labels.lifecycle("--teardown")
    check(
        result.returncode != 0 and "ownership is invalid" in result.stderr
        and labels.read_state()["role"] is not None
        and not any("delete" in call and "role" in call for call in calls),
        "Role ownership labels: mismatch fails before authorization deletion",
    )

    recreated = Sandbox(base / "recreated")
    recreated.mutate(lambda state: state.setdefault("faults", {}).__setitem__("delete:cluster", 1))
    first, _ = recreated.lifecycle("--teardown")
    def replace_uids(state: dict) -> None:
        state["cluster"]["metadata"]["uid"] = "cluster-recreated-uid"
        state["namespace"]["metadata"]["uid"] = "namespace-recreated-uid"
    recreated.mutate(replace_uids)
    result, calls = recreated.lifecycle("--teardown")
    check(
        first.returncode != 0 and result.returncode != 0
        and "different UID" in result.stderr and not mutation_calls(calls),
        "recreated Cluster/Namespace UID: durable identity mismatch refuses every deletion",
    )


def inventory_refresh_tests(base: Path) -> None:
    for mode in ("write", "read"):
        box = Sandbox(base / mode)
        def inject(state: dict) -> None:
            state["spawn_dv_after_cluster_delete"] = True
            if mode == "write":
                state.setdefault("faults", {})["patch:configmap"] = 1
            else:
                state.setdefault("fault_after", {})["get:configmap"] = 3
        box.mutate(inject)
        result, calls = box.lifecycle("--teardown")
        check(
            result.returncode != 0 and box.read_state()["namespace"] is not None
            and not any("delete" in call and "namespace" in call for call in calls),
            f"inventory refresh {mode} failure: Namespace is retained before destructive deletion",
        )
        result, _ = box.lifecycle("--teardown")
        state = box.read_state()
        check(
            result.returncode == 0 and ledger(state)["complete"] is True
            and "dv-late" in ledger(state)["data_volume_uids"],
            f"inventory refresh {mode} failure: retry merges late UID after prior PV cleanup",
        )


def deletion_race_tests(base: Path) -> None:
    for resource in ("cluster", "namespace"):
        box = Sandbox(base / resource)
        box.mutate(lambda state, key=resource: state.setdefault("race_on_delete", {}).__setitem__(key, "replace_uid"))
        result, calls = box.lifecycle("--teardown")
        state = box.read_state()
        check(
            result.returncode != 0 and state[resource] is not None
            and state[resource]["metadata"]["uid"] == f"replacement-{resource}-uid"
            and ledger(state)["complete"] is False,
            f"raw delete race ({resource} replacement): replacement survives and receipt stays incomplete",
        )

    for name, race in (("snapshot-replacement", "replace_uid"), ("snapshot-ownership", "change_ownership")):
        box = Sandbox(base / name)
        box.mutate(lambda state, value=race: state.setdefault("race_on_delete", {}).__setitem__("volumesnapshot", value))
        result, _ = box.lifecycle("--teardown")
        state = box.read_state()
        snapshot = named_state(state["snapshots"], "owned-snapshot")
        check(
            result.returncode != 0 and snapshot is not None
            and ledger(state)["complete"] is False,
            f"raw delete race ({name}): changed snapshot is preserved",
        )

    role = Sandbox(base / "role-version")
    role.mutate(lambda state: state.setdefault("race_on_delete", {}).__setitem__("role", "rv_only"))
    result, _ = role.lifecycle("--teardown")
    check(
        result.returncode != 0 and role.read_state()["role"] is not None
        and ledger(role.read_state())["complete"] is False,
        "raw delete race (Role resourceVersion): changed Role is preserved",
    )

    bodies = Sandbox(base / "delete-options")
    result, calls = bodies.lifecycle("--teardown")
    options = [call[1] for call in calls if call and call[0] == "kubectl-stdin"]
    check(
        result.returncode == 0 and options
        and all(body.get("preconditions", {}).get("uid") for body in options)
        and any(body.get("preconditions", {}).get("resourceVersion") for body in options),
        "raw delete requests carry observed UID preconditions and resourceVersion where required",
    )


def resume_tests(base: Path) -> None:
    supported = Sandbox(base / "supported")
    supported.mutate(lambda state: state["cluster"]["status"].update({
        "phase": "Provisioning", "conditions": [{"type": "ControlPlaneReady", "status": "False"}]
    }))
    result, calls = supported.lifecycle("--resume-preconditions")
    check(
        result.returncode == 0 and "PASS bootstrap resume preconditions" in result.stdout
        and not mutation_calls(calls),
        "resume supported post-apply: absent kubeconfig/CNI and NotReady state passes read-only",
    )
    for phase in ("", "Pending", "Provisioning", "Provisioned"):
        supported.mutate(lambda state, value=phase: state["cluster"].setdefault("status", {}).__setitem__("phase", value))
        result, calls = supported.lifecycle("--resume-preconditions")
        check(
            result.returncode == 0 and not mutation_calls(calls),
            f"resume supported phase {phase or '<empty>'}: passes read-only",
        )
    result, calls = supported.make("bootstrap-resume")
    check(
        result.returncode == 0 and any("--resume-preconditions" in line for line in result.stdout.splitlines()) is False
        and not any("apply" in call for call in calls),
        "bootstrap-resume happy path: real precondition plus post-apply fake flow never applies manifests",
    )

    mismatch = Sandbox(base / "mismatch")
    mismatch.mutate(lambda state: state["cluster"]["metadata"]["labels"].__setitem__("openkubes.io/type", "ubuntu"))
    result, calls = mismatch.lifecycle("--resume-preconditions")
    check(
        result.returncode != 0 and "differs" in result.stderr and not mutation_calls(calls),
        "resume rendered identity mismatch: fails before every mutation",
    )

    for name, operation in (
        ("pod CIDR", lambda item: item["spec"]["clusterNetwork"]["pods"]["cidrBlocks"].__setitem__(0, "10.99.0.0/16")),
        ("controlPlaneRef", lambda item: item["spec"]["controlPlaneRef"].__setitem__("name", "foreign")),
        ("infrastructureRef", lambda item: item["spec"]["infrastructureRef"].__setitem__("name", "foreign")),
    ):
        box = Sandbox(base / f"spec-{name.replace(' ', '-')}")
        box.mutate(lambda state, mutate=operation: mutate(state["cluster"]))
        result, calls = box.lifecycle("--resume-preconditions")
        check(
            result.returncode != 0 and "differs" in result.stderr and not mutation_calls(calls),
            f"resume rendered spec mismatch ({name}): fails read-only",
        )

    for field in ("uid", "name", "namespace"):
        box = Sandbox(base / f"identity-{field}")
        box.mutate(lambda state, key=field: state["cluster"]["metadata"].pop(key, None))
        result, calls = box.lifecycle("--resume-preconditions")
        check(
            result.returncode != 0 and "identity is invalid" in result.stderr
            and not mutation_calls(calls),
            f"resume live identity missing {field}: fails read-only",
        )

    absent = Sandbox(base / "absent")
    absent.mutate(lambda state: state.__setitem__("cluster", None))
    result, calls = absent.lifecycle("--resume-preconditions")
    check(
        result.returncode != 0 and "is absent" in result.stderr and not mutation_calls(calls),
        "resume absent Cluster: fails read-only",
    )
    forbidden = Sandbox(base / "forbidden")
    forbidden.mutate(lambda state: state.setdefault("faults", {}).__setitem__("get:cluster", 1))
    result, calls = forbidden.lifecycle("--resume-preconditions")
    check(
        result.returncode != 0 and "read failed" in result.stderr and not mutation_calls(calls),
        "resume forbidden Cluster read: fails read-only",
    )

    for name, mutate in (
        ("deleting", lambda item: item["metadata"].__setitem__("deletionTimestamp", "2026-10-12T00:00:00Z")),
        ("paused", lambda item: item["metadata"].setdefault("annotations", {}).__setitem__("cluster.x-k8s.io/paused", "")),
        ("failed", lambda item: item["status"].update({"phase": "Failed", "failureReason": "Broken"})),
    ):
        box = Sandbox(base / name)
        box.mutate(lambda state, operation=mutate: operation(state["cluster"]))
        result, calls = box.lifecycle("--resume-preconditions")
        check(
            result.returncode != 0 and not mutation_calls(calls),
            f"resume {name} Cluster state: refused without mutation",
        )


def non_golden_tests(base: Path) -> None:
    box = Sandbox(base, golden=False)
    box.mutate(lambda state: state.setdefault("commit_faults", {}).__setitem__("delete:namespace", 1))
    first, calls = box.lifecycle("--teardown")
    check(
        first.returncode != 0 and ledger(box.read_state())["config"]["golden_claim"] is None
        and not any(any(kind in call for kind in ("role", "rolebinding", "volumesnapshot")) for call in calls),
        "non-Golden teardown: durable delete failure semantics require no Golden reads",
    )
    result, _ = box.lifecycle("--teardown")
    check(
        result.returncode == 0 and ledger(box.read_state())["complete"] is True,
        "non-Golden teardown: retry completes with the same durable contract",
    )


def delete_poll_tests() -> None:
    resource = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": CLUSTER, "uid": "poll-uid", "resourceVersion": "7"},
    }
    raw_result = subprocess.CompletedProcess([], 0, "", "")
    with mock.patch.object(lifecycle, "kubectl", return_value=raw_result), \
         mock.patch.object(lifecycle, "kubectl_json_optional", side_effect=[resource, None]) as observe, \
         mock.patch.object(lifecycle.time, "sleep"):
        lifecycle.preconditioned_delete(
            Path("fake"), resource, "/api/v1/namespaces/x",
            ["get", "namespace", CLUSTER], "Namespace", timeout_seconds=5,
        )
    check(
        observe.call_count == 2,
        "raw delete completion: polls through the original UID until NotFound",
    )
    timed_out = False
    with mock.patch.object(lifecycle, "kubectl", return_value=raw_result), \
         mock.patch.object(lifecycle, "kubectl_json_optional", return_value=resource):
        try:
            lifecycle.preconditioned_delete(
                Path("fake"), resource, "/api/v1/namespaces/x",
                ["get", "namespace", CLUSTER], "Namespace", timeout_seconds=0,
            )
        except lifecycle.TalosLifecycleError as error:
            timed_out = "not deleted within 0s" in str(error)
    check(timed_out, "raw delete completion: a surviving original UID reaches a clear timeout")


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="ok186-"))
    make_tests(Sandbox(base / "make"))
    teardown_tests(base / "teardown")
    inventory_refresh_tests(base / "inventory-refresh")
    deletion_race_tests(base / "deletion-races")
    resume_tests(base / "resume")
    non_golden_tests(base / "non-golden")
    delete_poll_tests()
    make_defaults()
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
