#!/usr/bin/env python3
"""Coordinator-only, disposable OK-197 split-plane proof. See README operator note.

Credentials stay in memory (Linux memfd), never evidence or temporary files.
Persistent state contains identities only; interrupted runs retain the guest for
an explicit teardown retry. Shared ledger installation is intentionally retained.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[2]
LEDGER = "ok-cluster-teardown"
PROTECTED = "ok-cli-mvp-3"
MGMT_READER = "ok-cluster-teardown-namespace-reader"
PROVIDER_READER = "ok-cluster-teardown-provider-namespace-reader"
CAPI = {"Cluster", "Machine", "MachineDeployment", "MachineSet",
        "KubevirtCluster", "KubevirtMachine", "KubevirtMachineTemplate",
        "TalosControlPlane", "TalosConfig", "TalosConfigTemplate"}
PROVIDER = {"VirtualMachine", "VirtualMachineInstance", "DataVolume",
            "PersistentVolumeClaim", "VolumeSnapshot"}


class ProofError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise ProofError(message)


def guard(cluster, management_uid, provider_uid, existing_names,
          confirm_required=False, confirm=""):
    require(cluster != PROTECTED, "protected cluster ok-cli-mvp-3 is forbidden")
    require(re.fullmatch(r"ok197-split-[a-z0-9]{4,8}", cluster or ""),
            "CLUSTER must match ^ok197-split-[a-z0-9]{4,8}$")
    require(cluster not in existing_names, "cluster name already exists")
    require(management_uid and provider_uid and management_uid != provider_uid,
            "management and provider plane UIDs must differ")
    require(not confirm_required or confirm == "yes", "OK197_SPLIT_CONFIRM=yes required")


def split_documents(documents, cluster):
    result = {"management": [], "provider": []}
    for obj in documents:
        if not obj:
            continue
        kind, meta = obj["kind"], obj["metadata"]
        group = obj["apiVersion"].split("/")[0]
        if kind == "Namespace" and meta["name"] == cluster:
            planes = ("management", "provider")
        elif (kind in CAPI and group.endswith("cluster.x-k8s.io")
              and meta.get("namespace") == cluster):
            planes = ("management",)
        elif (kind in PROVIDER and meta.get("namespace") == cluster
              and group in {"v1", "kubevirt.io", "cdi.kubevirt.io", "snapshot.storage.k8s.io"}):
            planes = ("provider",)
        elif (kind in {"Role", "RoleBinding"} and meta.get("namespace") == "ok-images"
              and meta["name"] == f"{cluster}-talos-golden-image-cloner"):
            planes = ("provider",)
        else:
            raise ProofError(f"unrecognized split object {kind} {meta.get('name')}")
        for plane in planes:
            result[plane].append(obj)
    for plane in result:
        require(sum(o["kind"] == "Namespace" for o in result[plane]) == 1,
                f"{plane}: expected exactly one guest Namespace")
    require(any(o["kind"] == "Cluster" for o in result["management"]), "missing CAPI Cluster")
    return result


def trace_requests(stderr, plane):
    """Keep only completed HTTP method/path/status, never headers or hosts."""
    rows = []
    for line in stderr.splitlines():
        match = re.search(r'\b(GET|POST|PATCH|PUT|DELETE) (https?://\S+) (\d{3})\b', line)
        if not match:
            match = re.search(r'verb="(GET|POST|PATCH|PUT|DELETE)" url="([^"]+)".*status="(\d{3})', line)
        if match:
            method, url, status = match.groups()
            rows.append(dict(plane=plane, method=method, path=urlsplit(url).path, status=int(status)))
    return rows


def assert_trace(requests, denied=False):
    require(not any(PROTECTED in r["path"] and r["method"] in {"POST", "PATCH", "PUT", "DELETE"}
                    for r in requests), "trace attempted mutation of protected cluster")
    system = [r for r in requests if "/namespaces/kube-system" in r["path"]]
    require(len(system) == 2, "expected exactly one kube-system Namespace GET per plane")
    for plane in ("management", "provider"):
        rows = [r for r in system if r["plane"] == plane]
        require(len(rows) == 1 and rows[0]["method"] == "GET"
                and rows[0]["path"] == "/api/v1/namespaces/kube-system"
                and rows[0]["status"] == (403 if denied and plane == "provider" else 200),
                f"unexpected kube-system access on {plane}")
    if denied:
        require(not any(r["method"] in {"POST", "PATCH", "PUT", "DELETE"} for r in requests),
                "denied plane-binding path mutated the API")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


class Evidence:
    def __init__(self, command):
        location = os.environ.get("OK197_EVIDENCE_DIR", "")
        require(location and Path(location).is_absolute(), "absolute OK197_EVIDENCE_DIR required")
        self.directory = Path(location).resolve()
        require(not self.directory.is_relative_to(ROOT), "evidence must be outside the repo")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.prefix = self.directory / f"{stamp()}-{command}"
        self.log = Path(str(self.prefix) + ".log").open("x", encoding="utf-8")
        os.chmod(self.log.name, 0o600)
        self.summary = dict(command=command, started=stamp(), status="running", checks=[])
        self.summary_path = Path(str(self.prefix) + ".json")
        with self.summary_path.open("x") as out:
            os.chmod(out.name, 0o600)
            json.dump(self.summary, out, indent=2)

    def emit(self, message):
        # Commands are labelled, never printed. Drop endpoint URLs and IP addresses.
        text = str(message)
        for key in ("MGMT_KUBECONFIG", "INFRA_KUBECONFIG"):
            if os.environ.get(key):
                text = text.replace(os.environ[key], "<kubeconfig>")
        text = re.sub(r"https?://[^\s\"']+", "<endpoint>", text)
        text = text.replace(str(ROOT), "<repo>")
        text = re.sub(r"/(?:tmp|mnt|home)\b[^\s\"'<>]*", "<path>", text)
        text = re.sub(r"ok197-kubectl-[^\s\"'<>]+", "<path>", text)
        def redact_ipv6(match):
            candidate = match.group()
            address = candidate
            try:
                ipaddress.IPv6Address(address)
            except ValueError:
                address = candidate.rstrip(".:")
                try:
                    ipaddress.IPv6Address(address)
                except ValueError:
                    return candidate
            return "<ip>" + candidate[len(address):]
        text = re.sub(r"(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:.]*(?:%[\w.-]+)?",
                      redact_ipv6, text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)
        text = re.sub(r"/proc/(?:self|\d+)/fd/\d+", "<memory-credential>", text)
        line = f"{stamp()} {text}"
        print(line, flush=True)
        self.log.write(line + "\n")
        self.log.flush()

    def check(self, message):
        self.emit("PASS " + message)
        self.summary["checks"].append(message)

    def finish(self, success):
        self.summary.update(status="pass" if success else "fail", finished=stamp())
        with self.summary_path.open("w") as out:
            json.dump(self.summary, out, indent=2)
        self.log.close()


@contextmanager
def memory_config(document):
    require(hasattr(os, "memfd_create"), "Linux memfd support required; no credential-file fallback")
    fd = os.memfd_create("ok197-credential", 0)
    try:
        os.write(fd, yaml.safe_dump(document).encode())
        os.lseek(fd, 0, os.SEEK_SET)
        # A stable parent PID survives nested subprocesses closing their fds.
        yield f"/proc/{os.getpid()}/fd/{fd}", fd
    finally:
        os.close(fd)


class Proof:
    def __init__(self, evidence):
        self.e = evidence
        self.c = os.environ.get("CLUSTER", "")
        # Name and confirmation are checked before even reading either kubeconfig.
        guard(self.c, "unchecked-management", "unchecked-provider", set())
        self.configs = {}
        for plane, key in (("management", "MGMT_KUBECONFIG"), ("provider", "INFRA_KUBECONFIG")):
            require(os.environ.get(key), f"explicit {key} required")
            path = Path(os.environ[key]).expanduser().resolve()
            require(path.is_file(), f"{key} is not a regular file")
            self.configs[plane] = str(path)
        self.statepath = self.e.directory / f"{self.c}-state.json"
        self.state = json.loads(self.statepath.read_text()) if self.statepath.exists() else {}
        require(not self.state or self.state.get("cluster") == self.c, "state cluster mismatch")
        self.fds = ()
        self.env = dict(os.environ, OK_CLI_VERSION="proof", OK_CLI_REVISION="proof")
        self.e.summary["cluster"] = self.c

    def save(self):
        # State is credential-free. Exclusive staging file and atomic replacement.
        fd, name = tempfile.mkstemp(prefix=f".{self.c}-state-", dir=self.e.directory)
        try:
            with os.fdopen(fd, "w") as out:
                json.dump(self.state, out, indent=2)
            os.replace(name, self.statepath)
        finally:
            if Path(name).exists():
                Path(name).unlink()

    def run(self, args, *, data=None, allowed=(0,), label="command", output=False):
        self.e.emit("RUN " + label)
        result = subprocess.run(args, input=data, text=True, capture_output=True,
                                cwd=ROOT, env=self.env, pass_fds=self.fds)
        if output:
            self.e.emit(result.stdout)
            self.e.emit(result.stderr)
        require(result.returncode in allowed, f"{label} failed (exit {result.returncode})")
        return result

    def k(self, plane, args, **kw):
        return self.run(["kubectl", "--kubeconfig", self.configs[plane], *args],
                        label=f"{plane}: kubectl {args[0]}", **kw)

    def obj(self, plane, resource, name=None, namespace=None):
        args = ["get", resource]
        if name:
            args.extend([name, "--ignore-not-found"])
        if namespace:
            args.extend(["-n", namespace])
        result = self.k(plane, [*args, "-o", "json"])
        return json.loads(result.stdout) if result.stdout.strip() else None

    def make(self, target, *, management=None, provider=None, allowed=(0,), output=True, **variables):
        values = dict(CLUSTER=self.c, TALOS_INFRA_KUBECONFIG=management or self.configs["management"],
                      TALOS_TEARDOWN_PROVIDER_KUBECONFIG=provider or self.configs["provider"],
                      OK_CLI_VERSION="proof", OK_CLI_REVISION="proof", **variables)
        return self.run(["make", "--no-print-directory", target,
                         *(f"{k}={v}" for k, v in values.items())],
                        allowed=allowed, output=output, label="make " + target)

    def bind_planes(self):
        uids = {p: self.obj(p, "namespace", "kube-system")["metadata"]["uid"] for p in self.configs}
        guard(self.c, uids["management"], uids["provider"], set())
        if self.state.get("planes"):
            require(self.state["planes"] == uids, "plane UIDs changed since preflight")
        self.e.summary["planes"] = uids
        return uids

    def ledger(self, plane="management"):
        return self.obj(plane, "configmap", "ok-cluster-teardown-" + self.c, LEDGER)

    def snapshot(self, cluster):
        """Name/UID inventory only; never request Secret contents."""
        result = {}
        resources = {
            "management": ["clusters.cluster.x-k8s.io", "kubevirtclusters", "taloscontrolplanes",
                           "machinedeployments", "machines", "machinesets", "kubevirtmachines",
                           "kubevirtmachinetemplates", "talosconfigs", "talosconfigtemplates"],
            "provider": ["virtualmachines", "virtualmachineinstances", "datavolumes", "pvc"],
        }
        for plane, kinds in resources.items():
            ns = self.obj(plane, "namespace", cluster)
            result[f"{plane}/namespace"] = [] if not ns else [(cluster, ns["metadata"]["uid"])]
            for kind in kinds:
                objects = self.obj(plane, kind, namespace=cluster)["items"]
                result[f"{plane}/{kind}"] = sorted((o["metadata"]["name"], o["metadata"]["uid"]) for o in objects)
            # Namespace/CAPI UIDs bind this inventory; omit Secrets entirely.
            # Client-side -o filtering would still fetch their credential data.
        dvs = {uid for _, uid in result["provider/datavolumes"]}
        pvs = self.obj("provider", "pv")["items"]
        owned = [o for o in pvs if o.get("spec", {}).get("claimRef", {}).get("namespace") == cluster]
        result["provider/pv"] = sorted((o["metadata"]["name"], o["metadata"]["uid"]) for o in owned)
        names = {n for n, _ in result["provider/pv"]}
        volumes = self.obj("provider", "volumes.longhorn.io", namespace="longhorn-system")["items"]
        result["provider/longhorn"] = sorted((o["metadata"]["name"], o["metadata"]["uid"])
            for o in volumes if o["metadata"]["name"] in names or
            o.get("status", {}).get("kubernetesStatus", {}).get("namespace") == cluster)
        for kind in ("role", "rolebinding"):
            o = self.obj("provider", kind, cluster + "-talos-golden-image-cloner", "ok-images")
            result[f"provider/{kind}"] = [] if not o else [(o["metadata"]["name"], o["metadata"]["uid"])]
        snapshots = self.obj("provider", "volumesnapshots", namespace="ok-images")["items"]
        result["provider/snapshots"] = sorted((o["metadata"]["name"], o["metadata"]["uid"])
            for o in snapshots if o["metadata"].get("labels", {}).get("cdi.kubevirt.io/OwnedByUID") in dvs)
        return json.loads(json.dumps(result))

    def preflight(self):
        require(not self.state, "preflight state already exists; use a fresh evidence directory/name")
        linux = Path(self.env.get("OK_LINUX_PATH", str(ROOT.parent / "ok-linux")))
        require((linux / "profiles/kubevirt/profile.yaml").is_file(), "OK_LINUX_PATH must identify the owning ok-linux checkout")
        self.make("verify-cilium-chart")
        planes = self.bind_planes()
        names = set()
        clusters = json.loads(self.k("management", ["get", "clusters.cluster.x-k8s.io", "-A", "-o", "json"]).stdout)["items"]
        names.update(o["metadata"]["name"] for o in clusters)
        names.update(self.c for p in self.configs if self.obj(p, "namespace", self.c))
        guard(self.c, planes["management"], planes["provider"], names)
        require(self.ledger() is None and self.ledger("provider") is None, "receipt already exists")
        require(not (ROOT / self.c).exists(), "local cluster render already exists")
        require(any(o["metadata"]["name"] == PROTECTED for o in clusters), "protected reference Cluster is absent")
        self.state = dict(cluster=self.c, planes=planes, protected=self.snapshot(PROTECTED), resources=[])
        self.save()
        self.e.check("fresh name on both planes; protected names/UIDs captured")

    def need_state(self):
        require(self.state.get("protected"), "run preflight first in the same evidence directory")
        self.bind_planes()

    def create_object(self, plane, obj):
        meta = obj["metadata"]
        if obj["kind"] == "Secret":
            # CREATE is atomic and refuses AlreadyExists without a content GET.
            found = None
        else:
            found = self.obj(plane, obj["kind"], meta["name"], meta.get("namespace"))
        require(not found, f"refusing existing {plane} {obj['kind']} {meta['name']}")
        result = self.k(plane, ["create", "-f", "-", "-o", "json"], data=json.dumps(obj))
        created = json.loads(result.stdout)
        self.state["resources"].append(dict(plane=plane, apiVersion=obj["apiVersion"], kind=obj["kind"],
            name=meta["name"], namespace=meta.get("namespace"), uid=created["metadata"]["uid"]))
        self.save()

    def rbac(self, plane, kind, name, *, rules=None, namespace=None, role=None, account="teardown"):
        obj = dict(apiVersion="rbac.authorization.k8s.io/v1", kind=kind,
                   metadata=dict(name=name, **({"namespace": namespace} if namespace else {})))
        if rules is not None:
            obj["rules"] = rules
        else:
            obj.update(roleRef=dict(apiGroup="rbac.authorization.k8s.io", kind=role[0], name=role[1]),
                       subjects=[dict(kind="ServiceAccount", name=account, namespace=self.c + "-proof")])
        self.create_object(plane, obj)

    def identities(self):
        for plane in self.configs:
            ns = self.c + "-proof"
            self.create_object(plane, dict(apiVersion="v1", kind="Namespace", metadata=dict(name=ns)))
            accounts = ["teardown"] + (["capk", "denied"] if plane == "provider" else [])
            for name in accounts:
                self.create_object(plane, dict(apiVersion="v1", kind="ServiceAccount", metadata=dict(name=name, namespace=ns)))
            self.rbac(plane, "ClusterRoleBinding", self.c + "-reader",
                      role=("ClusterRole", MGMT_READER if plane == "management" else PROVIDER_READER))
        self.rbac("management", "RoleBinding", self.c, namespace=LEDGER, role=("Role", "ok-cluster-teardown-ledger"))

    @staticmethod
    def rule(group, resources, verbs, names=None):
        return dict(apiGroups=[group], resources=resources, verbs=verbs,
                    **({"resourceNames": names} if names else {}))

    def teardown_rules(self, plane):
        r = self.rule
        if plane == "management":
            # The completed-receipt retry must GET the absent Cluster after its
            # namespace (and every RoleBinding in it) has been deleted.
            return [(None, [r("cluster.x-k8s.io", ["clusters"], ["get", "delete"], [self.c])]),
                    (None, [r("", ["namespaces"], ["get", "delete"], [self.c])])]
        golden = self.state["golden"]
        auth = self.c + "-talos-golden-image-cloner"
        storage = self.state.get("storage_authority", {"volumes": [], "snapshots": []})
        volume_rule = [r("", ["persistentvolumes"], ["get", "delete"], storage["volumes"])] if storage["volumes"] else []
        longhorn_rule = [r("longhorn.io", ["volumes"], ["get", "delete"], storage["volumes"])] if storage["volumes"] else []
        snapshot_rule = [r("snapshot.storage.k8s.io", ["volumesnapshots"], ["get", "delete"], storage["snapshots"])] if storage["snapshots"] else []
        return [(self.c, [r("cdi.kubevirt.io", ["datavolumes"], ["get", "list"]),
                          r("", ["persistentvolumeclaims"], ["get", "list"])]),
                # kubectl confirms a namespaced 404 by reading the object's Namespace,
                # so absence checks in longhorn-system and ok-images need that get.
                (None, [r("", ["namespaces"], ["get", "delete"], [self.c]),
                        r("", ["namespaces"], ["get"], ["longhorn-system", "ok-images"]),
                        *volume_rule]),
                ("longhorn-system", longhorn_rule),
                ("ok-images", [r("", ["persistentvolumeclaims"], ["get"], [golden]),
                    r("rbac.authorization.k8s.io", ["roles", "rolebindings"], ["get", "delete"], [auth]),
                    r("snapshot.storage.k8s.io", ["volumesnapshots"], ["list"]), *snapshot_rule])]

    def refresh_teardown_roles(self):
        current = self.snapshot(self.c)
        receipt = self.ledger()
        record = json.loads(receipt["data"]["record.json"]) if receipt else {}
        volumes = {name for name, _ in current["provider/pv"]}
        volumes.update(record.get("persistent_volumes", []))
        volumes.update(self.state.get("storage_authority", {}).get("volumes", []))
        dvs = {uid for _, uid in current["provider/datavolumes"]} | set(record.get("data_volume_uids", []))
        snapshots = self.obj("provider", "volumesnapshots", namespace="ok-images")["items"]
        names = {o["metadata"]["name"] for o in snapshots
                 if o["metadata"].get("labels", {}).get("cdi.kubevirt.io/OwnedByUID") in dvs}
        names.update(self.state.get("storage_authority", {}).get("snapshots", []))
        self.state["storage_authority"] = dict(volumes=sorted(volumes), snapshots=sorted(names))
        self.save()
        self.install_extra_roles()

    def install_extra_roles(self):
        for plane in self.configs:
            for index, (namespace, rules) in enumerate(self.teardown_rules(plane)):
                if namespace == self.c and self.obj(plane, "namespace", self.c) is None:
                    # Namespace-scoped inventory authority vanished with the
                    # guest. An incomplete storage-cleanup retry no longer
                    # needs it and must not recreate the guest Namespace.
                    continue
                name = f"{self.c}-{plane}-{index}"
                kind = "Role" if namespace else "ClusterRole"
                self.e.emit(f"RBAC {plane} {namespace or 'cluster'} {json.dumps(rules, sort_keys=True)}")
                previous = next((o for o in self.state["resources"] if o["plane"] == plane and
                                 o["kind"] == kind and o["name"] == name and o["namespace"] == namespace), None)
                if previous:
                    obj = self.obj(plane, kind, name, namespace)
                    require(obj and obj["metadata"]["uid"] == previous["uid"], "teardown role UID changed")
                    if obj.get("rules") != rules:
                        obj["rules"] = rules
                        self.k(plane, ["replace", "-f", "-"], data=json.dumps(obj))
                else:
                    self.rbac(plane, kind, name, namespace=namespace, rules=rules)
                for account in (["teardown", "denied"] if plane == "provider" else ["teardown"]):
                    binding = name + "-" + account
                    saved = next((o for o in self.state["resources"] if o["plane"] == plane and
                                  o["kind"] == kind + "Binding" and o["name"] == binding and o["namespace"] == namespace), None)
                    if saved:
                        obj = self.obj(plane, kind + "Binding", binding, namespace)
                        require(obj and obj["metadata"]["uid"] == saved["uid"] and
                                obj["roleRef"] == dict(apiGroup="rbac.authorization.k8s.io", kind=kind, name=name) and
                                obj["subjects"] == [dict(kind="ServiceAccount", name=account, namespace=self.c + "-proof")],
                                "teardown binding identity changed")
                        continue
                    self.rbac(plane, kind + "Binding", name + "-" + account, namespace=namespace,
                              role=(kind, name), account=account)

    def credential(self, plane, account):
        duration = "4h" if account == "capk" else "1h"
        token = self.k(plane, ["create", "token", account, "-n", self.c + "-proof", "--duration=" + duration]).stdout.strip()
        require(token and not any(c.isspace() for c in token), "TokenRequest returned invalid token")
        # Only the selected endpoint/CA are read; no source user credentials.
        result = self.k(plane, ["config", "view", "--minify", "--flatten", "--raw", "-o",
                               'jsonpath={.clusters[0].cluster}'])
        transport = json.loads(result.stdout)
        require(transport.get("server", "").startswith("https://") and transport.get("certificate-authority-data")
                and not transport.get("insecure-skip-tls-verify") and not transport.get("proxy-url"),
                "verified static HTTPS endpoint and embedded CA required")
        return dict(apiVersion="v1", kind="Config", **{"current-context": "proof"},
                    clusters=[dict(name="proof", cluster={k: transport[k] for k in ("server", "certificate-authority-data")})],
                    users=[dict(name="proof", user=dict(token=token))],
                    contexts=[dict(name="proof", context=dict(cluster="proof", user="proof", namespace=self.c))])

    def create(self):
        self.need_state()
        require(not self.state.get("created"), "create is not replayable; teardown the existing proof")
        clusters = json.loads(self.k("management", ["get", "clusters.cluster.x-k8s.io", "-A", "-o", "json"]).stdout)["items"]
        existing = {o["metadata"]["name"] for o in clusters}
        existing.update(self.c for p in self.configs if self.obj(p, "namespace", self.c))
        guard(self.c, *[self.state["planes"][p] for p in self.configs], existing, True, os.environ.get("OK197_SPLIT_CONFIRM"))
        require(not (ROOT / self.c).exists(), "local render exists")
        require(not self.state["resources"], "partial create exists; teardown/recover before a new create")
        self.make("install-teardown-ledger", CONFIRM="yes")
        self.make("install-teardown-provider-reader", CONFIRM="yes")
        # `new` allocates the endpoint IP from live LoadBalancer Services; CAPK creates the guest's
        # control-plane Service on the provider plane, so allocation must read that plane.
        self.make("new", management=self.configs["provider"], TYPE="talos", WORKERS="1", HA="false",
                  K8S_VERSION="v1.34.1", TALOS_VERSION="v1.9.6")
        config_path = ROOT / self.c / "cluster-config.yaml"
        config = yaml.safe_load(config_path.read_text())
        config["infraClusterSecretRef"] = dict(name="external-infra-kubeconfig-" + self.c, namespace=self.c)
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))
        self.make("render", management=self.configs["provider"])
        config = yaml.safe_load(config_path.read_text())
        self.state["golden"] = config["os"]["goldenImage"]["claim"]
        self.save()
        documents = list(yaml.safe_load_all((ROOT / self.c / "cluster-base.yaml").read_text()))
        split = split_documents(documents, self.c)
        for plane, objects in split.items():
            for obj in objects:
                self.e.emit(f"SPLIT {plane} {obj['apiVersion']} {obj['kind']} "
                            f"{obj['metadata'].get('namespace', '-')}/{obj['metadata']['name']}")
        # Namespaces first, then credentials, then CAPI reconciliation.
        for plane, objects in split.items():
            for obj in objects:
                if obj["kind"] == "Namespace":
                    self.create_object(plane, obj)
        self.state["provider_namespace_uid"] = self.obj("provider", "namespace", self.c)["metadata"]["uid"]
        self.save()
        self.identities()
        # Reuse the repository's projected provider Role, including its exact verb set.
        self.run([sys.executable, "render.py", "projection", "--cluster", self.c,
                  "--intent-revision", "sha256:" + "1" * 64, "--output", str(ROOT / self.c / "proof-projection")],
                 label="render provider lifecycle authority")
        projection = list(yaml.safe_load_all((ROOT / self.c / "proof-projection" / "ok-infra-prerequisites.yaml").read_text()))
        role = next(o for o in projection if o["kind"] == "Role" and o["metadata"]["namespace"] == self.c)
        self.e.emit("CAPK RBAC " + json.dumps(role["rules"], sort_keys=True))
        self.create_object("provider", role)
        self.rbac("provider", "RoleBinding", self.c + "-capk", namespace=self.c,
                  role=("Role", role["metadata"]["name"]), account="capk")
        provider_config = self.credential("provider", "capk")
        try:
            payload = provider_config["users"][0]["user"]["token"].split(".")[1]
            expiry = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"]
        except (KeyError, IndexError, ValueError) as error:
            raise ProofError("CAPK TokenRequest must return a JWT with expiration") from error
        require(isinstance(expiry, int) and time.time() + 12600 < expiry <= time.time() + 14460,
                "CAPK token must have 210-241 minutes remaining; refusing shortened or unbounded credential")
        self.state["capk_expires_at"] = expiry
        self.save()
        self.create_object("management", dict(apiVersion="v1", kind="Secret",
            metadata=dict(name="external-infra-kubeconfig-" + self.c, namespace=self.c),
            type="Opaque", immutable=True,
            data=dict(kubeconfig=base64.b64encode(yaml.safe_dump(provider_config).encode()).decode())))
        for plane in ("provider", "management"):
            for obj in split[plane]:
                if obj["kind"] != "Namespace":
                    self.create_object(plane, obj)
                    if plane == "management" and obj["kind"] == "Cluster":
                        self.state["created"] = True
                        self.save()
        self.state["created"] = True
        self.save()
        self.ready(config)
        self.refresh_teardown_roles()
        require(time.time() + 1800 < self.state["capk_expires_at"],
                "CAPK credential has less than 30 minutes remaining; do not delay coordinator recovery")
        self.e.check("split guest nodes Ready; external CAPK credential is bounded to guest namespace")

    def ready(self, config):
        # Combined bootstrap-post-apply uses one kubeconfig for both planes.
        # Reuse its individual entrypoints/gate with the correct authority instead.
        deadline = time.monotonic() + 1200
        self.make("annotate-pvcs", management=self.configs["provider"])
        while True:
            secret = self.obj("management", "secret", self.c + "-kubeconfig", self.c)
            if secret:
                break
            require(time.monotonic() < deadline, "guest kubeconfig not ready within 20 minutes")
            time.sleep(10)
        guest = yaml.safe_load(base64.b64decode(secret["data"]["value"]))
        with memory_config(guest) as (path, fd):
            self.fds = (fd,)
            try:
                while True:
                    result = self.run(["kubectl", "--kubeconfig", path, "get", "nodes", "-o", "json"],
                                      allowed=(0, 1), label="wait guest API registration")
                    if result.returncode == 0 and json.loads(result.stdout).get("items"):
                        break
                    require(time.monotonic() < deadline, "guest API not registered within 20 minutes")
                    time.sleep(10)
                self.run(["make", "--no-print-directory", "-o", "kubeconfig", "install-cni",
                    "CLUSTER=" + self.c, "GUEST_KUBECONFIG=" + path,
                    "OK_CLI_VERSION=proof", "OK_CLI_REVISION=proof"], label="make install-cni", output=True)
                expected = int(config["controlPlane"]["replicas"]) + int(config["workers"]["replicas"])
                while True:
                    nodes = json.loads(self.run(["kubectl", "--kubeconfig", path, "get", "nodes", "-o", "json"],
                                                label="wait expected guest node count").stdout)["items"]
                    if len(nodes) == expected:
                        break
                    require(time.monotonic() < deadline, "guest node count differs from rendered replicas after 20 minutes")
                    time.sleep(10)
                seconds = min(600, int(deadline - time.monotonic()))
                require(seconds > 0, "guest readiness deadline elapsed before node Ready gate")
                self.run(["kubectl", "--kubeconfig", path, "wait", "--for=condition=Ready", "nodes", "--all", f"--timeout={seconds}s"],
                         label="existing guest node Ready gate", output=True)
                nodes = json.loads(self.run(["kubectl", "--kubeconfig", path, "get", "nodes", "-o", "json"], label="count Ready nodes").stdout)["items"]
                require(len(nodes) == expected,
                        "guest node count differs from rendered replicas")
            finally:
                self.fds = ()

    @contextmanager
    def traced_identities(self, phase, denied=False):
        # The wrapper captures kubectl -v=6 in memory, publishing only HTTP paths.
        # It never writes credentials, headers, endpoint hosts or response bodies.
        real = shutil.which("kubectl")
        require(real, "kubectl required")
        trace = self.e.directory / f"{stamp()}-{phase}-http.jsonl"
        trace.touch(mode=0o600, exist_ok=False)
        with memory_config(self.credential("management", "teardown")) as (mgmt, mf), \
             memory_config(self.credential("provider", "denied" if denied else "teardown")) as (infra, pf), \
             tempfile.TemporaryDirectory(prefix="ok197-kubectl-") as directory:
            wrapper = Path(directory) / "kubectl"
            wrapper.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(Path(__file__).resolve())!r}, run_name='__trace__')\n")
            wrapper.chmod(0o700)
            # Lifecycle resolves kubeconfig paths and tests is_file(). memfd
            # symlinks cannot survive that resolve. Credential-free handles do;
            # only this wrapper translates them to the memory-backed configs.
            handles = []
            for plane in ("management", "provider"):
                handle = Path(directory) / (plane + ".yaml")
                with handle.open("x") as out:
                    out.write("# credential-free proof handle; usable only by the trace wrapper\n")
                handles.append(str(handle))
            previous, oldfds = self.env, self.fds
            self.env = dict(previous, PATH=directory + os.pathsep + previous.get("PATH", ""),
                            OK197_REAL_KUBECTL=real, OK197_HTTP_TRACE=str(trace),
                            OK197_TRACE_MGMT=handles[0],
                            OK197_MEMORY_CONFIGS=json.dumps(dict(zip(handles, (mgmt, infra)))))
            self.fds = (mf, pf)
            try:
                yield *handles, trace
            finally:
                self.env, self.fds = previous, oldfds

    def auth(self, after=False):
        for plane in self.configs:
            principal = f"system:serviceaccount:{self.c}-proof:teardown"
            checks = [(ns, rules) for ns, rules in self.teardown_rules(plane)]
            manifest = "talos-teardown-ledger.yaml" if plane == "management" else "talos-teardown-provider-reader.yaml"
            for obj in yaml.safe_load_all((ROOT / "deploy" / manifest).read_text()):
                if obj and obj["kind"] in {"Role", "ClusterRole"}:
                    checks.append((obj["metadata"].get("namespace"), obj["rules"]))
            queries = set()
            for ns, rules in checks:
                for rule in rules:
                    for group in rule["apiGroups"]:
                        for resource in rule["resources"]:
                            resource = resource + ("." + group if group else "")
                            for verb in rule["verbs"]:
                                for name in rule.get("resourceNames", [None]):
                                    queries.add((verb, resource + ("/" + name if name else ""), ns,
                                                 not (after and ns == self.c)))
            for verb in ("update", "delete", "list"):
                queries.add((verb, "configmaps", LEDGER, False))
            for verb in ("get", "list", "create", "patch", "update", "delete", "watch"):
                for resource in ("configmaps", "secrets"):
                    queries.add((verb, resource, "kube-system", False))
            queries.update({("create", "namespaces", None, False), ("list", "namespaces", None, False)})
            if plane == "management":
                queries.add(("delete", "clusters.cluster.x-k8s.io/" + PROTECTED, PROTECTED, False))
            else:
                queries.update({("delete", "persistentvolumes/ok197-unowned", None, False),
                    ("delete", "volumes.longhorn.io/ok197-unowned", "longhorn-system", False),
                    ("delete", "volumesnapshots.snapshot.storage.k8s.io/ok197-unowned", "ok-images", False)})
            if plane == "provider":
                for verb in ("get", "create", "patch"):
                    queries.add((verb, "configmaps", LEDGER, False))
            for verb, resource, ns, expected in sorted(queries, key=str):
                args = ["auth", "can-i", verb, resource, "--as", principal]
                if ns:
                    args.extend(["-n", ns])
                result = self.k(plane, args, allowed=(0, 1))
                require(result.stdout.strip() == ("yes" if expected else "no") and
                        result.returncode == (0 if expected else 1), f"auth mismatch: {plane} {verb} {resource}")
                self.e.check(f"auth {plane} {verb} {resource} {ns or '-'} = {'yes' if expected else 'no'}")

    def teardown(self):
        self.need_state()
        require(self.state.get("created"), "create must complete manifest submission first")
        cm = self.ledger()
        already_complete = cm and json.loads(cm["data"]["record.json"]).get("complete") is True
        cluster = self.obj("management", "clusters.cluster.x-k8s.io", self.c, self.c)
        if cluster:
            recorded = next((o for o in self.state["resources"] if o["plane"] == "management"
                             and o["kind"] == "Cluster" and o["name"] == self.c
                             and o["namespace"] == self.c), None)
            require(recorded and cluster["metadata"]["uid"] == recorded["uid"], "management Cluster UID changed")
        require(not cluster or time.time() + 1800 < self.state.get("capk_expires_at", 0),
                "CAPK credential needs at least 30 minutes remaining for foreground deletion; coordinator recovery required")
        if not already_complete:
            self.refresh_teardown_roles()
        namespace = self.obj("provider", "namespace", self.c)
        self.auth(after=namespace is None or bool(namespace["metadata"].get("deletionTimestamp")))
        if not self.state.get("denied_proven"):
            denied_auth = self.k("provider", ["auth", "can-i", "get", "namespace/kube-system", "--as",
                                 f"system:serviceaccount:{self.c}-proof:denied"], allowed=(0, 1))
            require(denied_auth.returncode == 1 and denied_auth.stdout.strip() == "no", "denied identity unexpectedly has plane reader")
            before = self.ledger()
            before_objects = self.snapshot(self.c)
            with self.traced_identities("denied", denied=True) as (mgmt, infra, trace):
                result = self.make("teardown", management=mgmt, provider=infra, allowed=(2,),
                                   TALOS_TEARDOWN_PRESERVE_LOCAL="yes", CONFIRM="yes")
            requests = [json.loads(line) for line in trace.read_text().splitlines()]
            assert_trace(requests, denied=True)
            require("Forbidden" in result.stderr or "forbidden" in result.stderr, "expected provider plane-binding Forbidden")
            require(self.ledger() == before, "denied path changed ledger")
            require(self.snapshot(self.c) == before_objects, "denied path changed guest names/UIDs")
            self.state["denied_proven"] = True
            self.save()
            self.e.check("provider without Namespace reader: 403 before any mutation; ledger byte-identical")
        # Keep the original names through interrupted teardown retries.
        if "before_teardown" not in self.state:
            self.state["before_teardown"] = self.snapshot(self.c)
        self.save()
        with self.traced_identities("success") as (mgmt, infra, trace):
            self.make("teardown", management=mgmt, provider=infra, TALOS_TEARDOWN_PRESERVE_LOCAL="yes", CONFIRM="yes")
        assert_trace([json.loads(line) for line in trace.read_text().splitlines()])
        self.e.check("successful split teardown: exactly one kube-system Namespace GET per plane")
        self.verify()

    def verify(self):
        self.need_state()
        require(self.state.get("denied_proven"), "denied-path evidence missing")
        cm = self.ledger()
        require(cm, "management receipt absent")
        record = json.loads(cm["data"]["record.json"])
        lifecycle = load_module("ok197_lifecycle", ROOT / "scripts/talos_golden_lifecycle.py")
        lifecycle.validate_teardown_record(record, self.c)
        expected = dict(management_uid=self.state["planes"]["management"],
                        provider_uid=self.state["planes"]["provider"],
                        provider_namespace_uid=self.state["provider_namespace_uid"])
        require(record["schema_version"] == 2 and record["complete"] is True and record["planes"] == expected,
                "receipt is not complete schema-2 with captured live Namespace UIDs")
        require(self.ledger("provider") is None, "wrong-plane receipt exists")
        self.auth(after=True)
        with self.traced_identities("retry") as (mgmt, infra, trace):
            self.make("teardown", management=mgmt, provider=infra, TALOS_TEARDOWN_PRESERVE_LOCAL="yes", CONFIRM="yes")
        requests = [json.loads(line) for line in trace.read_text().splitlines()]
        assert_trace(requests)
        require(not any(r["method"] in {"POST", "PATCH", "PUT", "DELETE"} for r in requests), "completed retry mutated API")
        require(self.ledger() == cm, "completed retry changed receipt")
        self.e.check("completed receipt retry is idempotent with zero mutations")
        with self.traced_identities("prune") as (mgmt, infra, trace):
            result = self.make("prune-teardown-ledger", management=mgmt, provider=infra, allowed=(2,), CONFIRM="yes")
        require("split-plane teardown record cannot be pruned without provider-plane absence proof" in result.stderr,
                "missing documented schema-2 prune refusal")
        require(not any(json.loads(line)["method"] == "DELETE" for line in trace.read_text().splitlines()), "prune issued a delete")
        require(self.ledger() == cm, "prune changed receipt")
        self.state["record"] = record
        self.save()
        self.e.check("schema-2 receipt only on management; prune refused with zero deletes and receipt unchanged")

    def cleanup_check(self):
        self.need_state()
        complete = self.state.get("record", {}).get("complete")
        partial = not self.state.get("created")
        require(complete or partial, "run successful teardown/verify first")
        remaining = self.snapshot(self.c)
        if partial:
            # A failure before submitting the CAPI Cluster cannot have started
            # reconciliation. Never remove a partial guest that contains data.
            harmless = {"management/namespace", "provider/namespace", "provider/role", "provider/rolebinding"}
            require(not any(rows for key, rows in remaining.items() if key not in harmless),
                    "partial create has live guest/data objects; coordinator recovery required")
        else:
            require(not any(remaining.values()), "guest objects remain on one or both planes")
        record = self.state.get("record", {"persistent_volumes": [], "data_volume_uids": []})
        # Check saved names as well as claimRefs; a deleted PVC must not hide an orphan.
        names = set(record["persistent_volumes"])
        names.update(n for n, _ in self.state.get("before_teardown", {}).get("provider/pv", []))
        for name in names:
            require(self.obj("provider", "pv", name) is None, "saved PV remains")
            require(self.obj("provider", "volumes.longhorn.io", name, "longhorn-system") is None, "saved Longhorn volume remains")
        uids = set(record["data_volume_uids"])
        snapshots = self.obj("provider", "volumesnapshots", namespace="ok-images")["items"]
        require(not any(o["metadata"].get("labels", {}).get("cdi.kubevirt.io/OwnedByUID") in uids for o in snapshots),
                "owned CDI snapshot remains")
        require(self.snapshot(PROTECTED) == self.state["protected"], "protected reference names/UIDs changed")
        # Remove only proof identities/roles/bindings, with server-side UID preconditions.
        disposable = [o for o in self.state["resources"] if o["kind"] in
                      {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Namespace"}]
        for saved in reversed(disposable):
            if saved["kind"] == "Namespace" and saved["name"] == self.c and not partial:
                continue
            plane = saved["plane"]
            obj = self.obj(plane, saved["kind"], saved["name"], saved["namespace"])
            if obj is None:
                continue
            require(obj["metadata"]["uid"] == saved["uid"], "cleanup resource UID changed")
            plurals = {"Namespace": "namespaces", "ServiceAccount": "serviceaccounts", "Role": "roles",
                       "RoleBinding": "rolebindings", "ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings"}
            api = saved["apiVersion"]
            path = "/api/v1" if api == "v1" else "/apis/" + api
            if saved["namespace"]:
                path += "/namespaces/" + saved["namespace"]
            path += "/" + plurals[saved["kind"]] + "/" + saved["name"]
            self.k(plane, ["delete", "--raw", path, "-f", "-"], data=json.dumps(dict(
                apiVersion="v1", kind="DeleteOptions", preconditions=dict(uid=saved["uid"]))))
            deadline = time.monotonic() + 120
            while self.obj(plane, saved["kind"], saved["name"], saved["namespace"]) is not None:
                require(time.monotonic() < deadline, "proof identity cleanup is still pending; retry cleanup-check")
                time.sleep(2)
        require(not any(self.snapshot(self.c).values()), "guest residue remains after cleanup")
        require(self.snapshot(PROTECTED) == self.state["protected"], "protected reference names/UIDs changed during cleanup")
        self.e.check("guest/storage/Golden RBAC/snapshots absent; protected names/UIDs unchanged; proof identities removed")


def traced_kubectl():
    args = sys.argv[1:]
    plane = "management" if os.environ["OK197_TRACE_MGMT"] in args else "provider"
    mapping = json.loads(os.environ["OK197_MEMORY_CONFIGS"])
    translated = [mapping.get(a, a) for a in args]
    result = subprocess.run([os.environ["OK197_REAL_KUBECTL"], "-v=6", *translated], capture_output=True)
    rows = trace_requests(result.stderr.decode(errors="replace"), plane)
    # A transport error may have no completed HTTP response. Record mutation
    # attempts anyway so zero-delete/zero-mutation claims cannot silently pass.
    methods = {"delete": "DELETE", "create": "POST", "patch": "PATCH", "replace": "PUT", "apply": "PATCH"}
    command = next((arg for arg in args if arg in methods), None)
    if command and not any(row["method"] == methods[command] for row in rows):
        rows.append(dict(plane=plane, method=methods[command], path="/unobserved-mutation-attempt", status=0))
    with open(os.environ["OK197_HTTP_TRACE"], "a") as out:
        for row in rows:
            out.write(json.dumps(row) + "\n")
    sys.stdout.buffer.write(result.stdout)
    # Do not forward verbose headers or credentials to lifecycle errors.
    if result.returncode:
        print("Forbidden" if any(r["status"] == 403 for r in rows) else
              "Error from server (NotFound): object absent" if any(r["status"] == 404 for r in rows) else
              "kubectl failed; inspect sanitized HTTP trace", file=sys.stderr)
    raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "create", "teardown", "verify", "cleanup-check"])
    args = parser.parse_args()
    evidence = None
    success = False
    try:
        evidence = Evidence(args.command)
        if args.command in {"create", "teardown", "cleanup-check"}:
            require(os.environ.get("OK197_SPLIT_CONFIRM") == "yes", "OK197_SPLIT_CONFIRM=yes required")
        proof = Proof(evidence)
        getattr(proof, args.command.replace("-", "_"))()
        success = True
        return 0
    except (ProofError, OSError, ValueError, KeyError) as error:
        if evidence:
            evidence.emit("FAIL " + str(error))
        else:
            print("FAIL " + str(error), file=sys.stderr)
        return 1
    except Exception as error:
        # Parser/library exceptions may embed credential-bearing input lines.
        # Preserve the failing operation label without printing raw input.
        if evidence:
            evidence.emit(f"FAIL unexpected {type(error).__name__}; inspect the last operation label")
        return 1
    finally:
        if evidence:
            evidence.finish(success)


if __name__ == "__trace__":
    traced_kubectl()
elif __name__ == "__main__":
    raise SystemExit(main())
