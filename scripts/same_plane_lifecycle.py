"""Explicit same-plane M2b contract; legacy schemas and split routing are unchanged.

All Kubernetes IO goes through the existing lifecycle owner. No credentials are
stored in the public preparation or schema-3 teardown record.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = 3
PREPARATION = ".same-plane-lifecycle.json"


def fail(message):
    from scripts.talos_golden_lifecycle import TalosLifecycleError

    raise TalosLifecycleError(message)


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(life, path):
    cfg = life.kubectl_json(path, ["config", "view", "--minify", "--raw"])
    if len(cfg.get("clusters", [])) != 1 or len(cfg.get("contexts", [])) != 1:
        fail("same-plane identity requires exactly one selected cluster/context")
    c = cfg["clusters"][0]["cluster"]
    context = cfg.get("current-context")
    if not context or cfg["contexts"][0]["name"] != context:
        fail("same-plane current context is ambiguous")
    url = urlsplit(c.get("server", ""))
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or c.get("insecure-skip-tls-verify")
        or c.get("proxy-url")
        or c.get("tls-server-name")
    ):
        fail("same-plane API transport is not explicit verified TLS")
    try:
        if c.get("certificate-authority-data"):
            ca = base64.b64decode(c["certificate-authority-data"], validate=True)
        else:
            ca_path = Path(c["certificate-authority"])
            if not ca_path.is_absolute():
                fail("same-plane CA path must be absolute")
            ca = ca_path.read_bytes()
        ssl.create_default_context(cadata=ca.decode("ascii"))
    except (KeyError, ValueError, OSError, ssl.SSLError) as exc:
        fail(f"same-plane CA cannot be validated: {type(exc).__name__}")
    for user in cfg.get("users", []):
        if any(
            k in user.get("user", {})
            for k in ("exec", "auth-provider", "as", "as-uid", "as-groups")
        ):
            fail("same-plane authentication plugins/impersonation are unsupported")
    return {
        "context": context,
        "cluster": cfg["clusters"][0]["name"],
        "endpoint": c["server"],
        "caSHA256": fingerprint(ca),
        "kubeSystemUID": life.teardown_plane_uid(path),
    }


def artifacts(life, args):
    config = life.local_teardown_config(args)
    if config is None or not life.has_golden_config(config):
        fail("same-plane M2b requires original resolved Talos Golden config/render")
    if "infraClusterSecretRef" in config:
        fail("same-plane M2b rejects external provider references")
    directory = life.cluster_directory(args)
    result = {}
    for name in ("cluster-config.yaml", "cluster-base.yaml"):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
            fail("same-plane original artifact is absent/unsafe/oversized")
        raw = path.read_bytes()
        result[name] = {"sha256": fingerprint(raw), "content": raw.decode("utf-8")}
    for obj in life.objects(directory / "cluster-base.yaml"):
        if obj.get("kind") == "KubevirtCluster" and "infraClusterSecretRef" in obj.get(
            "spec", {}
        ):
            fail("same-plane render has an external provider reference")
    return config, result


def selected_identity(life, args):
    if not args.provider_kubeconfig:
        fail("same-plane requires explicit management and provider kubeconfigs")
    management = Path(args.kubeconfig).expanduser().resolve()
    provider = Path(args.provider_kubeconfig).expanduser().resolve()
    m, p = identity(life, management), identity(life, provider)
    if m != p:
        fail("same-plane management/provider API identities differ")
    return management, provider, m


def require_authority(life, path, cluster):
    checks = [
        ("delete", "clusters.cluster.x-k8s.io", cluster),
        ("delete", "namespaces", None),
        ("delete", "persistentvolumes", None),
        ("delete", "volumes.longhorn.io", "longhorn-system"),
        ("delete", "roles", "ok-images"),
        ("delete", "rolebindings", "ok-images"),
        ("delete", "volumesnapshots.snapshot.storage.k8s.io", "ok-images"),
        ("create", "configmaps", life.TEARDOWN_LEDGER_NAMESPACE),
        ("patch", "configmaps", life.TEARDOWN_LEDGER_NAMESPACE),
    ]
    for resource in (
        "volumes.longhorn.io",
        "engines.longhorn.io",
        "replicas.longhorn.io",
        "snapshots.longhorn.io",
        "volumeattachments.longhorn.io",
    ):
        life.kubectl_json(path, ["-n", "longhorn-system", "get", resource])
    life.kubectl_json(path, ["get", "volumeattachments.storage.k8s.io"])
    for verb, resource, namespace in checks:
        args = ["auth", "can-i", verb, resource]
        if namespace:
            args += ["-n", namespace]
        answer = life.kubectl(path, args)
        if answer.stdout.strip() != "yes":
            fail("same-plane cleanup authority is unavailable")


def preparation(life, args, *, create=False):
    management, provider, current = selected_identity(life, args)
    config, original = artifacts(life, args)
    path = life.cluster_directory(args) / PREPARATION
    expected = {
        "format": "ok76-same-plane-preparation/v1",
        "topology": "same-plane",
        "cluster": args.cluster,
        "identity": current,
        "artifacts": original,
        "golden": life.verify_golden(config, provider),
        "ledgerNamespaceUID": life.require_teardown_ledger_namespace(management)[
            "metadata"
        ]["uid"],
    }
    if path.is_symlink():
        fail("same-plane preparation must not be a symlink")
    if create:
        if (life.cluster_directory(args) / PROVISIONED).exists():
            fail("same-plane bootstrap already applied; do not replay bootstrap")
        if (
            life.kubectl_json_optional(management, ["get", "namespace", args.cluster])
            is not None
        ):
            fail("same-plane bootstrap refuses a pre-existing target namespace")
        require_authority(life, management, args.cluster)
    if path.exists():
        if path.stat().st_size > 600 * 1024 or json.loads(path.read_text()) != expected:
            fail("same-plane preparation identity/artifacts changed")
    elif create:
        if (
            life.kubectl_json_optional(management, ["get", "namespace", args.cluster])
            is not None
        ):
            fail("same-plane preparation refuses a pre-existing target namespace")
        life.require_teardown_ledger_namespace(management)
        # Verify Golden identity/readability and deletion authority prerequisites,
        # without creating a ledger, token, or any live object.
        life.verify_golden(config, provider)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(json.dumps(expected, sort_keys=True, indent=2) + "\n")
    else:
        fail("original same-plane preparation is missing; no reconstruction/fallback")
    return management, provider, config, expected


PROVISIONED = ".same-plane-provisioned.json"


def capture(life, args):
    path, _, _, prep = preparation(life, args)
    ns = life.kubectl_json(path, ["get", "namespace", args.cluster])
    cluster = life.kubectl_json(
        path, ["-n", args.cluster, "get", "cluster", args.cluster]
    )
    expected = next(
        o
        for o in life.objects(life.cluster_directory(args) / "cluster-base.yaml")
        if o.get("kind") == "Cluster"
        and o.get("metadata", {}).get("name") == args.cluster
    )
    if cluster.get("metadata", {}).get("namespace") != args.cluster or cluster.get(
        "spec", {}
    ).get("infrastructureRef") != expected.get("spec", {}).get("infrastructureRef"):
        fail("same-plane applied Cluster differs from original render")
    value = {
        "format": "ok76-same-plane-provisioned/v1",
        "identity": prep["identity"],
        "namespaceUID": ns["metadata"].get("uid"),
        "clusterUID": cluster["metadata"].get("uid"),
    }
    if not value["namespaceUID"] or not value["clusterUID"]:
        fail("same-plane applied UIDs are missing")
    target = life.cluster_directory(args) / PROVISIONED
    if target.is_symlink():
        fail("same-plane provisioned identity must not be a symlink")
    if target.exists():
        if json.loads(target.read_text()) != value:
            fail("same-plane provisioned identity changed")
    else:
        with os.fdopen(
            os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as out:
            out.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return value


def check_capture(life, args, identity):
    target = life.cluster_directory(args) / PROVISIONED
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 4096:
        fail("original provisioned UID evidence is absent/unsafe; no reconstruction")
    saved = json.loads(target.read_text())
    if (
        set(saved) != {"format", "identity", "namespaceUID", "clusterUID"}
        or saved["format"] != "ok76-same-plane-provisioned/v1"
        or saved["identity"] != identity
        or not saved["namespaceUID"]
        or not saved["clusterUID"]
    ):
        fail("same-plane provisioned identity is invalid")
    return saved


def validate_record(life, record, cluster):
    required = {
        "schema_version",
        "cluster",
        "namespace_uid",
        "config",
        "golden_before",
        "data_volume_uids",
        "persistent_volumes",
        "complete",
        "topology",
        "identity",
        "artifacts",
        "storage_bindings",
    }
    if set(record) != required or record.get("topology") != "same-plane":
        fail("same-plane schema-3 record fields/topology are invalid")
    # Reuse the unchanged schema-1 structural validation, then enforce all new bindings.
    legacy = {
        k: v
        for k, v in record.items()
        if k not in {"topology", "identity", "artifacts", "storage_bindings"}
    }
    legacy["schema_version"] = 1
    life.validate_teardown_record(legacy, cluster)
    ident = record["identity"]
    if (
        not isinstance(ident, dict)
        or set(ident) != {"context", "cluster", "endpoint", "caSHA256", "kubeSystemUID"}
        or not all(isinstance(v, str) and v for v in ident.values())
    ):
        fail("same-plane record API identity is invalid")
    if set(record["artifacts"]) != {"cluster-config.yaml", "cluster-base.yaml"}:
        fail("same-plane record original artifacts are missing")
    for value in record["artifacts"].values():
        if (
            not isinstance(value, dict)
            or set(value) != {"sha256", "content"}
            or not isinstance(value["content"], str)
            or fingerprint(value["content"].encode()) != value["sha256"]
        ):
            fail("same-plane record artifact digest differs")
    if not isinstance(record["artifacts"], dict):
        fail("same-plane artifacts must be a mapping")
    bindings = record["storage_bindings"]
    if not isinstance(bindings, dict) or set(bindings) != set(
        record["persistent_volumes"]
    ):
        fail("same-plane storage provenance is incomplete")
    for name, b in bindings.items():
        if (
            not isinstance(b, dict)
            or set(b)
            != {
                "pvUID",
                "pvcName",
                "pvcUID",
                "volumeHandle",
                "longhornUID",
                "dataVolumeUID",
                "vmUID",
                "kubevirtMachineUID",
                "machineUID",
            }
            or not all(isinstance(v, str) and v for v in b.values())
            or b["volumeHandle"] != name
        ):
            fail("same-plane PVC/PV/CSI/Longhorn provenance is invalid")


def storage(life, path, cluster, saved=None, *, observed=None):
    saved = saved or {}
    claims = life.kubectl_json(path, ["-n", cluster, "get", "pvc"])["items"]
    dvs = life.kubectl_json(path, ["-n", cluster, "get", "datavolumes"])["items"]
    dv_by_name = {d["metadata"]["name"]: d for d in dvs}
    vms = life.kubectl_json(
        path, ["-n", cluster, "get", "virtualmachines.kubevirt.io"]
    )["items"]
    machines = life.kubectl_json(
        path, ["-n", cluster, "get", "kubevirtmachines.infrastructure.cluster.x-k8s.io"]
    )["items"]
    capi_machines = life.kubectl_json(
        path, ["-n", cluster, "get", "machines.cluster.x-k8s.io"]
    )["items"]
    capi_by_uid = {
        m["metadata"].get("uid"): m
        for m in capi_machines
        if m.get("metadata", {}).get("labels", {}).get("cluster.x-k8s.io/cluster-name")
        == cluster
    }
    capk_by_name = {
        m["metadata"]["name"]: m
        for m in machines
        if m.get("metadata", {}).get("labels", {}).get("cluster.x-k8s.io/cluster-name")
        == cluster
    }
    vm_bindings = {}
    for vm in vms:
        meta = vm["metadata"]
        labels = meta.get("labels", {})
        capk = capk_by_name.get(
            labels.get("capk.cluster.x-k8s.io/kubevirt-machine-name")
        )
        if (
            not capk
            or labels.get("capk.cluster.x-k8s.io/kubevirt-machine-namespace") != cluster
            or labels.get("cluster.x-k8s.io/cluster-name") != cluster
        ):
            fail("same-plane VM CAPK label ownership differs")
        owners = capk["metadata"].get("ownerReferences", [])
        capi = next(
            (
                capi_by_uid[o.get("uid")]
                for o in owners
                if o.get("kind") == "Machine" and o.get("uid") in capi_by_uid
            ),
            None,
        )
        ref = (capi or {}).get("spec", {}).get("infrastructureRef", {})
        if (
            not capi
            or ref.get("kind") != "KubevirtMachine"
            or ref.get("name") != capk["metadata"]["name"]
            or ref.get("namespace", cluster) != cluster
        ):
            fail("same-plane CAPK/CAPI Machine ownership differs")
        for owner in meta.get("ownerReferences", []):
            if owner.get("kind") != "KubevirtMachine" or owner.get("uid") != capk[
                "metadata"
            ].get("uid"):
                fail("same-plane VM has an unexpected ownerReference")
        for machine in (capi, capk):
            if machine.get("spec", {}).get("providerID") not in (
                None,
                "",
                "kubevirt://" + meta["name"],
            ):
                fail("same-plane VM providerID differs from CAPK/CAPI mapping")
        vm_bindings[meta["uid"]] = {
            "vmUID": meta["uid"],
            "kubevirtMachineUID": capk["metadata"]["uid"],
            "machineUID": capi["metadata"]["uid"],
        }
    dv_bindings = {}
    for dv in dvs:
        owners = dv["metadata"].get("ownerReferences", [])
        if (
            len(owners) != 1
            or owners[0].get("kind") != "VirtualMachine"
            or owners[0].get("uid") not in vm_bindings
        ):
            fail("same-plane DataVolume ownership is not a target VM")
        dv_bindings[dv["metadata"]["uid"]] = vm_bindings[owners[0]["uid"]]
    result = dict(saved)
    for claim in claims:
        m = claim["metadata"]
        pvname = claim.get("spec", {}).get("volumeName")
        if not pvname:
            fail("same-plane PVC is not bound; storage provenance incomplete")
        dv = dv_by_name.get(m["name"])
        owners = m.get("ownerReferences", [])
        if not dv or not any(
            o.get("uid") == dv["metadata"].get("uid") and o.get("kind") == "DataVolume"
            for o in owners
        ):
            fail("same-plane PVC ownership is not its inventoried DataVolume")
        pv = life.kubectl_json(path, ["get", "pv", pvname])
        spec = pv["spec"]
        ref, csi = spec.get("claimRef", {}), spec.get("csi", {})
        if (
            ref.get("namespace") != cluster
            or ref.get("name") != m["name"]
            or not m.get("uid")
            or ref.get("uid") != m["uid"]
            or csi.get("driver") != "driver.longhorn.io"
            or csi.get("volumeHandle") != pvname
            or spec.get("persistentVolumeReclaimPolicy") != "Retain"
        ):
            fail("same-plane PV claimRef/CSI/Retain ownership mismatch")
        lh = life.kubectl_json(
            path, ["-n", "longhorn-system", "get", "volumes.longhorn.io", pvname]
        )
        b = {
            "pvUID": pv["metadata"].get("uid"),
            "pvcName": m["name"],
            "pvcUID": m["uid"],
            "volumeHandle": pvname,
            "longhornUID": lh["metadata"].get("uid"),
            "dataVolumeUID": dv["metadata"]["uid"],
            **dv_bindings[dv["metadata"]["uid"]],
        }
        if not all(b.values()) or (pvname in saved and saved[pvname] != b):
            fail("same-plane storage UID changed")
        result[pvname] = b
    if observed is not None:
        # These are authenticated by the complete ownership graph above. Keep
        # them in memory only; never extend or rewrite historical schema-3 data.
        observed.update(
            {
                kind: {x["metadata"]["uid"]: x for x in values}
                for kind, values in (
                    ("virtualmachines.kubevirt.io", vms),
                    ("kubevirtmachines.infrastructure.cluster.x-k8s.io", machines),
                    ("machines.cluster.x-k8s.io", capi_machines),
                    ("datavolumes", dvs),
                    ("pvc", claims),
                )
            }
        )
    return result


def wait_compute_absent(life, path, cluster, bindings, observed, timeout_seconds):
    """Wait for recorded children, without rebuilding already deleted parents."""
    kinds = {
        "virtualmachines.kubevirt.io": "vmUID",
        "kubevirtmachines.infrastructure.cluster.x-k8s.io": "kubevirtMachineUID",
        "machines.cluster.x-k8s.io": "machineUID",
        "datavolumes": "dataVolumeUID",
        "pvc": "pvcUID",
    }
    deadline = time.monotonic() + min(timeout_seconds, 600)
    while True:
        remaining = []
        for kind, field in kinds.items():
            # A successful empty list proves convergence. API/auth errors must
            # propagate; they are never interpreted as disappearance.
            values = life.kubectl_json(path, ["-n", cluster, "get", kind])["items"]
            expected = {b[field] for b in bindings.values()}
            for obj in values:
                meta = obj["metadata"]
                uid = meta.get("uid")
                if uid not in expected:
                    fail("same-plane unrecorded/replacement compute UID: " + kind)
                before = observed.get(kind, {}).get(uid)
                if before is None:
                    # A resumed historical record binds UIDs, not all original
                    # labels/names. Do not invent missing live ownership proof.
                    fail("same-plane live compute ownership is unproven: " + kind)
                original = before["metadata"]
                if any(
                    meta.get(key) != original.get(key)
                    for key in ("name", "namespace", "labels", "ownerReferences")
                ) or (
                    kind in ("pvc", "datavolumes")
                    and obj.get("spec") != before.get("spec")
                ):
                    fail("same-plane live compute ownership changed: " + kind)
                remaining.append(kind + "/" + meta["name"])
        if not remaining:
            return
        if time.monotonic() >= deadline:
            fail("same-plane recorded compute absence timeout: " + ", ".join(remaining))
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def verify_storage(life, path, cluster, bindings, *, detached=False):
    for name, b in bindings.items():
        pv = life.kubectl_json_optional(path, ["get", "pv", name])
        if pv:
            if (
                pv["metadata"].get("uid") != b["pvUID"]
                or pv.get("spec", {}).get("claimRef", {}).get("uid") != b["pvcUID"]
                or pv["spec"]["claimRef"].get("namespace") != cluster
                or pv["spec"]["claimRef"].get("name") != b["pvcName"]
                or pv["spec"].get("csi", {}).get("volumeHandle") != b["volumeHandle"]
                or pv["spec"].get("csi", {}).get("driver") != "driver.longhorn.io"
                or pv["spec"].get("persistentVolumeReclaimPolicy") != "Retain"
            ):
                fail("same-plane persisted PV/PVC/CSI identity changed")
        lh = life.kubectl_json_optional(
            path, ["-n", "longhorn-system", "get", "volumes.longhorn.io", name]
        )
        if lh and lh["metadata"].get("uid") != b["longhornUID"]:
            fail("same-plane Longhorn UID changed")
        if detached:
            if pv and pv.get("status", {}).get("phase") not in (
                "Released",
                "Available",
            ):
                fail("same-plane retained PV is still bound/in use")
            if lh and (
                lh.get("status", {}).get("state") != "detached"
                or lh.get("spec", {}).get("nodeID")
                or lh.get("spec", {}).get("migrationNodeID")
            ):
                fail("same-plane Longhorn volume is not detached")
    if detached:
        handles = set(bindings)
        for kind in (
            "volumeattachments.storage.k8s.io",
            "persistentvolumeclaims",
            "pods",
        ):
            args = (
                ["get", kind, "-A"]
                if kind != "volumeattachments.storage.k8s.io"
                else ["get", kind]
            )
            for obj in life.kubectl_json(path, args)["items"]:
                if (
                    kind == "volumeattachments.storage.k8s.io"
                    and obj.get("spec", {})
                    .get("source", {})
                    .get("persistentVolumeName")
                    in handles
                ):
                    fail("same-plane CSI attachment remains")
                if (
                    kind == "persistentvolumeclaims"
                    and obj.get("spec", {}).get("volumeName") in handles
                ):
                    fail("same-plane PVC consumer remains")
        for kind in ("engines.longhorn.io", "volumeattachments.longhorn.io"):
            for obj in life.kubectl_json(path, ["-n", "longhorn-system", "get", kind])[
                "items"
            ]:
                if backend_matches(obj, bindings):
                    if kind.startswith("engines") and (
                        obj.get("spec", {}).get("desireState") != "stopped"
                        or obj.get("status", {}).get("currentState") != "stopped"
                    ):
                        fail("same-plane Longhorn engine is not stopped")
                    if kind.startswith("volumeattachments") and obj.get("spec", {}).get(
                        "attachmentTickets"
                    ):
                        fail("same-plane Longhorn attachment tickets remain")


def backend_matches(obj, bindings):
    spec, meta = obj.get("spec", {}), obj.get("metadata", {})
    return (
        meta.get("name") in bindings
        or spec.get("volumeName") in bindings
        or spec.get("volume") in bindings
        or any(
            o.get("uid") in {b["longhornUID"] for b in bindings.values()}
            for o in meta.get("ownerReferences", [])
        )
    )


def absence(life, path, cluster, bindings):
    if life.kubectl_json_optional(path, ["get", "namespace", cluster]) is not None:
        fail("same-plane target namespace remains")
    handles = set(bindings)
    for pv in life.kubectl_json(path, ["get", "pv"])["items"]:
        if pv.get("spec", {}).get("claimRef", {}).get("namespace") == cluster:
            fail("same-plane target PV reference remains outside captured cleanup")
    for kind in (
        "volumes.longhorn.io",
        "engines.longhorn.io",
        "replicas.longhorn.io",
        "snapshots.longhorn.io",
        "volumeattachments.longhorn.io",
    ):
        for obj in life.kubectl_json(path, ["-n", "longhorn-system", "get", kind])[
            "items"
        ]:
            if backend_matches(obj, bindings) or (
                kind == "volumes.longhorn.io"
                and obj.get("status", {}).get("kubernetesStatus", {}).get("namespace")
                == cluster
            ):
                fail(f"same-plane target backend remains: {kind}")
    for obj in life.kubectl_json(path, ["get", "volumeattachments.storage.k8s.io"])[
        "items"
    ]:
        if obj.get("spec", {}).get("source", {}).get("persistentVolumeName") in handles:
            fail("same-plane target CSI attachment remains")
    for name in bindings:
        if life.kubectl_json_optional(path, ["get", "pv", name]) is not None:
            fail("same-plane target PV remains")


def stage(number, text):
    print(f"[{number}/5] {text}", flush=True)


def confirm_cluster_name(record, cluster):
    identity, volumes = record["identity"], record["persistent_volumes"]
    print("Checked against the original ok up evidence (read-only):")
    print(f"  ✓ API identity  context {identity['context']} · {identity['endpoint']}")
    print(f"                  kube-system UID {identity['kubeSystemUID']}")
    print(f"  ✓ Namespace {cluster} UID {record['namespace_uid']}")
    print(f"  ✓ CAPI Cluster {cluster} UID {record['cluster']['uid']}")
    print("  ✓ Golden image unchanged")
    print("Will permanently delete:")
    print(
        f"  CAPI Cluster {cluster}, its KubeVirt VMs,"
        f" {len(record['data_volume_uids'])} DataVolume(s), namespace {cluster}"
    )
    print(
        f"  {len(volumes)} retained volume(s) (PV + Longhorn):"
        f" {', '.join(volumes) or 'none'}"
    )
    print(f"  image-clone access for {cluster} in the Golden image namespace")
    print("Kept: Golden image, other clusters, local evidence, teardown ledger")
    if not sys.stdin.isatty():
        fail("cluster-name confirmation needs an interactive terminal; nothing deleted")
    try:
        answer = input(f"Type {cluster} to delete it, or press Enter to cancel: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip() == cluster


def teardown(life, args):
    path, provider, config, prep = preparation(life, args)
    life.require_teardown_ledger_namespace(path)
    applied = check_capture(life, args, prep["identity"])
    cm = life.read_teardown_configmap(path, args.cluster)
    record = life.teardown_record_from_configmap(cm, args.cluster) if cm else None
    if record and record.get("schema_version") != SCHEMA:
        fail("same-plane refuses legacy/split teardown records; no automatic migration")
    ns = life.kubectl_json_optional(path, ["get", "namespace", args.cluster])
    cluster = life.kubectl_json_optional(
        path, ["-n", args.cluster, "get", "cluster", args.cluster]
    )
    if ns and ns["metadata"].get("uid") != applied["namespaceUID"]:
        fail("same-plane namespace differs from original provisioned UID")
    if cluster and cluster["metadata"].get("uid") != applied["clusterUID"]:
        fail("same-plane Cluster differs from original provisioned UID")
    if record:
        if (
            record["namespace_uid"] != applied["namespaceUID"]
            or record["cluster"]["uid"] != applied["clusterUID"]
        ):
            fail("same-plane record differs from provisioned UIDs")
        if (
            record["identity"] != prep["identity"]
            or record["artifacts"] != prep["artifacts"]
        ):
            fail("same-plane teardown differs from original preparation")
    else:
        if not ns or not cluster:
            fail("same-plane Cluster/Namespace missing before durable provenance")
        if cluster["metadata"].get("namespace") != args.cluster:
            fail("same-plane CAPI Cluster namespace differs")
        kvc_ref = cluster.get("spec", {}).get("infrastructureRef", {})
        if (
            kvc_ref.get("kind") != "KubevirtCluster"
            or kvc_ref.get("namespace", args.cluster) != args.cluster
        ):
            fail("same-plane infrastructureRef is not target KubevirtCluster")
        kvc = life.kubectl_json(
            path, ["-n", args.cluster, "get", "kubevirtcluster", kvc_ref["name"]]
        )
        if "infraClusterSecretRef" in kvc.get("spec", {}) or not any(
            o.get("uid") == cluster["metadata"].get("uid")
            and o.get("kind") == "Cluster"
            for o in kvc["metadata"].get("ownerReferences", [])
        ):
            fail("same-plane live provider ownership/topology differs")
        dv, volumes = life.teardown_inventory(
            provider,
            args.cluster,
            life.teardown_config_subset(config),
            ns["metadata"]["uid"],
            set(),
        )
        bindings = storage(life, provider, args.cluster)
        if set(bindings) != volumes:
            fail("same-plane storage inventory differs")
        record = {
            "schema_version": SCHEMA,
            "topology": "same-plane",
            "identity": prep["identity"],
            "artifacts": prep["artifacts"],
            "cluster": {
                "name": args.cluster,
                "namespace": args.cluster,
                "uid": cluster["metadata"]["uid"],
            },
            "namespace_uid": ns["metadata"]["uid"],
            "config": life.teardown_config_subset(config),
            "golden_before": life.verify_golden(config, provider),
            "data_volume_uids": sorted(dv),
            "persistent_volumes": sorted(volumes),
            "storage_bindings": bindings,
            "complete": False,
        }
    validate_record(life, record, args.cluster)

    observed = {}

    def guard():
        if (
            life.require_teardown_ledger_namespace(path)["metadata"].get("uid")
            != prep["ledgerNamespaceUID"]
        ):
            fail("same-plane ledger Namespace UID changed")
        if selected_identity(life, args)[2] != record["identity"]:
            fail("same-plane API identity changed before mutation")
        if artifacts(life, args)[1] != record["artifacts"]:
            fail("same-plane original artifacts changed before mutation")
        life.bound_resource(
            path,
            ["get", "namespace", args.cluster],
            record["namespace_uid"],
            "Namespace",
        )
        life.bound_resource(
            path,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        current_cluster = life.kubectl_json_optional(
            path, ["-n", args.cluster, "get", "cluster", args.cluster]
        )
        if current_cluster is not None and not current_cluster["metadata"].get(
            "deletionTimestamp"
        ):
            if (
                storage(
                    life,
                    provider,
                    args.cluster,
                    record["storage_bindings"],
                    observed=observed,
                )
                != record["storage_bindings"]
            ):
                fail("same-plane compute/storage ownership changed before mutation")
        verify_storage(
            life,
            provider,
            args.cluster,
            record["storage_bindings"],
            detached=life.kubectl_json_optional(
                path, ["get", "namespace", args.cluster]
            )
            is None,
        )
        if life.verify_golden(config, provider) != record["golden_before"]:
            fail("same-plane Golden identity changed")
        if record["complete"]:
            absence(life, provider, args.cluster, record["storage_bindings"])

    guard()
    if record["complete"]:
        absence(life, provider, args.cluster, record["storage_bindings"])
        print("SKIP same-plane cluster already torn down; original evidence preserved")
        return 0
    if args.confirm == "cluster-name":
        # Only `ok destroy <name>`: confirm the live, UID-bound record that this
        # same process will persist and delete. Nothing has been written yet.
        if not confirm_cluster_name(record, args.cluster):
            print("Cancelled. Nothing deleted.")
            return 0
    else:
        life.confirm_teardown(args.cluster, record["persistent_volumes"], args.confirm)
    guard()
    token = life.MUTATION_GUARD.set(guard)
    try:
        cm = life.persist_teardown_record(path, args.cluster, record, cm)
        current = life.bound_resource(
            path,
            ["-n", args.cluster, "get", "cluster", args.cluster],
            record["cluster"]["uid"],
            "CAPI Cluster",
        )
        stage(1, "Deleting CAPI Cluster (machines and VMs; usually a few minutes)")
        if current:
            life.preconditioned_delete(
                path,
                current,
                life.api_path(current, "clusters", expected_group="cluster.x-k8s.io"),
                ["-n", args.cluster, "get", "cluster", args.cluster],
                "CAPI Cluster",
                propagation_policy="Foreground",
            )
        ns = life.bound_resource(
            path,
            ["get", "namespace", args.cluster],
            record["namespace_uid"],
            "Namespace",
        )
        stage(2, "Waiting for KubeVirt VMs and launcher pods to disappear")
        if ns:
            # CAPK can finish before KubeVirt finishes deleting its children.
            # Their original graph is already durable; never reconstruct it
            # from partially collected lists or adopt new storage during GC.
            wait_compute_absent(
                life,
                provider,
                args.cluster,
                record["storage_bindings"],
                observed,
                getattr(args, "backend_timeout_seconds", 600),
            )
            ns = life.bound_resource(
                path,
                ["get", "namespace", args.cluster],
                record["namespace_uid"],
                "Namespace",
            )
        stage(3, f"Deleting namespace {args.cluster}")
        if ns:
            life.preconditioned_delete(
                path,
                ns,
                life.api_path(ns, "namespaces"),
                ["get", "namespace", args.cluster],
                "Namespace",
                propagation_policy="Foreground",
            )
        stage(4, "Removing retained volumes and image-clone access")
        verify_storage(
            life, provider, args.cluster, record["storage_bindings"], detached=True
        )
        uids = {
            n: {"pv": b["pvUID"], "longhorn": b["longhornUID"]}
            for n, b in record["storage_bindings"].items()
        }
        failures = life.cleanup_retained_volumes(
            provider, record["persistent_volumes"], storage_uids=uids
        )
        if failures:
            fail("same-plane storage cleanup incomplete: " + "; ".join(failures))
        life.cleanup_authorization(
            args,
            config=config,
            data_volume_uids=set(record["data_volume_uids"]),
            golden_before=record["golden_before"],
            kubeconfig=provider,
        )
        stage(5, "Verifying absence independently")
        deadline = time.monotonic() + min(
            getattr(args, "backend_timeout_seconds", 600), 600
        )
        while True:
            guard()
            try:
                absence(life, provider, args.cluster, record["storage_bindings"])
                break
            except life.TalosLifecycleError as error:
                if "target backend remains" not in str(error):
                    raise
                if time.monotonic() >= deadline:
                    fail("same-plane backend absence timeout: " + str(error))
                time.sleep(min(2, max(0, deadline - time.monotonic())))
        # Independently repeat absence reads rather than trusting DELETE responses.
        guard()
        absence(life, provider, args.cluster, record["storage_bindings"])
        record = {**record, "complete": True}
        life.persist_teardown_record(path, args.cluster, record, cm)
    finally:
        life.MUTATION_GUARD.reset(token)
    print(
        "Same-plane teardown independently observed complete; original evidence preserved"
        f" (ledger {life.TEARDOWN_LEDGER_NAMESPACE}/{life.TEARDOWN_LEDGER_PREFIX}{args.cluster},"
        f" {life.cluster_directory(args)})"
    )
    return 0
