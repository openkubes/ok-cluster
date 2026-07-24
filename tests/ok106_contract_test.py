#!/usr/bin/env python3
"""
OK-106 structural contract test (ADR-Platform-023, merge gates 3 + 4).

Renders a native Talos workload cluster for each CAPI infrastructure profile
(kubevirt, openstack) and asserts:

  Gate 3 — the provider-neutral lifecycle objects (Cluster, TalosControlPlane,
  TalosConfigTemplate, MachineDeployment) are field-equivalent across profiles,
  differing ONLY at an explicit allowlist of provider seams. Any other divergence
  is treated as contract drift and fails the test. (Cheapest static form of the
  OK-78 "Contract Verified" phase.)

  Gate 4 — the openkubes.io/provider label is present on both Cluster objects,
  is consistently derivable from spec.infrastructureRef.kind, and is never used
  as an independent control source in the renderer or scripts.

Static only. No provisioning. Exit non-zero on any failure.
"""
import copy, os, shutil, subprocess, sys, pathlib, yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
PROVIDER_LABEL = "openkubes.io/provider"

SHARED_KINDS = {"Cluster", "TalosControlPlane", "TalosConfigTemplate", "MachineDeployment"}

# Explicit allowlist of permitted provider seams inside the shared objects.
# (kind, dotted-path). Everything else in the shared objects must be equivalent.
# Seam paths are explicit key LISTS (not dot-strings) because the provider label
# key itself contains dots ("openkubes.io/provider").
ALLOWED_SEAMS = [
    ("Cluster", ["spec", "infrastructureRef"]),
    ("Cluster", ["metadata", "labels", PROVIDER_LABEL]),
    ("TalosControlPlane", ["spec", "infrastructureTemplate"]),
    ("MachineDeployment", ["spec", "template", "spec", "infrastructureRef"]),
]

# infrastructureRef.kind -> canonical clusterctl provider name (Gate 4 derivation)
KIND_TO_PROVIDER = {"KubevirtCluster": "kubevirt", "OpenStackCluster": "openstack"}

FIXTURES = {
    "ct-kubevirt": {"name": "ct", "type": "talos", "provider": "kubevirt",
                    "controlPlane": {"replicas": 1}, "workers": {"replicas": 2},
                    "network": {"endpoint": "192.168.100.250", "podCIDR": "10.32.0.0/16", "serviceCIDR": "10.96.0.0/20"}, "nodeSelector": "ok-infra"},
    "ct-openstack": {"name": "ct", "type": "talos", "provider": "openstack",
                     "controlPlane": {"replicas": 1}, "workers": {"replicas": 2},
                     "network": {"endpoint": "192.168.100.251", "podCIDR": "10.32.0.0/16", "serviceCIDR": "10.96.0.0/20"},
                     "openstack": {"cloud": "openstack", "externalNetwork": "public",
                                   "image": "talos-openstack-amd64", "controlPlaneFlavor": "m1.large",
                                   "nodeFlavor": "m1.large", "sshKeyName": "ok-cluster"}},
}

def render(name, cfg):
    d = REPO / name; d.mkdir(exist_ok=True)
    (d / "cluster-config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
    env = dict(os.environ, OKB_KUBECONFIG="/nonexistent")
    subprocess.run([sys.executable, "render.py", "render", "--cluster", name],
                   cwd=REPO, env=env, check=True, capture_output=True)
    docs = []
    for f in sorted(d.glob("*")):
        if f.name == "cluster-config.yaml" or f.suffix in (".sh",): continue
        if f.suffix in ("", ".yaml"):
            try: docs += [x for x in yaml.safe_load_all(f.read_text()) if x]
            except Exception: pass
    return docs

def by_key(docs):
    return {(d.get("kind"), d.get("metadata", {}).get("name")): d
            for d in docs if d.get("kind") in SHARED_KINDS}

def redact(obj, kind):
    o = copy.deepcopy(obj)
    for k, parts in ALLOWED_SEAMS:
        if k != kind: continue
        cur = o
        for p in parts[:-1]:
            cur = cur.get(p, {}) if isinstance(cur, dict) else {}
        if isinstance(cur, dict): cur.pop(parts[-1], None)
    return o

def main():
    fails = []
    kv = render("ct-kubevirt", FIXTURES["ct-kubevirt"])
    os_ = render("ct-openstack", FIXTURES["ct-openstack"])
    try:
        kkv, kos = by_key(kv), by_key(os_)

        # ---- Gate 3 ----
        if set(kkv) != set(kos):
            fails.append(f"Gate3: shared object set differs: {set(kkv) ^ set(kos)}")
        for key in set(kkv) & set(kos):
            kind = key[0]
            if redact(kkv[key], kind) != redact(kos[key], kind):
                fails.append(f"Gate3: contract drift in {key} outside allowed seams")
            else:
                print(f"PASS Gate3: {kind}/{key[1]} equivalent (only allowed seams differ)")

        # ---- Gate 4 ----
        for label_name, docs in (("kubevirt", kv), ("openstack", os_)):
            cl = next(d for d in docs if d.get("kind") == "Cluster")
            lbl = cl.get("metadata", {}).get("labels", {}).get(PROVIDER_LABEL)
            ref_kind = cl.get("spec", {}).get("infrastructureRef", {}).get("kind")
            derived = KIND_TO_PROVIDER.get(ref_kind)
            if lbl is None:
                fails.append(f"Gate4: {label_name} Cluster missing {PROVIDER_LABEL}")
            elif lbl != derived:
                fails.append(f"Gate4: {label_name} label '{lbl}' != derived '{derived}' from {ref_kind}")
            else:
                print(f"PASS Gate4: {label_name} Cluster label '{lbl}' == derived from {ref_kind}")

        # label must not be an independent control source (renderer / scripts)
        offenders = []
        for f in list((REPO).glob("*.py")) + list((REPO).glob("*.sh")) + list((REPO / "templates").rglob("*.sh.tpl")):
            if PROVIDER_LABEL in f.read_text():
                offenders.append(str(f.relative_to(REPO)))
        if offenders:
            fails.append(f"Gate4: {PROVIDER_LABEL} referenced as logic in: {offenders} (must be metadata only)")
        else:
            print(f"PASS Gate4: {PROVIDER_LABEL} not used as a control source (metadata only)")
    finally:
        shutil.rmtree(REPO / "ct-kubevirt", ignore_errors=True)
        shutil.rmtree(REPO / "ct-openstack", ignore_errors=True)

    print()
    if fails:
        print("CONTRACT TEST FAILED:")
        for x in fails: print("  FAIL:", x)
        sys.exit(1)
    print("CONTRACT TEST PASSED — provider-neutral lifecycle objects equivalent; provider label symmetric & inert.")

if __name__ == "__main__":
    main()
