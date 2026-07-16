#!/usr/bin/env python3
"""
render.py — OpenKubes Cluster Manifest Renderer
Reads cluster-config.yaml, resolves auto IP/CIDR, renders templates to manifests.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import yaml
from pathlib import Path
from string import Template

SCRIPT_DIR = Path(__file__).parent
CLUSTERS_DIR = SCRIPT_DIR
TEMPLATES_DIR = SCRIPT_DIR / "templates"

METALLB_POOL_START = ipaddress.IPv4Address("192.168.100.200")
METALLB_POOL_END   = ipaddress.IPv4Address("192.168.100.254")

# Management cluster kubeconfig — source of truth for live MetalLB allocations (OK-83)
OKB_KUBECONFIG = os.environ.get(
    "OKB_KUBECONFIG", os.path.expanduser("~/.kube/ok-infra.yaml")
)

# ok-linux is the source of truth for this default.
# See: https://github.com/openkubes/ok-linux/blob/main/profiles/kubevirt/profile.yaml
# Verified against the running ok1-talos cluster (ok-linux v0.1.0).
OK_LINUX_DEFAULT_PROFILE = "kubevirt"
OK_LINUX_DEFAULT_SCHEMATIC_ID = "ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515"
OK_LINUX_DEFAULT_TALOS_VERSION = "v1.9.5"

def load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)

def discover_clusters() -> list[dict]:
    clusters = []
    for d in sorted(CLUSTERS_DIR.iterdir()):
        cfg_path = d / "cluster-config.yaml"
        if cfg_path.exists():
            clusters.append({"name": d.name, "config": load_yaml(cfg_path)})
    return clusters

def allocated_ips(clusters):
    return {c["config"]["network"]["endpoint"] for c in clusters
            if c["config"].get("network", {}).get("endpoint", "auto") != "auto"}

def allocated_pod_cidrs(clusters):
    return {c["config"]["network"]["podCIDR"] for c in clusters
            if c["config"].get("network", {}).get("podCIDR", "auto") != "auto"}

def allocated_svc_cidrs(clusters):
    return {c["config"]["network"]["serviceCIDR"] for c in clusters
            if c["config"].get("network", {}).get("serviceCIDR", "auto") != "auto"}

def live_metallb_allocations(exclude_cluster=None):
    """Query LoadBalancer IPs actually allocated by MetalLB on the management
    cluster (OK-83). Returns {ip: "namespace/service"} or None if the cluster
    is unreachable (caller falls back to local state with a warning).

    Services in the namespace of `exclude_cluster` are skipped so that
    re-rendering an existing cluster does not collide with its own IPs.
    """
    try:
        out = subprocess.run(
            ["kubectl", "--kubeconfig", OKB_KUBECONFIG,
             "get", "svc", "-A", "-o", "json", "--request-timeout=10s"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
        items = json.loads(out).get("items", [])
    except (subprocess.SubprocessError, FileNotFoundError, OSError, ValueError):
        return None
    allocations = {}
    for svc in items:
        if svc.get("spec", {}).get("type") != "LoadBalancer":
            continue
        ns = svc["metadata"]["namespace"]
        if exclude_cluster and ns == exclude_cluster:
            continue
        name = f'{ns}/{svc["metadata"]["name"]}'
        for ing in (svc.get("status", {}).get("loadBalancer", {}) or {}).get("ingress", []) or []:
            if ing.get("ip"):
                allocations[ing["ip"]] = name
        lb_ip = svc.get("spec", {}).get("loadBalancerIP")
        if lb_ip:
            allocations[lb_ip] = name
    return allocations

def effective_used_ips(others, exclude_cluster=None):
    """Union of locally declared endpoints and live MetalLB allocations (OK-83)."""
    used = dict.fromkeys(allocated_ips(others), "local cluster-config.yaml")
    live = live_metallb_allocations(exclude_cluster=exclude_cluster)
    if live is None:
        print(
            f"WARNING: management cluster unreachable via {OKB_KUBECONFIG} — "
            "IP allocation based on local cluster-config state only. "
            "Verify with: kubectl --kubeconfig ~/.kube/ok-infra.yaml get svc -A | grep LoadBalancer",
            file=sys.stderr,
        )
    else:
        used.update(live)
    return used

def next_free_ip(used, start_ip=None):
    ip = METALLB_POOL_START
    if start_ip:
        ip = ipaddress.IPv4Address(start_ip)
        if not (METALLB_POOL_START <= ip <= METALLB_POOL_END):
            raise SystemExit(
                f"ERROR: START_IP {start_ip} outside MetalLB pool "
                f"{METALLB_POOL_START}-{METALLB_POOL_END}"
            )
    while ip <= METALLB_POOL_END:
        if str(ip) not in used:
            return str(ip)
        ip += 1
    raise RuntimeError("MetalLB pool exhausted")

def next_free_pod_cidr(used):
    for net in ipaddress.IPv4Network("10.32.0.0/11").subnets(new_prefix=16):
        if str(net) not in used:
            return str(net)
    raise RuntimeError("Pod CIDR space exhausted")

def next_free_svc_cidr(used):
    for net in ipaddress.IPv4Network("10.96.0.0/12").subnets(new_prefix=20):
        if str(net) not in used:
            return str(net)
    raise RuntimeError("Service CIDR space exhausted")

def resolve_config(cfg: dict, cluster_name: str) -> dict:
    cfg = yaml.safe_load(yaml.dump(cfg))
    clusters = discover_clusters()
    others = [c for c in clusters if c["name"] != cluster_name]
    net = cfg.setdefault("network", {})
    used = effective_used_ips(others, exclude_cluster=cluster_name)
    if net.get("endpoint", "auto") == "auto":
        net["endpoint"] = next_free_ip(used, start_ip=os.environ.get("START_IP"))
    elif net["endpoint"] in used:
        # OK-83: collision must be an error, never a silent wrong assignment
        raise SystemExit(
            f"ERROR: endpoint {net['endpoint']} is already allocated "
            f"({used[net['endpoint']]}). Next free IP: {next_free_ip(used)}"
        )
    if net.get("podCIDR", "auto") == "auto":
        net["podCIDR"] = next_free_pod_cidr(allocated_pod_cidrs(others))
    if net.get("serviceCIDR", "auto") == "auto":
        net["serviceCIDR"] = next_free_svc_cidr(allocated_svc_cidrs(others))
    cfg.setdefault("controlPlane", {}).setdefault("replicas", 1)
    cfg.setdefault("workers", {}).setdefault("replicas", 1)
    cfg.setdefault("upgrade", {}).setdefault("strategy", "blue-green")
    # nodeSelector defaults to empty string (= no pinning)
    if "nodeSelector" not in cfg:
        cfg["nodeSelector"] = ""

    # versions.talos defaults to the ok-linux verified version, not an
    # arbitrary hardcoded one. Only applies if the cluster type is talos —
    # ubuntu clusters don't carry a talos version at all.
    if cfg.get("type") == "talos":
        ver = cfg.setdefault("versions", {})
        ver.setdefault("talos", OK_LINUX_DEFAULT_TALOS_VERSION)

    # os: section — explicit, written back to cluster-config.yaml.
    # This is the seam described in ok-linux ADR-004: today these defaults
    # are hardcoded here, in the future they will be resolved dynamically
    # from the ok-linux repository. The field names and structure stay
    # the same either way.
    if cfg.get("type") == "talos":
        os_cfg = cfg.setdefault("os", {})
        os_cfg.setdefault("distribution", "ok-linux")
        os_cfg.setdefault("profile", OK_LINUX_DEFAULT_PROFILE)
        os_cfg.setdefault("schematic_id", OK_LINUX_DEFAULT_SCHEMATIC_ID)

    return cfg

def build_context(cfg: dict) -> dict:
    cp = cfg.get("controlPlane", {})
    wk = cfg.get("workers", {})
    net = cfg.get("network", {})
    ver = cfg.get("versions", {})
    upg = cfg.get("upgrade", {})
    return {
        "CLUSTER_NAME":       cfg["name"],
        "CLUSTER_TYPE":       cfg.get("type", "ubuntu"),
        "CP_REPLICAS":        cp.get("replicas", 1),
        "CP_CORES":           cp.get("cores", 2),
        "CP_MEMORY":          cp.get("memory", "4Gi"),
        "CP_DISK":            cp.get("disk", "20Gi"),
        "WORKER_REPLICAS":    wk.get("replicas", 1),
        "WORKER_CORES":       wk.get("cores", 2),
        "WORKER_MEMORY":      wk.get("memory", "4Gi"),
        "WORKER_DISK":        wk.get("disk", "15Gi"),
        "ENDPOINT_IP":        net.get("endpoint"),
        "POD_CIDR":           net.get("podCIDR"),
        "SERVICE_CIDR":       net.get("serviceCIDR"),
        "K8S_VERSION":        ver.get("kubernetes", "v1.34.1"),
        "TALOS_VERSION":      ver.get("talos", OK_LINUX_DEFAULT_TALOS_VERSION),
        "UPGRADE_STRATEGY":   upg.get("strategy", "blue-green"),
        "NODE_SELECTOR":      cfg.get("nodeSelector", ""),
        "TALOS_SCHEMATIC_ID": (
            cfg.get("os", {}).get("schematic_id") or
            os.environ.get("TALOS_SCHEMATIC_ID") or
            OK_LINUX_DEFAULT_SCHEMATIC_ID
        ),
    }

def apply_node_selector(rendered: str, node_selector: str) -> str:
    """Remove nodeSelector block if NODE_SELECTOR is empty."""
    if not node_selector:
        rendered = re.sub(
            r'\s+nodeSelector:\n\s+kubernetes\.io/hostname:.*\n',
            '\n',
            rendered
        )
    return rendered

def render_cluster(cluster_name: str, output_dir: Path, cfg: dict) -> None:
    cluster_type = cfg.get("type", "ubuntu")
    ctx = build_context(cfg)
    tpl_dirs = [TEMPLATES_DIR / cluster_type]
    if cluster_type == "talos-mgmt":
        tpl_dirs = [TEMPLATES_DIR / "talos", TEMPLATES_DIR / "talos-mgmt"]
    out_dir = output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    resolved_cfg_path = out_dir / "cluster-config.yaml"
    with open(resolved_cfg_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    print(f"  ✔ {resolved_cfg_path.relative_to(SCRIPT_DIR)}")

    for tpl_dir in tpl_dirs:
        for tpl in sorted(tpl_dir.glob("*.tpl")):
            rendered = Template(tpl.read_text()).safe_substitute(ctx)
            rendered = apply_node_selector(rendered, ctx["NODE_SELECTOR"])
            out_name = tpl.stem
            out_path = out_dir / out_name
            out_path.write_text(rendered)
            if out_path.suffix == ".sh":
                out_path.chmod(0o755)
            print(f"  ✔ {out_path.relative_to(SCRIPT_DIR)}")

def cmd_render(args):
    cluster_name = args.cluster
    cluster_dir  = CLUSTERS_DIR / cluster_name
    cfg_path     = cluster_dir / "cluster-config.yaml"
    if not cfg_path.exists():
        print(f"ERROR: {cfg_path} not found.", file=sys.stderr)
        sys.exit(1)
    raw = load_yaml(cfg_path)
    cfg = resolve_config(raw, cluster_name)
    render_cluster(cluster_name, cluster_dir, cfg)
    print(f"\nCluster '{cluster_name}' rendered → {cluster_dir.relative_to(SCRIPT_DIR)}/")

def cmd_list(args):
    clusters = discover_clusters()
    if not clusters:
        print("No clusters defined yet.")
        return
    print(f"{'NAME':<20} {'TYPE':<8} {'CP':<4} {'W':<4} {'ENDPOINT':<18} {'K8S':<12} {'NODE'}")
    print("-" * 78)
    for c in clusters:
        cfg = c["config"]
        node = cfg.get("nodeSelector", "") or "(any)"
        print(
            f"{c['name']:<20} "
            f"{cfg.get('type','ubuntu'):<8} "
            f"{cfg.get('controlPlane',{}).get('replicas',1):<4} "
            f"{cfg.get('workers',{}).get('replicas',1):<4} "
            f"{cfg.get('network',{}).get('endpoint','auto'):<18} "
            f"{cfg.get('versions',{}).get('kubernetes','?'):<12} "
            f"{node}"
        )

def cmd_show_ip(args):
    clusters = discover_clusters()
    others = [c for c in clusters if c["name"] != args.cluster]
    used = effective_used_ips(others, exclude_cluster=args.cluster)
    start_ip = args.start_ip or os.environ.get("START_IP")
    print(next_free_ip(used, start_ip=start_ip))

def main():
    p = argparse.ArgumentParser(description="OpenKubes cluster manifest renderer")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render"); r.add_argument("--cluster", required=True); r.set_defaults(func=cmd_render)
    l = sub.add_parser("list"); l.set_defaults(func=cmd_list)
    ip = sub.add_parser("next-ip"); ip.add_argument("--cluster", default="__new__"); ip.add_argument("--start-ip", default=None); ip.set_defaults(func=cmd_show_ip)
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
