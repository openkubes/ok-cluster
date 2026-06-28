#!/usr/bin/env python3
"""
render.py — OpenKubes Cluster Manifest Renderer
Reads cluster-config.yaml, resolves auto IP/CIDR, renders templates to manifests.
"""
import argparse
import ipaddress
import os
import re
import sys
import yaml
from pathlib import Path
from string import Template

SCRIPT_DIR = Path(__file__).parent
CLUSTERS_DIR = SCRIPT_DIR
TEMPLATES_DIR = SCRIPT_DIR / "templates"

METALLB_POOL_START = ipaddress.IPv4Address("192.168.100.200")
METALLB_POOL_END   = ipaddress.IPv4Address("192.168.100.254")

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

def next_free_ip(used):
    ip = METALLB_POOL_START
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
    if net.get("endpoint", "auto") == "auto":
        net["endpoint"] = next_free_ip(allocated_ips(others))
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
        "TALOS_VERSION":      ver.get("talos", "v1.13.4"),
        "UPGRADE_STRATEGY":   upg.get("strategy", "blue-green"),
        "NODE_SELECTOR":      cfg.get("nodeSelector", ""),
        "TALOS_SCHEMATIC_ID": os.environ.get(
            "TALOS_SCHEMATIC_ID",
            "ce4c980550dd2ab1b17bbf2b08801c7eb59418eafe8f279833297925d67c7515"
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
    tpl_dir = TEMPLATES_DIR / cluster_type
    out_dir = output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    resolved_cfg_path = out_dir / "cluster-config.yaml"
    with open(resolved_cfg_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    print(f"  ✔ {resolved_cfg_path.relative_to(SCRIPT_DIR)}")

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
    print(next_free_ip(allocated_ips(others)))

def main():
    p = argparse.ArgumentParser(description="OpenKubes cluster manifest renderer")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render"); r.add_argument("--cluster", required=True); r.set_defaults(func=cmd_render)
    l = sub.add_parser("list"); l.set_defaults(func=cmd_list)
    ip = sub.add_parser("next-ip"); ip.add_argument("--cluster", default="__new__"); ip.set_defaults(func=cmd_show_ip)
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
