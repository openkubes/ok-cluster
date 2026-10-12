#!/usr/bin/env python3
"""
render.py — OpenKubes Cluster Manifest Renderer
Reads cluster-config.yaml, resolves auto IP/CIDR, renders templates to manifests.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import posixpath
import re
import subprocess
import sys
import yaml
from pathlib import Path
from string import Template

from profile_resolvers.flatcar import resolve_flatcar_config
from profile_resolvers.talos import resolve_talos_config

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
OK_LINUX_DEFAULT_TALOS_VERSION = "v1.9.6"
OK_LINUX_PATH = Path(
    os.environ.get("OK_LINUX_PATH", SCRIPT_DIR.parent / "ok-linux")
).resolve()

WORKLOAD_USER_NAMESPACES_DEFAULT_MAX = 11255
WORKLOAD_USER_NAMESPACES_KEYS = {
    "enabled",
    "maxUserNamespaces",
    "provisionerBasePath",
}

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


def validate_registry_trust(cfg: dict) -> None:
    """Validate the opt-in shape without resolving runtime CA/address values."""
    if "registryTrust" not in cfg:
        return
    trust = cfg["registryTrust"]
    if not isinstance(trust, dict) or trust.get("enabled") is not True:
        raise SystemExit(
            "ERROR: registryTrust must be absent or set enabled: true explicitly"
        )
    if cfg.get("type") != "talos":
        raise SystemExit("ERROR: registryTrust is supported only for type: talos")
    required = {
        "host": trust.get("host"),
        "caSecret.namespace": (trust.get("caSecret") or {}).get("namespace"),
        "caSecret.name": (trust.get("caSecret") or {}).get("name"),
        "caSecret.key": (trust.get("caSecret") or {}).get("key"),
        "address.serviceNamespace": (trust.get("address") or {}).get(
            "serviceNamespace"
        ),
        "address.serviceName": (trust.get("address") or {}).get("serviceName"),
        "talosconfigSecret.namespace": (trust.get("talosconfigSecret") or {}).get(
            "namespace"
        ),
        "talosconfigSecret.name": (trust.get("talosconfigSecret") or {}).get("name"),
        "talosconfigSecret.key": (trust.get("talosconfigSecret") or {}).get("key"),
    }
    missing = [key for key, value in required.items() if not isinstance(value, str) or not value]
    if missing:
        raise SystemExit(
            "ERROR: registryTrust is incomplete: " + ", ".join(missing)
        )
    if trust["host"] != "registry.ok-shared.internal":
        raise SystemExit(
            "ERROR: registryTrust.host must be registry.ok-shared.internal"
        )


def render_infra_cluster_secret_ref(cfg: dict) -> str:
    """Render an explicit CAPK external-infrastructure credential reference.

    The reference is optional because CAPK can legitimately manage KubeVirt in
    the management cluster itself.  When an external provider cluster is
    intended, callers must opt in explicitly; silently inventing this reference
    would blur the lifecycle authority boundary.
    """
    reference = cfg.get("infraClusterSecretRef")
    if reference is None:
        return ""
    if cfg.get("type") != "talos" or cfg.get("provider", "kubevirt") != "kubevirt":
        raise SystemExit(
            "ERROR: infraClusterSecretRef is supported only for Talos on KubeVirt"
        )
    if not isinstance(reference, dict) or set(reference) != {"name", "namespace"}:
        raise SystemExit(
            "ERROR: infraClusterSecretRef requires exactly name and namespace"
        )
    name = reference["name"]
    namespace = reference["namespace"]
    dns_subdomain = re.compile(
        r"^(?=.{1,253}$)[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$"
    )
    dns_label = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
    if not isinstance(name, str) or not dns_subdomain.fullmatch(name):
        raise SystemExit("ERROR: infraClusterSecretRef.name is not a DNS subdomain")
    if not isinstance(namespace, str) or not dns_label.fullmatch(namespace):
        raise SystemExit("ERROR: infraClusterSecretRef.namespace is not a DNS label")
    return (
        "  infraClusterSecretRef:\n"
        "    apiVersion: v1\n"
        "    kind: Secret\n"
        f"    name: {name}\n"
        f"    namespace: {namespace}\n"
    )


def validate_workload_user_namespaces(cfg: dict) -> dict | None:
    """Validate and normalize the Talos/KubeVirt user-namespace opt-in."""
    if "workloadUserNamespaces" not in cfg:
        return None
    capability = cfg["workloadUserNamespaces"]
    if not isinstance(capability, dict):
        raise SystemExit("ERROR: workloadUserNamespaces must be a mapping")
    invalid_keys = [key for key in capability if not isinstance(key, str)]
    if invalid_keys:
        raise SystemExit(
            "ERROR: workloadUserNamespaces keys must be strings; invalid: "
            + ", ".join(sorted(repr(key) for key in invalid_keys))
        )
    unknown = set(capability) - WORKLOAD_USER_NAMESPACES_KEYS
    if unknown:
        raise SystemExit(
            "ERROR: workloadUserNamespaces allows only enabled, "
            "maxUserNamespaces, and provisionerBasePath; unknown: "
            + ", ".join(sorted(unknown))
        )
    if "enabled" not in capability or not isinstance(capability["enabled"], bool):
        raise SystemExit("ERROR: workloadUserNamespaces.enabled must be a boolean")
    if capability["enabled"] and (
        cfg.get("type") != "talos" or cfg.get("provider", "kubevirt") != "kubevirt"
    ):
        raise SystemExit(
            "ERROR: workloadUserNamespaces is supported only for Talos on KubeVirt"
        )

    maximum = capability.get(
        "maxUserNamespaces", WORKLOAD_USER_NAMESPACES_DEFAULT_MAX
    )
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise SystemExit(
            "ERROR: workloadUserNamespaces.maxUserNamespaces must be a positive integer"
        )

    has_base_path = "provisionerBasePath" in capability
    base_path = capability.get("provisionerBasePath")
    if capability["enabled"] and not has_base_path:
        raise SystemExit(
            "ERROR: workloadUserNamespaces.provisionerBasePath is required when enabled"
        )
    if has_base_path:
        if not isinstance(base_path, str) or not base_path:
            raise SystemExit(
                "ERROR: workloadUserNamespaces.provisionerBasePath must be a path"
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in base_path):
            raise SystemExit(
                "ERROR: workloadUserNamespaces.provisionerBasePath must not contain "
                "control characters"
            )
        normalized = posixpath.normpath(base_path)
        if (
            not base_path.startswith("/")
            or normalized != base_path
            or normalized == "/var"
            or not normalized.startswith("/var/")
        ):
            raise SystemExit(
                "ERROR: workloadUserNamespaces.provisionerBasePath must be a "
                "normalized absolute child of /var"
            )

    normalized_capability = dict(capability)
    normalized_capability["maxUserNamespaces"] = maximum
    return normalized_capability


def render_workload_user_namespace_patches(cfg: dict) -> str:
    """Render worker-only Talos patches; disabled/absent is byte-empty."""
    capability = validate_workload_user_namespaces(cfg)
    if capability is None or not capability["enabled"]:
        return ""
    maximum = capability["maxUserNamespaces"]
    base_path = capability["provisionerBasePath"]
    return (
        "\n      - op: add\n"
        "        path: /machine/sysctls\n"
        "        value:\n"
        f'          user.max_user_namespaces: "{maximum}"\n'
        "      - op: add\n"
        "        path: /machine/kubelet/extraMounts\n"
        "        value:\n"
        f"        - destination: {json.dumps(base_path)}\n"
        "          type: bind\n"
        f"          source: {json.dumps(base_path)}\n"
        "          options:\n"
        "          - bind\n"
        "          - rshared\n"
        "          - rw"
    )


WORKLOAD_USER_NAMESPACE_PATCH_PATHS = (
    "/machine/sysctls",
    "/machine/kubelet/extraMounts",
)


def _json_pointer_segments(pointer: str) -> tuple[str, ...] | None:
    if not isinstance(pointer, str):
        return None
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise SystemExit(
            f"ERROR: rendered worker configPatches contains invalid JSON pointer {pointer!r}"
        )
    return tuple(
        segment.replace("~1", "/").replace("~0", "~")
        for segment in pointer[1:].split("/")
    )


def _paths_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    common = min(len(left), len(right))
    return left[:common] == right[:common]


def _strategic_patch_paths(value, prefix: tuple[str, ...] = ()):
    """Yield leaf config paths represented by Talos strategic patch mappings."""
    if isinstance(value, dict):
        if not value:
            yield prefix
            return
        for key, child in value.items():
            if isinstance(key, str):
                path = prefix + (key,)
                if isinstance(child, (dict, list)):
                    yield from _strategic_patch_paths(child, path)
                else:
                    yield path
    elif isinstance(value, list):
        if not value:
            yield prefix
            return
        # A strategic patch replaces/merges the entire list field.
        yield prefix


def validate_workload_user_namespace_template(rendered: str, cfg: dict) -> None:
    """Reject worker defaults that overlap fields owned by this opt-in."""
    resources = [item for item in yaml.safe_load_all(rendered) if item]
    worker_templates = [
        item
        for item in resources
        if item.get("kind") == "TalosConfigTemplate"
        and item.get("spec", {}).get("template", {}).get("spec", {}).get("generateType")
        == "worker"
    ]
    if not worker_templates:
        raise SystemExit(
            "ERROR: enabled workloadUserNamespaces requires a rendered worker TalosConfigTemplate"
        )

    targets = tuple(_json_pointer_segments(path) for path in WORKLOAD_USER_NAMESPACE_PATCH_PATHS)
    capability = validate_workload_user_namespaces(cfg)
    if capability is None or not capability["enabled"]:
        return
    maximum = str(capability["maxUserNamespaces"])
    base_path = capability["provisionerBasePath"]
    expected_patches = [
        {"op": "add", "path": "/machine/sysctls", "value": {"user.max_user_namespaces": maximum}},
        {
            "op": "add",
            "path": "/machine/kubelet/extraMounts",
            "value": [
                {
                    "destination": base_path,
                    "type": "bind",
                    "source": base_path,
                    "options": ["bind", "rshared", "rw"],
                }
            ],
        },
    ]
    for resource in worker_templates:
        spec = resource["spec"]["template"]["spec"]
        patches = spec.get("configPatches", [])
        if not isinstance(patches, list):
            raise SystemExit("ERROR: worker TalosConfigTemplate configPatches must be a list")
        if patches[-len(expected_patches):] != expected_patches:
            raise SystemExit(
                "ERROR: enabled workloadUserNamespaces worker configPatches are missing "
                "or do not match the expected sysctl and extraMounts patches"
            )
        for patch in patches[:-len(expected_patches)]:
            if not isinstance(patch, dict):
                continue
            for pointer_name in ("path", "from"):
                pointer = patch.get(pointer_name)
                path = _json_pointer_segments(pointer)
                if path is None:
                    continue
                for target_text, target in zip(WORKLOAD_USER_NAMESPACE_PATCH_PATHS, targets):
                    if _paths_overlap(path, target):
                        raise SystemExit(
                            "ERROR: enabled workloadUserNamespaces conflicts with existing "
                            f"worker configPatches {pointer_name} {pointer!r} "
                            f"(overlaps {target_text})"
                        )

        strategic_patches = spec.get("strategicPatches", [])
        if not isinstance(strategic_patches, list):
            strategic_patches = [strategic_patches]
        for strategic_patch in strategic_patches:
            parsed_patch = strategic_patch
            if isinstance(strategic_patch, str):
                try:
                    parsed_patch = yaml.safe_load(strategic_patch)
                except yaml.YAMLError as exc:
                    raise SystemExit(
                        "ERROR: enabled workloadUserNamespaces cannot inspect malformed "
                        f"worker strategicPatches: {exc}"
                    ) from exc
            if not isinstance(parsed_patch, dict):
                raise SystemExit(
                    "ERROR: enabled workloadUserNamespaces cannot inspect a non-mapping "
                    "worker strategicPatches entry"
                )
            for path in _strategic_patch_paths(parsed_patch):
                for target_text, target in zip(WORKLOAD_USER_NAMESPACE_PATCH_PATHS, targets):
                    if _paths_overlap(path, target):
                        raise SystemExit(
                            "ERROR: enabled workloadUserNamespaces conflicts with existing "
                            f"worker strategicPatches path {'/'.join(path)!r} "
                            f"(overlaps {target_text})"
                        )


def workload_user_namespaces_from_env(cluster_type: str, provider: str) -> dict | None:
    """Validate Make scaffold inputs and return the block to persist when enabled."""
    enabled_text = os.environ.get("WORKLOAD_USER_NAMESPACES", "false")
    if enabled_text not in {"true", "false"}:
        raise SystemExit("ERROR: WORKLOAD_USER_NAMESPACES must be exactly true or false")
    maximum_text = os.environ.get(
        "MAX_USER_NAMESPACES", str(WORKLOAD_USER_NAMESPACES_DEFAULT_MAX)
    )
    if not maximum_text.isdecimal():
        raise SystemExit("ERROR: MAX_USER_NAMESPACES must be a positive integer")
    capability = {
        "enabled": enabled_text == "true",
        "maxUserNamespaces": int(maximum_text),
    }
    base_path = os.environ.get("PROVISIONER_BASE_PATH", "")
    if base_path:
        capability["provisionerBasePath"] = base_path
    validation_type = cluster_type if capability["enabled"] else "talos"
    validation_provider = provider if capability["enabled"] else "kubevirt"
    validated = validate_workload_user_namespaces(
        {
            "type": validation_type,
            "provider": validation_provider,
            "workloadUserNamespaces": capability,
        }
    )
    return validated if validated["enabled"] else None

def resolve_config(cfg: dict, cluster_name: str) -> dict:
    cfg = yaml.safe_load(yaml.dump(cfg))
    validate_registry_trust(cfg)
    workload_user_namespaces = validate_workload_user_namespaces(cfg)
    if workload_user_namespaces is not None:
        cfg["workloadUserNamespaces"] = workload_user_namespaces
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
        if cfg.get("provider", "kubevirt") == "kubevirt":
            cfg = resolve_talos_config(cfg, OK_LINUX_PATH)
    elif cfg.get("type") == "flatcar":
        # Flatcar defaults and support constraints are owned by the selected
        # ok-linux implementation profile. The shared renderer only dispatches
        # to its isolated resolver.
        cfg = resolve_flatcar_config(cfg, OK_LINUX_PATH)

    return cfg

def build_context(cfg: dict) -> dict:
    cp = cfg.get("controlPlane", {})
    wk = cfg.get("workers", {})
    net = cfg.get("network", {})
    ver = cfg.get("versions", {})
    upg = cfg.get("upgrade", {})
    _osp = cfg.get("openstack", {})
    os_cfg = cfg.get("os", {})
    golden_image = os_cfg.get("goldenImage", {})
    provider_profile = cfg.get("providerProfile", {})
    bootstrap = cfg.get("bootstrap", {})
    identity = str(os_cfg.get("identity", ""))
    identity_hex = identity.removeprefix("sha256:")
    provider_identity = str(provider_profile.get("identity", ""))
    provider_identity_hex = provider_identity.removeprefix("sha256:")
    provider_name = str(provider_profile.get("name", ""))
    machine_template_id = identity_hex[:12]
    if provider_name and provider_name != "ok-infra":
        machine_template_id = (
            f"{machine_template_id}-{provider_identity_hex[:8]}"
        )
    talos_version = str(
        ver.get("talos", OK_LINUX_DEFAULT_TALOS_VERSION)
    )
    talos_version_name = re.sub(
        r"[^a-z0-9]+", "-", talos_version.lower()
    ).strip("-")
    return {
        "CLUSTER_NAME":       cfg["name"],
        "CLUSTER_TYPE":       cfg.get("type", "ubuntu"),
        "INFRA_PROVIDER":     cfg.get("provider", "kubevirt"),
        "INFRA_CLUSTER_SECRET_REF": render_infra_cluster_secret_ref(cfg),
        "WORKLOAD_USER_NAMESPACE_PATCHES": (
            render_workload_user_namespace_patches(cfg)
        ),
        "OS_IMAGE_NAME":      _osp.get("image", "talos-openstack-amd64"),
        "OS_CP_FLAVOR":       _osp.get("controlPlaneFlavor", "m1.large"),
        "OS_NODE_FLAVOR":     _osp.get("nodeFlavor", "m1.large"),
        "OS_EXTERNAL_NETWORK": _osp.get("externalNetwork", "public"),
        "OS_CLOUD_NAME":      _osp.get("cloud", "openstack"),
        "OS_SSH_KEY":         _osp.get("sshKeyName", "ok-cluster"),
        "OS_DNS":             _osp.get("dnsNameserver", "8.8.8.8"),
        "OS_SUBNET_CIDR":     _osp.get("subnetCIDR", "10.6.0.0/24"),
        "OS_CREDENTIALS_SECRET": _osp.get("credentialsSecret", cfg["name"] + "-cloud-config"),
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
        "TALOS_VERSION":      talos_version,
        "TALOS_VERSION_NAME": talos_version_name,
        "UPGRADE_STRATEGY":   upg.get("strategy", "blue-green"),
        "NODE_SELECTOR":      cfg.get("nodeSelector", ""),
        "PROVIDER_PROFILE_NAME": provider_name,
        "PROVIDER_PROFILE_IDENTITY": provider_identity,
        "MACHINE_TEMPLATE_ID": machine_template_id,
        "CLONE_TARGET_STORAGE_CLASS": provider_profile.get(
            "cloneTargetStorageClass", "ok-storage-block"
        ),
        # Generic, explicit OS/profile inputs. The shared renderer does not
        # assign Flatcar defaults; profile semantics stay in ok-linux and the
        # selected templates/<type> directory.
        "OS_DISTRIBUTION":    os_cfg.get("distribution", ""),
        "OS_PROFILE":         os_cfg.get("profile", ""),
        "OS_PROFILE_REVISION": os_cfg.get("profileRevision", ""),
        "OS_VERSION":         os_cfg.get("version", ""),
        "OS_ARCHITECTURE":    os_cfg.get("architecture", ""),
        "OS_IMAGE_DIGEST":    os_cfg.get("imageDigest", ""),
        "OS_IDENTITY":        identity,
        "OS_IDENTITY_SHORT":  identity_hex[:12],
        "OS_CANDIDATE_STATUS": os_cfg.get(
            "status", os_cfg.get("candidateStatus", "")
        ),
        "OS_DEPLOYABLE":      str(os_cfg.get("deployable", False)).lower(),
        "OS_GOLDEN_IMAGE_NAMESPACE": golden_image.get("namespace", ""),
        "OS_GOLDEN_IMAGE_CLAIM": golden_image.get("claim", ""),
        "OS_GOLDEN_IMAGE_PUBLISHED": str(
            golden_image.get("published", False)
        ).lower(),
        "OS_GOLDEN_IMAGE_STORAGE_CLASS": golden_image.get("storageClass", ""),
        "BOOTSTRAP_FORMAT": bootstrap.get("format", ""),
        "VM_BOOTSTRAP_CHECK_STRATEGY": bootstrap.get(
            "virtualMachineBootstrapCheck", ""
        ),
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
        # Provider profile: select the infra-provider fragment dir the same way
        # cluster_type selects its dir. Only the selected provider's fragment is
        # rendered, so provider-specific blocks never leak into the other's output.
        provider = cfg.get("provider", "kubevirt")
        prov_dir = TEMPLATES_DIR / "talos-mgmt" / "providers" / provider
        if not prov_dir.is_dir():
            raise SystemExit(f"ERROR: unknown provider profile '{provider}' "
                             f"(expected templates/talos-mgmt/providers/{provider}/)")
        tpl_dirs.append(prov_dir)
    elif cluster_type == "talos":
        # Workload provider selection (OK-106 Proof B). KubeVirt overlays only
        # its provider-specific manifests while retaining common Talos scripts;
        # other providers render their self-contained manifest set.
        provider = cfg.get("provider", "kubevirt")
        prov_dir = TEMPLATES_DIR / "talos" / "providers" / provider
        if not prov_dir.is_dir():
            raise SystemExit(f"ERROR: unknown talos provider profile '{provider}' "
                             f"(expected templates/talos/providers/{provider}/)")
        if provider == "kubevirt":
            tpl_dirs.append(prov_dir)
        else:
            tpl_dirs = [prov_dir]
    # Render and validate every artifact before the first filesystem write.
    templates = {}
    for tpl_dir in tpl_dirs:
        for tpl in tpl_dir.glob("*.tpl"):
            templates[tpl.name] = tpl
    rendered_templates = {}
    for tpl in sorted(templates.values(), key=lambda value: value.name):
        rendered = Template(tpl.read_text()).safe_substitute(ctx)
        rendered = apply_node_selector(rendered, ctx["NODE_SELECTOR"])
        if (
            cfg.get("workloadUserNamespaces", {}).get("enabled") is True
            and cluster_type == "talos"
            and cfg.get("provider", "kubevirt") == "kubevirt"
            and tpl.stem == "cluster-base.yaml"
        ):
            validate_workload_user_namespace_template(rendered, cfg)
        rendered_templates[tpl.stem] = (tpl, rendered)

    out_dir = output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    resolved_cfg_path = out_dir / "cluster-config.yaml"
    with open(resolved_cfg_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    print(f"  ✔ {resolved_cfg_path.relative_to(SCRIPT_DIR)}")

    for out_name, (tpl, rendered) in rendered_templates.items():
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
    if os.environ.get("OK_CLUSTER_SCAFFOLD_WORKLOAD_USER_NAMESPACES") == "1":
        capability = workload_user_namespaces_from_env(
            raw.get("type", "ubuntu"), raw.get("provider", "kubevirt")
        )
        if capability is not None:
            raw["workloadUserNamespaces"] = capability
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

def cmd_validate_workload_user_namespaces_env(args):
    workload_user_namespaces_from_env(args.cluster_type, args.provider)

def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def semantic_digest(value) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return sha256_bytes(raw)

def projection_resource(document: dict) -> dict:
    metadata = document.get("metadata", {})
    resource = {
        "apiVersion": document["apiVersion"],
        "kind": document["kind"],
        "name": metadata["name"],
    }
    if metadata.get("namespace"):
        resource["namespace"] = metadata["namespace"]
    return resource

def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)

def cmd_projection(args):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.intent_revision):
        raise SystemExit("ERROR: --intent-revision must be a lowercase SHA-256 digest")
    cluster_dir = CLUSTERS_DIR / args.cluster
    config_path = cluster_dir / "cluster-config.yaml"
    lifecycle_path = cluster_dir / "cluster-base.yaml"
    if not config_path.is_file() or not lifecycle_path.is_file():
        raise SystemExit("ERROR: render the cluster before creating its projection")
    config = load_yaml(config_path)
    if config.get("name") != args.cluster or config.get("type") != "talos" or config.get("provider", "kubevirt") != "kubevirt":
        raise SystemExit("ERROR: OK-147 projection requires the named Talos/KubeVirt cluster")
    secret_ref = config.get("infraClusterSecretRef")
    if not isinstance(secret_ref, dict) or set(secret_ref) != {"name", "namespace"}:
        raise SystemExit("ERROR: OK-147 projection requires infraClusterSecretRef")
    documents = [item for item in yaml.safe_load_all(lifecycle_path.read_text()) if item]
    expected_kinds = [
        "Namespace", "Role", "RoleBinding", "Cluster", "KubevirtCluster",
        "TalosControlPlane", "TalosConfigTemplate", "MachineDeployment",
        "KubevirtMachineTemplate", "KubevirtMachineTemplate",
    ]
    if [item.get("kind") for item in documents] != expected_kinds:
        raise SystemExit("ERROR: lifecycle manifest has an unexpected object inventory")
    annotations = {
        "openkubes.io/contract-name": args.cluster,
        "openkubes.io/contract-namespace": args.cluster,
        "openkubes.io/intent-revision": args.intent_revision,
    }
    for document in documents:
        document.setdefault("metadata", {}).setdefault("annotations", {}).update(annotations)
    infrastructure = documents[:3]
    management = [documents[0], *documents[3:]]
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit("ERROR: projection output already exists; refusing to overwrite it")
    if not output.parent.is_dir():
        raise SystemExit("ERROR: projection output parent must exist")
    output.mkdir(mode=0o700)
    infra_raw = yaml.safe_dump_all(infrastructure, sort_keys=False).encode()
    management_raw = yaml.safe_dump_all(management, sort_keys=False).encode()
    authority = {
        "format": "ok141-contract-to-capi-projection/v2",
        "contractIdentity": {"name": args.cluster, "namespace": args.cluster},
        "intentRevision": args.intent_revision,
        "infrastructurePlane": {
            "identity": "ok-infra",
            "role": "provider-runtime-and-golden-image-prerequisites",
            "resources": [projection_resource(item) for item in infrastructure],
        },
        "managementPlane": {
            "identity": "ok-mgmt",
            "role": "single-lifecycle-writer",
            "resources": [projection_resource(item) for item in management],
        },
        "providerAccess": {
            "mode": "external-cluster-secret",
            "managementPlane": "ok-mgmt",
            "providerPlane": "ok-infra",
            "secretRef": {"apiVersion": "v1", "kind": "Secret", **secret_ref},
            "targetNamespace": args.cluster,
            "materialization": "separate-gated-prerequisite-no-credential-bytes-in-projection",
        },
        "excludedRendererArtifacts": [{
            "path": "cluster-v2.yaml",
            "reason": "auxiliary machine template is outside the initial lifecycle graph",
        }],
    }
    authority_raw = (json.dumps(authority, indent=2) + "\n").encode()
    artifacts = {
        "authority-map.json": sha256_bytes(authority_raw),
        "ok-infra-prerequisites.yaml": sha256_bytes(infra_raw),
        "ok-mgmt-lifecycle.yaml": sha256_bytes(management_raw),
    }
    manifest = {
        "format": "ok141-contract-to-capi-projection/v2",
        "R": args.intent_revision,
        "authorizationState": "NO-GO",
        "artifacts": artifacts,
        "objectSets": {
            "okInfraPrerequisites": {"count": len(infrastructure), "digest": semantic_digest(infrastructure)},
            "okMgmtLifecycle": {"count": len(management), "digest": semantic_digest(management)},
        },
        "providerAccess": authority["providerAccess"],
        "source": {
            "clusterConfigDigest": sha256_bytes(config_path.read_bytes()),
            "clusterBaseDigest": sha256_bytes(lifecycle_path.read_bytes()),
            "renderer": "ok-cluster/render.py",
        },
    }
    manifest_raw = (json.dumps(manifest, indent=2) + "\n").encode()
    for name, raw in (
        ("authority-map.json", authority_raw),
        ("ok-infra-prerequisites.yaml", infra_raw),
        ("ok-mgmt-lifecycle.yaml", management_raw),
        ("manifest.json", manifest_raw),
    ):
        write_private(output / name, raw)
    print(json.dumps({
        "format": "ok147-offline-projection-render/v1",
        "state": "RENDERED",
        "cluster": args.cluster,
        "intentRevision": args.intent_revision,
        "outputDirectory": str(output),
        "apiContacted": False,
        "mutationAllowed": False,
    }, indent=2))

def main():
    p = argparse.ArgumentParser(description="OpenKubes cluster manifest renderer")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render"); r.add_argument("--cluster", required=True); r.set_defaults(func=cmd_render)
    l = sub.add_parser("list"); l.set_defaults(func=cmd_list)
    ip = sub.add_parser("next-ip"); ip.add_argument("--cluster", default="__new__"); ip.add_argument("--start-ip", default=None); ip.set_defaults(func=cmd_show_ip)
    wuns = sub.add_parser("validate-workload-user-namespaces-env")
    wuns.add_argument("--type", dest="cluster_type", required=True)
    wuns.add_argument("--provider", required=True)
    wuns.set_defaults(func=cmd_validate_workload_user_namespaces_env)
    projection = sub.add_parser("projection")
    projection.add_argument("--cluster", required=True)
    projection.add_argument("--intent-revision", required=True)
    projection.add_argument("--output", required=True)
    projection.set_defaults(func=cmd_projection)
    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
