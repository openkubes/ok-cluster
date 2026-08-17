#!/usr/bin/env python3
"""Hydrate and operate the opt-in Talos registry-trust building block.

Secret values stay in process memory or anonymous file descriptors.  No CA,
registry address, talosconfig, or complete machine config is written to disk.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
from string import Template
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PATCH_TEMPLATE = ROOT / "templates/talos/patches/registry-trust.yaml.tpl"
EXPECTED_HOST = "registry.ok-shared.internal"


class TrustError(RuntimeError):
    pass


def run(argv: list[str], *, stdin: bytes | None = None) -> bytes:
    try:
        return subprocess.run(
            argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True,
        ).stdout
    except FileNotFoundError as exc:
        raise TrustError(f"required command not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        # Never echo stderr: kubectl/talosctl may include Secret or config data.
        raise TrustError(f"{argv[0]} failed (exit {exc.returncode})") from exc


def load_config(cluster: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = ROOT / cluster / "cluster-config.yaml"
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise TrustError(f"cannot read {path}") from exc
    trust = cfg.get("registryTrust")
    if not isinstance(trust, dict) or trust.get("enabled") is not True:
        raise TrustError("registryTrust.enabled must be explicitly true")
    if cfg.get("type") != "talos":
        raise TrustError("registry trust is supported only for type: talos")
    required = {
        "host": trust.get("host"),
        "caSecret.namespace": (trust.get("caSecret") or {}).get("namespace"),
        "caSecret.name": (trust.get("caSecret") or {}).get("name"),
        "caSecret.key": (trust.get("caSecret") or {}).get("key"),
        "address.serviceNamespace": (trust.get("address") or {}).get("serviceNamespace"),
        "address.serviceName": (trust.get("address") or {}).get("serviceName"),
        "talosconfigSecret.namespace": (trust.get("talosconfigSecret") or {}).get("namespace"),
        "talosconfigSecret.name": (trust.get("talosconfigSecret") or {}).get("name"),
        "talosconfigSecret.key": (trust.get("talosconfigSecret") or {}).get("key"),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise TrustError("registryTrust is incomplete: " + ", ".join(missing))
    if trust["host"] != EXPECTED_HOST:
        raise TrustError(f"registryTrust.host must be {EXPECTED_HOST}")
    return cfg, trust


def secret_value(kubeconfig: str, ref: dict[str, str]) -> bytes:
    raw = run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", ref["namespace"],
        "get", "secret", ref["name"], "-o", "json",
    ])
    try:
        encoded = json.loads(raw)["data"][ref["key"]]
        value = base64.b64decode(encoded, validate=True)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise TrustError(
            f"Secret {ref['namespace']}/{ref['name']} lacks valid key {ref['key']}"
        ) from exc
    if not value:
        raise TrustError("Secret value is empty")
    return value


def _single_ip(values: list[str], source: str) -> str:
    concrete: list[str] = []
    for value in values:
        try:
            concrete.append(str(socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, value))))
        except OSError as exc:
            raise TrustError(f"{source} contains a non-IPv4 value") from exc
    concrete = sorted(set(concrete))
    if len(concrete) != 1:
        raise TrustError(f"{source} must resolve to exactly one concrete IPv4 address")
    return concrete[0]


def discover_address(
    trust: dict[str, Any], infra_kubeconfig: str, override: str | None
) -> tuple[str, str]:
    if override:
        return _single_ip([override], "explicit REGISTRY_ADDRESS"), "explicit override"
    try:
        answers = socket.getaddrinfo(trust["host"], 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = [answer[4][0] for answer in answers]
        return _single_ip(ips, "DNS"), "DNS"
    except socket.gaierror:
        pass
    address = trust["address"]
    raw = run([
        "kubectl", "--kubeconfig", infra_kubeconfig, "-n", address["serviceNamespace"],
        "get", "service", address["serviceName"], "-o", "json",
    ])
    try:
        ingress = json.loads(raw).get("status", {}).get("loadBalancer", {}).get("ingress", [])
        if any(item.get("hostname") for item in ingress if isinstance(item, dict)):
            raise TrustError(
                "ok-infra Service status contains a hostname; extraHostEntries requires IPv4"
            )
        ips = [item.get("ip", "") for item in ingress if isinstance(item, dict)]
    except json.JSONDecodeError as exc:
        raise TrustError("invalid Service JSON while discovering registry address") from exc
    return _single_ip(ips, "ok-infra Service status.loadBalancer.ingress"), "ok-infra Service"


def validate_ca(ca: bytes) -> None:
    try:
        ca_text = ca.decode("utf-8")
        ssl.PEM_cert_to_DER_cert(ca_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TrustError("registry CA is not UTF-8 PEM") from exc


def semantic_patch(host: str, address: str, ca: bytes) -> dict[str, Any]:
    validate_ca(ca)
    return {
        "machine": {
            "registries": {
                "config": {
                    host: {
                        "tls": {
                            # Talos v1.9 RegistryTLSConfig.ca is Base64Bytes.
                            "ca": base64.b64encode(ca).decode("ascii")
                        }
                    }
                }
            },
            "network": {"extraHostEntries": [{"ip": address, "aliases": [host]}]},
        }
    }


def render_patch(host: str, address: str, ca: bytes) -> bytes:
    # Render the committed fragment, then parse/re-emit it to guarantee the
    # runtime and declarative forms come from the same semantic object.
    rendered = Template(PATCH_TEMPLATE.read_text(encoding="utf-8")).substitute(
        REGISTRY_HOST=json.dumps(host),
        REGISTRY_ADDRESS=json.dumps(address),
        REGISTRY_CA_BASE64=json.dumps(base64.b64encode(ca).decode("ascii")),
    )
    parsed = yaml.safe_load(rendered)
    expected = semantic_patch(host, address, ca)
    if parsed != expected:
        raise TrustError("committed registry patch fragment changed semantics")
    return yaml.safe_dump(expected, sort_keys=False).encode()


def capi_ops(host: str, address: str, ca: bytes) -> list[dict[str, Any]]:
    machine = semantic_patch(host, address, ca)["machine"]
    return [
        {"op": "add", "path": "/machine/registries", "value": machine["registries"]},
        {"op": "add", "path": "/machine/network/extraHostEntries", "value": machine["network"]["extraHostEntries"]},
    ]


def upsert_capi_patches(
    existing: list[dict[str, Any]], host: str, address: str, ca: bytes
) -> list[dict[str, Any]]:
    if not isinstance(existing, list) or not all(
        isinstance(item, dict) for item in existing
    ):
        raise TrustError("live CAPI configPatches is not an object list")
    owned_paths = {"/machine/registries", "/machine/network/extraHostEntries"}
    preserved: list[dict[str, Any]] = []
    registries: dict[str, Any] = {}
    entries: list[dict[str, Any]] = []
    for item in existing:
        path = item.get("path")
        if isinstance(path, str) and (
            path.startswith("/machine/registries/")
            or path.startswith("/machine/network/extraHostEntries/")
        ):
            raise TrustError(
                f"cannot safely compose registry trust with nested CAPI patch {path}; "
                "consolidate it at the parent path first"
            )
        if path not in owned_paths:
            preserved.append(item)
            continue
        if item.get("op") not in ("add", "replace"):
            raise TrustError(f"cannot safely merge CAPI patch operation at {path}")
        value = json.loads(json.dumps(item.get("value")))
        if path == "/machine/registries":
            if not isinstance(value, dict):
                raise TrustError("CAPI /machine/registries patch is not a mapping")
            registries = value
        else:
            if not isinstance(value, list):
                raise TrustError("CAPI extraHostEntries patch is not a list")
            entries = value
    merged = runtime_ops(
        {
            "machine": {
                "registries": registries,
                "network": {"extraHostEntries": entries},
            }
        },
        host,
        address,
        ca,
    )
    return [*preserved, *merged]


def hydrate_manifest(raw: bytes, host: str, address: str, ca: bytes) -> bytes:
    docs = list(yaml.safe_load_all(raw))
    matched: list[str] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind == "TalosControlPlane":
            spec = doc["spec"]["controlPlaneConfig"]["controlplane"]
            matched.append(kind)
        elif kind == "TalosConfigTemplate":
            spec = doc["spec"]["template"]["spec"]
            matched.append(kind)
        else:
            continue
        spec["configPatches"] = upsert_capi_patches(
            spec.setdefault("configPatches", []), host, address, ca
        )
    if matched.count("TalosControlPlane") != 1 or matched.count("TalosConfigTemplate") != 1:
        raise TrustError("manifest must contain exactly one control-plane and one worker Talos config")
    return yaml.safe_dump_all(docs, sort_keys=False).encode()


def anonymous_fd(data: bytes) -> tuple[int, str]:
    if not hasattr(os, "memfd_create"):
        raise TrustError("anonymous memfd support is required")
    fd = os.memfd_create("ok-registry-trust", flags=0)
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    os.set_inheritable(fd, True)
    return fd, f"/proc/self/fd/{fd}"


def run_with_fds(
    argv: list[str], fds: list[int], *, include_stderr: bool = False
) -> bytes:
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            pass_fds=tuple(fds),
        )
        return result.stdout + (result.stderr if include_stderr else b"")
    except FileNotFoundError as exc:
        raise TrustError(f"required command not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise TrustError(f"{argv[0]} failed (exit {exc.returncode})") from exc
    finally:
        for fd in fds:
            os.close(fd)


def validate_with_talosctl(patch: bytes) -> None:
    version = run(["talosctl", "version", "--client"]).decode("utf-8", "replace")
    if not re.search(r"(?m)^\s*Tag:\s+v1\.9\.5\s*$", version):
        raise TrustError("talosctl v1.9.5 is required")
    for role in ("controlplane", "worker"):
        patch_fd, patch_path = anonymous_fd(patch)
        generated = run_with_fds([
            "talosctl", "gen", "config", "ok138-validation",
            "https://192.0.2.10:6443",
            "--talos-version", "v1.9",
            "--output-types", role,
            "--output", "-",
            "--with-cluster-discovery=false",
            "--with-docs=false",
            "--with-examples=false",
            "--config-patch", "@" + patch_path,
        ], [patch_fd])
        config_fd, config_path = anonymous_fd(generated)
        run_with_fds([
            "talosctl", "validate", "--config", config_path,
            "--mode", "cloud", "--strict",
        ], [config_fd])


def probe_registry(host: str, address: str, ca: bytes) -> None:
    context = ssl.create_default_context(cadata=ca.decode("utf-8"))
    try:
        with socket.create_connection((address, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    f"GET /v2/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                first = tls.recv(4096).split(b"\r\n", 1)[0]
    except (OSError, ssl.SSLError) as exc:
        raise TrustError("registry TLS/SNI preflight failed") from exc
    if not first.startswith((b"HTTP/1.1 200", b"HTTP/1.1 401", b"HTTP/2 200", b"HTTP/2 401")):
        raise TrustError("registry /v2/ preflight returned an unexpected status")


def node_internal_ip(kubeconfig: str, node_name: str) -> str:
    """Look up the authoritative InternalIP of a workload-cluster Node.

    CAPI Machine.status.addresses can carry several entries tagged
    InternalIP on multi-NIC nodes (a secondary network plus per-interface
    IPv6 link-local addresses), which breaks any assumption of exactly one
    InternalIP at the Machine level. The Kubernetes Node object itself is
    authoritative and kubelet-reported: it always exposes exactly one
    InternalIP. We cross-reference via the Machine's Hostname address,
    which is identical to the Node name.
    """
    raw = run([
        "kubectl", "--kubeconfig", kubeconfig, "get", "node", node_name, "-o", "json",
    ])
    try:
        addresses = json.loads(raw)["status"]["addresses"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise TrustError(f"invalid Node address data for {node_name}") from exc
    ips = sorted({
        a["address"] for a in addresses if a.get("type") == "InternalIP"
    })
    if len(ips) != 1:
        raise TrustError(f"Node {node_name} must expose exactly one InternalIP")
    return ips[0]


def discover_nodes(cluster: str, infra_kubeconfig: str, workload_kubeconfig: str) -> list[str]:
    raw = run([
        "kubectl", "--kubeconfig", infra_kubeconfig, "-n", cluster, "get", "machines",
        "-l", f"cluster.x-k8s.io/cluster-name={cluster}", "-o", "json",
    ])
    try:
        items = json.loads(raw).get("items", [])
        values = []
        for item in items:
            hostnames = sorted({
                address["address"]
                for address in item.get("status", {}).get("addresses", [])
                if address.get("type") == "Hostname"
            })
            if len(hostnames) != 1:
                raise TrustError("every CAPI Machine must expose exactly one Hostname")
            values.append(node_internal_ip(workload_kubeconfig, hostnames[0]))
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise TrustError("invalid Machine address data") from exc
    nodes = sorted(set(values))
    if not nodes or len(nodes) != len(items):
        raise TrustError("every CAPI Machine must resolve to a unique Node InternalIP")
    for node in nodes:
        _single_ip([node], "Machine InternalIP")
    return nodes


def runtime_ops(
    current: dict[str, Any], host: str, address: str, ca: bytes
) -> list[dict[str, Any]]:
    """Upsert our two fields while preserving unrelated node configuration."""
    machine = current.get("machine")
    if not isinstance(machine, dict):
        raise TrustError("live MachineConfig spec has no machine mapping")

    registries = json.loads(json.dumps(machine.get("registries") or {}))
    if not isinstance(registries, dict):
        raise TrustError("live machine.registries is not a mapping")
    config = registries.setdefault("config", {})
    if not isinstance(config, dict):
        raise TrustError("live machine.registries.config is not a mapping")
    registry = config.setdefault(host, {})
    if not isinstance(registry, dict):
        raise TrustError("live registry-specific config is not a mapping")
    tls = registry.setdefault("tls", {})
    if not isinstance(tls, dict):
        raise TrustError("live registry-specific TLS config is not a mapping")
    tls["ca"] = base64.b64encode(ca).decode("ascii")

    network = machine.get("network") or {}
    if not isinstance(network, dict):
        raise TrustError("live machine.network is not a mapping")
    entries = network.get("extraHostEntries") or []
    if not isinstance(entries, list):
        raise TrustError("live machine.network.extraHostEntries is not a list")
    preserved: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("aliases", []), list):
            raise TrustError("live extraHostEntries contains an invalid entry")
        kept = json.loads(json.dumps(entry))
        kept["aliases"] = [alias for alias in kept.get("aliases", []) if alias != host]
        if kept["aliases"]:
            preserved.append(kept)
    preserved.append({"ip": address, "aliases": [host]})

    return [
        {"op": "add", "path": "/machine/registries", "value": registries},
        {
            "op": "add",
            "path": "/machine/network/extraHostEntries",
            "value": preserved,
        },
    ]


def get_machine_config(node: str, talosconfig: bytes) -> dict[str, Any]:
    config_fd, config_path = anonymous_fd(talosconfig)
    raw = run_with_fds([
        "talosctl", "--talosconfig", config_path, "--nodes", node,
        "get", "machineconfig", "--output", "json",
    ], [config_fd])
    try:
        resource = json.loads(raw)
        spec = resource["spec"]
        # talosctl encodes MachineConfig.spec as a YAML string, not nested JSON.
        if isinstance(spec, str):
            spec = yaml.safe_load(spec)
    except (json.JSONDecodeError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise TrustError(f"Talos returned an invalid MachineConfig for node {node}") from exc
    if not isinstance(spec, dict):
        raise TrustError(f"Talos returned a non-mapping MachineConfig spec for node {node}")
    return spec


def assert_applied(
    current: dict[str, Any], host: str, address: str, ca: bytes
) -> None:
    machine = current.get("machine") or {}
    actual_ca = (
        ((machine.get("registries") or {}).get("config") or {})
        .get(host, {}).get("tls", {}).get("ca")
    )
    aliases = [
        entry for entry in ((machine.get("network") or {}).get("extraHostEntries") or [])
        if isinstance(entry, dict) and host in entry.get("aliases", [])
    ]
    alias_ok = (
        len(aliases) == 1
        and aliases[0].get("ip") == address
        and aliases[0].get("aliases") == [host]
    )
    if actual_ca != base64.b64encode(ca).decode("ascii") or not alias_ok:
        raise TrustError("post-apply MachineConfig readback does not match registry trust")


def runtime_talos(
    action: str, cluster: str, trust: dict[str, Any], infra: str, workload_kubeconfig: str,
    patch: bytes, address: str, ca: bytes,
) -> None:
    probe_registry(trust["host"], address, ca)
    validate_with_talosctl(patch)
    nodes = discover_nodes(cluster, infra, workload_kubeconfig)
    talosconfig = secret_value(infra, trust["talosconfigSecret"])
    patches: dict[str, bytes] = {}
    for node in nodes:
        current = get_machine_config(node, talosconfig)
        patches[node] = yaml.safe_dump(
            runtime_ops(current, trust["host"], address, ca), sort_keys=False
        ).encode()

    def invoke(node: str, *, dry_run: bool) -> None:
        patch_fd, patch_path = anonymous_fd(patches[node])
        config_fd, config_path = anonymous_fd(talosconfig)
        argv = [
            "talosctl", "patch", "machineconfig", "--talosconfig", config_path,
            "--nodes", node, "--patch-file", patch_path,
            "--mode", "no-reboot",
        ]
        if dry_run:
            argv.append("--dry-run")
        # A current config may contain existing registry auth. Capture and
        # discard Talos' patch preview rather than risk echoing it.
        run_with_fds(argv, [patch_fd, config_fd])

    for node in nodes:
        invoke(node, dry_run=True)
    print(
        f"Talos API accepted --mode=no-reboot dry-run for all {len(nodes)} CAPI Machines"
    )
    if action == "apply":
        for node in nodes:
            invoke(node, dry_run=False)
        for node in nodes:
            assert_applied(
                get_machine_config(node, talosconfig),
                trust["host"], address, ca,
            )
            print(f"readback PASS node={node}: registry CA and host alias landed")
        print(f"apply succeeded for all {len(nodes)} CAPI Machines without reboot")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("hydrate", "review", "dry-run", "apply"))
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--infra-kubeconfig", required=True)
    parser.add_argument("--ca-kubeconfig")
    parser.add_argument("--workload-kubeconfig")
    parser.add_argument("--address")
    args = parser.parse_args()
    try:
        _, trust = load_config(args.cluster)
        ca_kubeconfig = args.ca_kubeconfig or os.environ.get("REGISTRY_CA_KUBECONFIG")
        if not ca_kubeconfig:
            raise TrustError("REGISTRY_CA_KUBECONFIG is required")
        ca = secret_value(ca_kubeconfig, trust["caSecret"])
        address, source = discover_address(trust, args.infra_kubeconfig, args.address)
        patch = render_patch(trust["host"], address, ca)
        if args.action == "hydrate":
            manifest = (ROOT / args.cluster / "cluster-base.yaml").read_bytes()
            hydrated = hydrate_manifest(manifest, trust["host"], address, ca)
            run(["kubectl", "--kubeconfig", args.infra_kubeconfig, "apply", "-f", "-"], stdin=hydrated)
            print(f"hydrated CAPI control-plane and worker configs from {source}")
        elif args.action == "review":
            probe_registry(trust["host"], address, ca)
            validate_with_talosctl(patch)
            print(f"registry trust review: host={trust['host']} address-source={source}")
            print("semantic patch: machine.registries.config CA + machine.network.extraHostEntries")
            print("Talos v1.9.5 control-plane and worker validation passed")
            print("registry TLS/SNI /v2/ probe succeeded")
            print("exact hydrated patch (runtime-only; do not commit):")
            print(patch.decode("utf-8"), end="")
        else:
            if args.action == "apply" and os.environ.get("REGISTRY_TRUST_APPLY") != "yes":
                raise TrustError("apply requires REGISTRY_TRUST_APPLY=yes")
            # The CA lives on whichever cluster hosts the registry (ok-shared); the nodes
            # being patched live on --cluster, which is not always the same cluster. Reusing
            # ca_kubeconfig here silently looked up Node objects on the wrong cluster for any
            # CLUSTER other than the one hosting the CA -- never caught before because every
            # prior run onboarded ok-shared to itself, where the two happen to coincide.
            workload_kubeconfig = args.workload_kubeconfig or os.environ.get(
                "TALOS_WORKLOAD_KUBECONFIG"
            )
            if not workload_kubeconfig:
                raise TrustError(
                    "TALOS_WORKLOAD_KUBECONFIG (or --workload-kubeconfig) is required for "
                    "dry-run/apply: it must be the kubeconfig of --cluster itself, not of "
                    "whichever cluster hosts the registry CA"
                )
            runtime_talos(
                args.action, args.cluster, trust, args.infra_kubeconfig, workload_kubeconfig,
                patch, address, ca,
            )
        return 0
    except (TrustError, OSError, UnicodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
