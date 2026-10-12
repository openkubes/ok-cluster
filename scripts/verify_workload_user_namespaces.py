#!/usr/bin/env python3
"""Compare the Talos worker mount path with the guest StorageClass BasePath."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import render  # noqa: E402


def verify(cluster_dir: Path, kubeconfig: str) -> int:
    config_path = cluster_dir / "cluster-config.yaml"
    try:
        config = render.load_yaml(config_path)
        capability = render.validate_workload_user_namespaces(config)
    except Exception as exc:
        print(f"FAIL: invalid workloadUserNamespaces config: {exc}", file=sys.stderr)
        return 1
    if capability is None or not capability["enabled"]:
        print("SKIP: workload user namespaces are disabled; no guest API reads performed")
        return 0
    expected = capability["provisionerBasePath"]
    command = ["kubectl", "--kubeconfig", kubeconfig, "get", "storageclass", "ok-storage-local-quota", "-o", "json"]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        print(f"FAIL: cannot read StorageClass ok-storage-local-quota: {detail.strip()}", file=sys.stderr)
        return 1
    try:
        storage_class = json.loads(result.stdout)
        annotation = storage_class["metadata"]["annotations"]["cas.openebs.io/config"]
        entries = yaml.safe_load(annotation)
    except (KeyError, TypeError, yaml.YAMLError, json.JSONDecodeError) as exc:
        print(f"FAIL: StorageClass is missing a valid cas.openebs.io/config annotation: {exc}", file=sys.stderr)
        return 1
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        print("FAIL: cas.openebs.io/config must be a YAML list of mappings", file=sys.stderr)
        return 1
    base_paths = [item.get("value") for item in entries if item.get("name") == "BasePath"]
    if len(base_paths) != 1:
        print(f"FAIL: expected exactly one BasePath entry in StorageClass annotation; found {len(base_paths)}", file=sys.stderr)
        return 1
    if base_paths[0] != expected:
        print(f"FAIL: worker provisionerBasePath {expected!r} does not match StorageClass BasePath {base_paths[0]!r}", file=sys.stderr)
        return 1
    print(f"PASS: worker provisionerBasePath matches ok-storage-local-quota BasePath ({expected})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster-dir", type=Path, required=True)
    parser.add_argument("--kubeconfig", required=True)
    args = parser.parse_args()
    return verify(args.cluster_dir, args.kubeconfig)


if __name__ == "__main__":
    raise SystemExit(main())
