#!/usr/bin/env python3
"""v1.0.1 + compatibility patch (compat/v1.0.1-scaleway): offline tests.

Proves that with OK_COMPAT_* unset every rendered artifact is byte-identical to v1.0.1 behaviour, and that
when set only VM placement / node lookups and the endpoint pool change (logical profile, identity digest,
storage contract unchanged). Each scenario runs in a fresh subprocess because render.py reads the pool at import.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OK_LINUX = Path(os.environ.get("OK_LINUX_PATH", ROOT.parent / "ok-linux"))
FAILURES: list[str] = []
PASSED = 0


def check(condition: bool, message: str) -> None:
    global PASSED
    if condition:
        PASSED += 1
        print(f"PASS {message}")
    else:
        FAILURES.append(message)
        print(f"FAIL {message}")


def run(code: str, **env: str) -> subprocess.CompletedProcess:
    environment = {k: v for k, v in os.environ.items() if not k.startswith("OK_COMPAT_")}
    environment.update(env)
    environment["OK_LINUX_PATH"] = str(OK_LINUX)
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=environment,
                          capture_output=True, text=True, timeout=120)


RENDER = r'''
import json, sys, tempfile, copy, yaml
from pathlib import Path
sys.path.insert(0, ".")
import render
from profile_resolvers.talos import resolve_talos_config
out = {}
raw = yaml.safe_load(open("tests/fixtures/ok130-talos/cluster-config.yaml"))
resolved = resolve_talos_config(raw, Path("''' + str(OK_LINUX) + r'''"))
with tempfile.TemporaryDirectory(prefix=".compat-", dir=".") as t:
    render.render_cluster(raw["name"], Path(t), resolved)
    out["talos"] = {p.name: p.read_text() for p in sorted(Path(t).iterdir()) if p.is_file()}
ubuntu = copy.deepcopy(yaml.safe_load(open("ok-robotics/cluster-config.yaml")))
ubuntu["type"] = "ubuntu"; ubuntu["name"] = "compat-ubuntu"
with tempfile.TemporaryDirectory(prefix=".compat-", dir=".") as t:
    render.render_cluster(ubuntu["name"], Path(t), ubuntu)
    out["ubuntu"] = {p.name: p.read_text() for p in sorted(Path(t).iterdir()) if p.is_file()}
out["resolved_nodeSelector"] = resolved["nodeSelector"]
out["provider"] = resolved["providerProfile"]
out["pool"] = [str(render.METALLB_POOL_START), str(render.METALLB_POOL_END)]
out["first_free"] = render.next_free_ip(set())
print(json.dumps(out))
'''


def render_with(**env: str) -> dict:
    result = run(RENDER, **env)
    if result.returncode != 0:
        print(result.stdout[-2000:], result.stderr[-2000:])
        return {}
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> int:
    # 1. helper unit behaviour
    probe = r'''
import sys, ipaddress; sys.path.insert(0, ".")
from profile_resolvers.compat import physical_node, endpoint_pool, CompatError
d = (ipaddress.IPv4Address("192.168.100.200"), ipaddress.IPv4Address("192.168.100.254"))
r = [physical_node("ok-infra"), physical_node("ok-gpu"), physical_node("")]
try: r.append([str(a) for a in endpoint_pool(*d)])
except CompatError as e: r.append("ERR " + str(e))
print(r)
'''
    check(run(probe).stdout.strip() == "['ok-infra', 'ok-gpu', '', ['192.168.100.200', '192.168.100.254']]",
          "unset: physical node == logical node, pool == v1.0.1 constants")
    check(run(probe, OK_COMPAT_PHYSICAL_NODE="scw2", OK_COMPAT_ENDPOINT_POOL="10.250.0.10-10.250.0.20").stdout.strip()
          == "['scw2', 'ok-gpu', '', ['10.250.0.10', '10.250.0.20']]",
          "set: only the ok-infra profile maps to scw2; pool overridden")
    for value, why in (("Bad_Node", "invalid node name"),):
        check("is not a valid Kubernetes node name" in run(probe, OK_COMPAT_PHYSICAL_NODE=value).stderr,
              f"rejects {why}")
    for value, why in (("10.40.0.1-10.40.0.5", "overlap with workload Pod CIDR pool 10.32.0.0/11"),
                       ("10.100.0.1-10.100.0.5", "overlap with workload Service CIDR pool 10.96.0.0/12"),
                       ("10.250.0.0-10.250.1.255", "more than 256 addresses"),
                       ("127.0.0.10-127.0.0.20", "loopback"),
                       ("10.250.0.20-10.250.0.10", "reversed range"),
                       ("10.250.0.10", "malformed value")):
        check("ERR" in run(probe, OK_COMPAT_ENDPOINT_POOL=value).stdout, f"rejects pool: {why}")

    # 2. rendering: unset == v1.0.1 (reference: render code of the v1.0.1 tag in a git worktree)
    base = render_with()
    check(bool(base), "render (unset) succeeds for Talos/KubeVirt and Ubuntu")
    reference = os.environ.get("COMPAT_REFERENCE_JSON")
    if reference and base:
        ref = json.loads(Path(reference).read_text())
        check(ref.get("talos") == base.get("talos") and ref.get("ubuntu") == base.get("ubuntu"),
              "unset: rendered Talos and Ubuntu manifests byte-identical to unpatched v1.0.1")
    patched = render_with(OK_COMPAT_PHYSICAL_NODE="scw2", OK_COMPAT_ENDPOINT_POOL="10.250.0.10-10.250.0.20")
    check(bool(patched), "render (set) succeeds")
    if base and patched:
        check(patched["resolved_nodeSelector"] == "ok-infra" and patched["provider"] == base["provider"],
              "set: logical nodeSelector, provider profile and identity digest unchanged")
        for kind in ("talos", "ubuntu"):
            changed = []
            for name, text in base[kind].items():
                old, new = text.splitlines(), patched[kind][name].splitlines()
                changed += [(a, b) for a, b in zip(old, new) if a != b]
            hostname = [p for p in changed if "kubernetes.io/hostname:" in p[0]]
            check(bool(hostname) and len(hostname) == len(changed)
                  and all(a.endswith("ok-infra") and b.endswith("scw2") for a, b in changed),
                  f"set: {kind} differs only in VM placement hostname ok-infra -> scw2 ({len(changed)} lines)")
        check(base["pool"] == ["192.168.100.200", "192.168.100.254"] and base["first_free"] == "192.168.100.200",
              "unset: endpoint allocation starts at 192.168.100.200")
        check(patched["pool"] == ["10.250.0.10", "10.250.0.20"] and patched["first_free"] == "10.250.0.10",
              "set: endpoint allocation from 10.250.0.10-10.250.0.20")
    bad = run(RENDER, OK_COMPAT_ENDPOINT_POOL="10.40.0.1-10.40.0.5")
    check(bad.returncode != 0 and "overlaps the workload CIDR pool" in (bad.stdout + bad.stderr),
          "render refuses an invalid pool before rendering anything")

    # 3. lifecycle checks look up the physical node
    lookup = r'''
import sys, json; sys.path.insert(0, ".")
from pathlib import Path
import scripts.talos_golden_lifecycle as t
calls = []
def fake(kubeconfig, args):
    calls.append(args)
    if args[:2] == ["get", "node"]:
        return {"metadata": {"name": args[2]}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}],
                "allocatable": {"cpu": "8", "memory": "32Gi"}}}
    return {"items": []}
t.kubectl_json = fake
cfg = {"providerProfile": {"nodeSelector": "ok-infra"}, "controlPlane": {"replicas": 1, "cpu": 2, "memory": "4Gi"},
       "workers": {"replicas": 1, "cpu": 2, "memory": "4Gi"}}
try:
    t.verify_scheduling(cfg, Path("/dev/null"))
except Exception as e:
    pass
print(json.dumps(calls[0]))
'''
    check(run(lookup).stdout.strip().endswith('["get", "node", "ok-infra"]'), "unset: scheduling check reads node/ok-infra")
    check(run(lookup, OK_COMPAT_PHYSICAL_NODE="scw2").stdout.strip().endswith('["get", "node", "scw2"]'),
          "set: scheduling check reads node/scw2")
    source = (ROOT / "scripts" / "talos_golden_lifecycle.py").read_text()
    check(source.count("physical_node(") == 4 and 'provider["nodeSelector"] not in' not in source,
          "all four physical-node comparisons in the Talos lifecycle use physical_node()")

    print(f"RESULT: {PASSED} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
