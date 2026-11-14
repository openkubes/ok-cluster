#!/usr/bin/env python3
"""Offline regression tests for OK-76 M2a Make and inventory gates."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import contextlib
import io
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("ok76_render", ROOT / "render.py")
assert SPEC and SPEC.loader
render = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render)


def service(name="svc", namespace="default", service_type="LoadBalancer", **extra):
    uid = extra.pop("uid", f"uid-{namespace}-{name}")
    item = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace, "uid": uid},
        "spec": {"type": service_type},
    }
    item.update(extra)
    return item


def list_json(items):
    return json.dumps({"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": "123"}, "items": items})


class RenderInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.kubeconfig = Path(self.temp.name) / "management.kubeconfig"
        self.kubeconfig.write_text("fixture only\n", encoding="utf-8")
        self.explicit_kubeconfig = mock.patch.object(render, "OKB_KUBECONFIG", str(self.kubeconfig))
        self.explicit_kubeconfig_flag = mock.patch.object(render, "OKB_KUBECONFIG_EXPLICIT", True)
        self.explicit_kubeconfig.start()
        self.explicit_kubeconfig_flag.start()
        self.addCleanup(self.explicit_kubeconfig.stop)
        self.addCleanup(self.explicit_kubeconfig_flag.stop)

    def run_inventory(self, stdout, required=True, returncode=0):
        result = subprocess.CompletedProcess(["kubectl"], returncode, stdout, "")
        if returncode:
            with mock.patch.object(render.subprocess, "run", side_effect=subprocess.CalledProcessError(returncode, "kubectl")):
                return render.live_metallb_allocations(required=required)
        with mock.patch.object(render.subprocess, "run", return_value=result):
            return render.live_metallb_allocations(required=required)

    def test_valid_empty_inventory_is_confirmed_empty(self):
        result = subprocess.CompletedProcess(["kubectl"], 0, list_json([]), "")
        with mock.patch.object(render.subprocess, "run", return_value=result) as run:
            self.assertEqual(render.live_metallb_allocations(required=True), {})
        argv = run.call_args.args[0]
        self.assertEqual(argv[1:], ["--kubeconfig", render.OKB_KUBECONFIG, "get", "svc", "-A", "-o", "json", "--request-timeout=10s"])
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_valid_inventory_collects_ipv4_and_excludes_requested_namespace(self):
        items = [
            service("one", spec={"type": "LoadBalancer", "loadBalancerIP": "192.168.100.210"}),
            service("two", "other", status={"loadBalancer": {"ingress": [{"ip": "192.168.100.211"}]}}),
        ]
        self.assertEqual(
            self.run_inventory(list_json(items)),
            {"192.168.100.210": "default/one", "192.168.100.211": "other/two"},
        )
        result = subprocess.CompletedProcess(["kubectl"], 0, list_json(items), "")
        with mock.patch.object(render.subprocess, "run", return_value=result):
            self.assertEqual(render.live_metallb_allocations(exclude_cluster="default", required=True),
                             {"192.168.100.211": "other/two"})

    def test_non_loadbalancer_without_status_is_valid(self):
        self.assertEqual(self.run_inventory(list_json([service(service_type="ClusterIP")])), {})

    def test_command_failure_is_unknown_in_required_mode_and_fallback_for_legacy_mode(self):
        with mock.patch.object(render.subprocess, "run", side_effect=subprocess.TimeoutExpired("kubectl", 20)):
            with self.assertRaisesRegex(RuntimeError, "inventory is unavailable"):
                render.live_metallb_allocations(required=True)
            self.assertIsNone(render.live_metallb_allocations(required=False))

    def test_nonzero_exit_and_missing_binary_fail_closed(self):
        with mock.patch.object(render.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "kubectl")):
            with self.assertRaisesRegex(RuntimeError, "inventory is unavailable"):
                render.live_metallb_allocations(required=True)

    def test_required_inventory_rejects_implicit_or_missing_kubeconfig(self):
        with mock.patch.object(render, "OKB_KUBECONFIG_EXPLICIT", False):
            with self.assertRaisesRegex(RuntimeError, "explicit management kubeconfig is required"):
                render.live_metallb_allocations(required=True)
        with mock.patch.object(render, "OKB_KUBECONFIG", str(self.kubeconfig) + ".missing"):
            with self.assertRaisesRegex(RuntimeError, "explicit management kubeconfig is unavailable"):
                render.live_metallb_allocations(required=True)
        with mock.patch.object(render.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(RuntimeError, "inventory is unavailable"):
                render.live_metallb_allocations(required=True)

    def test_malformed_or_incomplete_inventories_fail_closed(self):
        malformed = [
            "not-json",
            json.dumps({"apiVersion": "v1", "kind": "ServiceList", "items": []}),
            json.dumps({"apiVersion": "v1", "kind": "List"}),
            list_json([{"apiVersion": "v1", "kind": "Service", "spec": {"type": "ClusterIP"}}]),
            json.dumps({"apiVersion": "v1", "kind": "List", "metadata": {"continue": "next"}, "items": []}),
            list_json([service(uid="")]),
            list_json([service(service_type="Unknown")]),
            list_json([service(spec={"type": "LoadBalancer", "loadBalancerIP": "not-an-ip"})]),
            list_json([service("one", spec={"type": "LoadBalancer", "loadBalancerIP": "192.168.100.210"}),
                       service("two", "other", spec={"type": "LoadBalancer", "loadBalancerIP": "192.168.100.210"})]),
            list_json([service("duplicate"), service("duplicate")]),
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:80]):
                with self.assertRaisesRegex(RuntimeError, "incomplete or invalid"):
                    self.run_inventory(raw)

    def test_empty_output_is_not_an_empty_inventory(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete or invalid"):
            self.run_inventory("")

    def test_only_exact_m2_reference_requires_live_inventory(self):
        cfg = {
            "name": "ok-m2-test",
            "type": "talos",
            "provider": "kubevirt",
            "providerProfile": {"name": "ok-infra"},
            "network": {"endpoint": "auto", "podCIDR": "auto", "serviceCIDR": "auto"},
        }
        with mock.patch.object(render, "discover_clusters", return_value=[]), \
             mock.patch.object(render, "live_metallb_allocations", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "refusing network allocation"):
                render.resolve_config(cfg, "ok-m2-test", require_live_inventory=True)

        unrelated = dict(cfg, providerProfile={"name": "ok-gpu"})
        with mock.patch.object(render, "discover_clusters", return_value=[]), \
             mock.patch.object(render, "live_metallb_allocations", return_value=None), \
             mock.patch.object(render, "resolve_talos_config", side_effect=lambda value, _path: value):
            with mock.patch("builtins.print"):
                resolved = render.resolve_config(unrelated, "ok-other")
        self.assertEqual(resolved["network"]["endpoint"], "192.168.100.200")

    def test_strict_first_create_inventory_does_not_exclude_target_namespace(self):
        cfg = {
            "name": "ok-m2-test",
            "type": "talos",
            "provider": "kubevirt",
            "providerProfile": {"name": "ok-infra"},
            "network": {"endpoint": "auto", "podCIDR": "auto", "serviceCIDR": "auto"},
        }
        allocation = {"192.168.100.200": "ok-m2-test/existing-service"}
        with mock.patch.object(render, "discover_clusters", return_value=[]), \
             mock.patch.object(render, "live_metallb_allocations", return_value=allocation) as inventory, \
             mock.patch.object(render, "resolve_talos_config", side_effect=lambda value, _path: value):
            resolved = render.resolve_config(cfg, "ok-m2-test", require_live_inventory=True)
        inventory.assert_called_once_with(exclude_cluster=None, required=True)
        self.assertEqual(resolved["network"]["endpoint"], "192.168.100.201")

    def test_render_inventory_failure_occurs_before_manifest_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stage = root / ".ok76-ok-m2-test.test"
            stage.mkdir()
            (stage / "cluster-config.yaml").write_text(
                "name: ok-m2-test\ntype: talos\nprovider: kubevirt\n"
                "providerProfile:\n  name: ok-infra\n"
                "network:\n  endpoint: auto\n  podCIDR: auto\n  serviceCIDR: auto\n",
                encoding="utf-8",
            )
            with mock.patch.object(render, "SCRIPT_DIR", root), \
                 mock.patch.object(render, "CLUSTERS_DIR", root), \
                 mock.patch.object(render, "discover_clusters", return_value=[]), \
                 mock.patch.object(render.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "kubectl")):
                with self.assertRaisesRegex(RuntimeError, "inventory is unavailable"):
                    render.cmd_render(argparse.Namespace(
                        cluster="ok-m2-test", cluster_dir=str(stage), require_live_inventory=True
                    ))
            self.assertEqual([path.name for path in stage.iterdir()], ["cluster-config.yaml"])


class RenderExternalStateTests(unittest.TestCase):
    """ok up stages under CLUSTERS_DIR (outside the checkout); render must accept
    exactly that staging directory and nothing looser (OK-228 acceptance blocker)."""

    CONFIG = ("name: ok-v101-a1\ntype: talos\nprovider: kubevirt\nproviderProfile:\n  name: ok-infra\n"
              "network:\n  endpoint: auto\n  podCIDR: auto\n  serviceCIDR: auto\n")

    def render(self, state, stage):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(render, "CLUSTERS_DIR", state), \
             mock.patch.object(render, "live_metallb_allocations", return_value={}), \
             mock.patch.object(render, "resolve_talos_config", side_effect=lambda value, _path: value), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            render.cmd_render(argparse.Namespace(cluster="ok-v101-a1", cluster_dir=str(stage), require_live_inventory=True))
        return out.getvalue(), err.getvalue()

    def test_renders_into_staging_directory_under_external_clusters_dir(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state" / "ok" / "clusters"
            stage = state / ".ok76-ok-v101-a1.FFzvxy"
            stage.mkdir(parents=True)
            (stage / "cluster-config.yaml").write_text(self.CONFIG, encoding="utf-8")
            out, _ = self.render(state, stage)
            self.assertTrue((stage / "cluster-base.yaml").is_file())
            self.assertIn(f"rendered → {stage}/", out)  # absolute: not a descendant of the checkout

    def test_rejects_unsafe_staging_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            state = base / "state" / "ok" / "clusters"
            state.mkdir(parents=True)
            target = base / "elsewhere"
            target.mkdir()
            (state / ".ok76-ok-v101-a1.link").symlink_to(target, target_is_directory=True)
            (state / "nested").mkdir()
            cases = {
                "outside CLUSTERS_DIR": base / ".ok76-ok-v101-a1.abc",
                "checkout instead of CLUSTERS_DIR": ROOT / ".ok76-ok-v101-a1.abc",
                "nested below CLUSTERS_DIR": state / "nested" / ".ok76-ok-v101-a1.abc",
                "other cluster's name": state / ".ok76-ok-other.abc",
                "not a staging name": state / "ok-v101-a1",
                "symlink": state / ".ok76-ok-v101-a1.link",
                "missing": state / ".ok76-ok-v101-a1.missing",
                "relative": Path("state/ok/clusters/.ok76-ok-v101-a1.abc"),
            }
            for label, stage in cases.items():
                if label not in ("symlink", "missing", "relative", "checkout instead of CLUSTERS_DIR"):
                    stage.mkdir(parents=True, exist_ok=True)
                with self.subTest(label):
                    with self.assertRaises(SystemExit):
                        _, err = self.render(state, stage)
            self.assertEqual(sorted(p.name for p in target.iterdir()), [])

    def test_real_make_new_publishes_into_external_state(self):
        """The acceptance failure end to end: real make new, new-cluster.sh and
        render.py with ok up's assignments; only kubectl is faked."""
        if not os.environ.get("OK_LINUX_PATH"):
            self.skipTest("needs OK_LINUX_PATH (pinned ok-linux) for the real renderer")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            state, bin_dir = base / "state" / "ok" / "clusters", base / "bin"
            state.mkdir(parents=True)
            bin_dir.mkdir()
            kubectl = bin_dir / "kubectl"
            kubectl.write_text("#!/bin/sh\ncase \"$*\" in *\" svc \"*) "
                               "echo '{\"apiVersion\":\"v1\",\"kind\":\"List\",\"metadata\":{},\"items\":[]}';; esac\nexit 0\n")
            kubectl.chmod(0o755)
            management = base / "management.yaml"
            management.write_text("fixture only\n")
            before = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True).stdout
            result = subprocess.run(
                ["make", "-s", "-C", str(ROOT), "new", "CLUSTER=ok-v101-a1", "TYPE=talos", "PROVIDER=kubevirt", "HA=false",
                 "WORKERS=1", "K8S_VERSION=v1.34.1", "TALOS_VERSION=v1.9.6", "ARCHITECTURE=amd64",
                 "SCHEDULING_PROFILE=ok-infra", "NODE_SELECTOR=ok-infra", "REGISTRY_TRUST=false", "START_IP=",
                 "OK76_REQUIRE_LIVE_METALLB_INVENTORY=true", f"TALOS_INFRA_KUBECONFIG={management}",
                 f"OK_LINUX_PATH={os.environ['OK_LINUX_PATH']}", f"CLUSTERS_DIR={state}"],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "HOME": str(base), "PATH": f"{bin_dir}:{os.environ['PATH']}"},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            published = state / "ok-v101-a1"
            for name in ("cluster-config.yaml", "cluster-base.yaml"):
                self.assertTrue((published / name).is_file(), name)
            self.assertEqual(sorted(p.name for p in state.iterdir()), ["ok-v101-a1"])  # no staging left
            after = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True).stdout
            self.assertEqual(after, before)  # nothing written into the checkout


class BootstrapStateDirectoryTests(unittest.TestCase):
    """make bootstrap's Golden preflight must read the scaffold from CLUSTERS_DIR."""

    def test_golden_preflight_reads_the_state_directory(self):
        state = "/state-home/ok/clusters"
        result = subprocess.run(
            ["make", "-n", "-s", "-C", str(ROOT), "talos-golden-preflight", "CLUSTER=demo",
             f"CLUSTERS_DIR={state}", "TALOS_INFRA_KUBECONFIG=/k/management.yaml"],
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'--cluster-dir "{state}/demo"', result.stdout)
        self.assertIn(f'"{state}/demo/cluster-config.yaml"', result.stdout)
        self.assertNotIn(f"{ROOT}/demo", result.stdout)


class DiscoverClustersTests(unittest.TestCase):
    """Allocation sees committed/pre-v1.0.1 clusters and the external state."""

    def write(self, root, name, endpoint):
        (root / name).mkdir(parents=True)
        (root / name / "cluster-config.yaml").write_text(
            f"network:\n  endpoint: {endpoint}\n  podCIDR: auto\n  serviceCIDR: auto\n", encoding="utf-8")

    def test_scans_checkout_and_state_and_refuses_duplicate_names(self):
        with tempfile.TemporaryDirectory() as temp:
            checkout, state = Path(temp) / "checkout", Path(temp) / "state"
            self.write(checkout, "ok-ai", "192.168.100.10")
            self.write(state, "team-a", "192.168.100.11")
            with mock.patch.object(render, "SCRIPT_DIR", checkout), mock.patch.object(render, "CLUSTERS_DIR", state):
                clusters = render.discover_clusters()
                self.assertEqual(sorted(c["name"] for c in clusters), ["ok-ai", "team-a"])
                self.assertEqual(render.allocated_ips(clusters), {"192.168.100.10", "192.168.100.11"})
                self.write(state, "ok-ai", "192.168.100.12")
                with self.assertRaisesRegex(SystemExit, "exists in both"):
                    render.discover_clusters()
            with mock.patch.object(render, "SCRIPT_DIR", checkout), \
                 mock.patch.object(render, "CLUSTERS_DIR", Path(temp) / "not-created-yet"):
                self.assertEqual([c["name"] for c in render.discover_clusters()], ["ok-ai"])


class NewClusterPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.bin = self.root / "bin"
        self.repo.mkdir()
        self.bin.mkdir()
        shutil.copy2(ROOT / "new-cluster.sh", self.repo / "new-cluster.sh")
        self.kubeconfig = self.root / "management.kubeconfig"
        self.kubeconfig.write_text("fixture only\n", encoding="utf-8")
        self.kubectl_log = self.root / "kubectl-argv.txt"
        self.python_log = self.root / "python-argv.txt"
        self._write_executable(self.bin / "python3", """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_PYTHON_LOG"
case "$*" in
  *validate-workload-user-namespaces-env*) exit 0 ;;
  *next-ip*)
    if [ "${FAKE_NEXT_IP_FAIL:-0}" = "1" ]; then echo 'inventory unavailable' >&2; exit 1; fi
    echo 192.168.100.200; exit 0 ;;
  *render*)
    if [ "${FAKE_RENDER_FAIL:-0}" = "1" ]; then echo 'inventory unavailable during render' >&2; exit 1; fi
    exit 0 ;;
esac
exit 99
""")

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _write_executable(path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def invoke(self, kubectl_mode=None, include_kubectl=True, kubeconfig=None, inventory_fail=False,
               render_fail=False, missing_okb=False, okb_kubeconfig=None,
               strict=True, profile="ok-infra", clusters_dir=None):
        if include_kubectl:
            mode = kubectl_mode or "empty"
            self._write_executable(self.bin / "kubectl", f"""#!/bin/sh
printf '%s\\n' "$@" > "$FAKE_KUBECTL_LOG"
case "{mode}" in
  empty) exit 0 ;;
  present) echo cluster.cluster.x-k8s.io/ok-m2-test; exit 0 ;;
  unexpected) echo 'forbidden (but exit zero)'; exit 0 ;;
  forbidden) echo 'forbidden' >&2; exit 1 ;;
  tls) echo 'x509: certificate verify failed' >&2; exit 1 ;;
  timeout) echo 'request timed out' >&2; exit 124 ;;
esac
""")
        else:
            (self.bin / "kubectl").unlink(missing_ok=True)
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.root),
            "CLUSTER": "ok-m2-test",
            "TYPE": "talos",
            "PROVIDER": "kubevirt",
            "SCHEDULING_PROFILE": profile,
            "OK76_REQUIRE_LIVE_METALLB_INVENTORY": "true" if strict else "false",
            "INFRA_KUBECONFIG": str(kubeconfig or self.kubeconfig),
            "OKB_KUBECONFIG": str(okb_kubeconfig or kubeconfig or self.kubeconfig),
            "FAKE_KUBECTL_LOG": str(self.kubectl_log),
            "FAKE_PYTHON_LOG": str(self.python_log),
            "FAKE_NEXT_IP_FAIL": "1" if inventory_fail else "0",
            "FAKE_RENDER_FAIL": "1" if render_fail else "0",
        }
        if missing_okb:
            env.pop("OKB_KUBECONFIG")
        if clusters_dir is not None:
            env["CLUSTERS_DIR"] = str(clusters_dir)
        return subprocess.run(["/bin/bash", str(self.repo / "new-cluster.sh")],
                              cwd=self.repo, env=env, capture_output=True, text=True)

    def assert_no_scaffold(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.repo / "ok-m2-test").exists())
        self.assertEqual(list(self.repo.glob(".ok76-ok-m2-test.*")), [])

    def test_missing_kubectl_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke(include_kubectl=False))

    def test_missing_kubeconfig_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke(kubeconfig=self.root / "missing.kubeconfig"))

    def test_missing_or_mismatched_inventory_kubeconfig_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke(missing_okb=True))
        self.assert_no_scaffold(self.invoke(okb_kubeconfig=self.root / "different.kubeconfig"))

    def test_existing_cluster_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke("present"))

    def test_ambiguous_zero_exit_output_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke("unexpected"))

    def test_auth_tls_and_timeout_failures_fail_before_scaffold(self):
        for mode in ("forbidden", "tls", "timeout"):
            with self.subTest(mode=mode):
                self.assert_no_scaffold(self.invoke(mode))

    def test_live_allocation_inventory_failure_fails_before_scaffold(self):
        self.assert_no_scaffold(self.invoke("empty", inventory_fail=True))

    def test_render_inventory_failure_discards_unpublished_staging_directory(self):
        self.assert_no_scaffold(self.invoke("empty", render_fail=True))

    def test_strict_inventory_mode_rejects_non_reference_profile(self):
        self.assert_no_scaffold(self.invoke("empty", profile="ok-gpu"))

    def test_stale_stage_is_preserved_and_blocks_implicit_retry(self):
        stale = self.repo / ".ok76-ok-m2-test.previous"
        stale.mkdir()
        (stale / "cluster-config.yaml").write_text("diagnostic fixture\n", encoding="utf-8")
        result = self.invoke("empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((stale / "cluster-config.yaml").is_file())
        self.assertFalse((self.repo / "ok-m2-test").exists())

    def test_confirmed_not_found_allows_existing_successful_scaffold_path(self):
        result = self.invoke("empty")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.repo / "ok-m2-test" / "cluster-config.yaml").is_file())
        argv = self.kubectl_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(argv, ["--kubeconfig", str(self.kubeconfig), "get", "clusters.cluster.x-k8s.io",
                                "ok-m2-test", "-n", "ok-m2-test", "--ignore-not-found", "-o", "name"])
        python_calls = self.python_log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(any(call.endswith("render.py next-ip --cluster ok-m2-test --require-live-inventory") for call in python_calls))
        render_call = next(call for call in python_calls if "render.py render --cluster ok-m2-test" in call)
        self.assertIn("--cluster-dir", render_call)
        self.assertIn("--require-live-inventory", render_call)
        self.assertTrue((self.repo / "ok-m2-test" / "cluster-config.yaml").is_file())
        self.assertEqual(list(self.repo.glob(".ok76-ok-m2-test.*")), [])

    def test_clusters_dir_publishes_scaffold_outside_checkout(self):
        state = self.root / "state" / "ok" / "clusters"
        state.mkdir(parents=True)
        result = self.invoke("empty", clusters_dir=state)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((state / "ok-m2-test" / "cluster-config.yaml").is_file())
        self.assertFalse((self.repo / "ok-m2-test").exists())
        self.assertEqual(list(state.glob(".ok76-ok-m2-test.*")) + list(self.repo.glob(".ok76-*")), [])
        render_call = next(call for call in self.python_log.read_text(encoding="utf-8").splitlines()
                           if "render.py render --cluster ok-m2-test" in call)
        self.assertIn(f"--cluster-dir {state}/.ok76-ok-m2-test.", render_call)

    def test_clusters_dir_refuses_name_in_checkout_and_stale_state_stage(self):
        state = self.root / "state"
        state.mkdir()
        legacy = self.repo / "ok-m2-test"
        legacy.mkdir()
        (legacy / "cluster-config.yaml").write_text("pre-v1.0.1 evidence\n", encoding="utf-8")
        result = self.invoke("empty", clusters_dir=state)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists in the checkout", result.stdout + result.stderr)
        self.assertEqual((legacy / "cluster-config.yaml").read_text(encoding="utf-8"), "pre-v1.0.1 evidence\n")
        self.assertEqual(list(state.iterdir()), [])
        legacy.joinpath("cluster-config.yaml").unlink()
        legacy.rmdir()
        stale = state / ".ok76-ok-m2-test.previous"
        stale.mkdir()
        self.assertNotEqual(self.invoke("empty", clusters_dir=state).returncode, 0)
        self.assertEqual(sorted(path.name for path in state.iterdir()), [stale.name])

    def test_unrelated_talos_profile_keeps_legacy_inventory_mode(self):
        result = self.invoke("empty", strict=False, profile="ok-gpu")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        python_calls = self.python_log.read_text(encoding="utf-8").splitlines()
        self.assertTrue(any(call.endswith("render.py next-ip --cluster ok-m2-test") for call in python_calls))
        self.assertFalse(any(call.endswith("render.py next-ip --cluster ok-m2-test --require-live-inventory") for call in python_calls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
