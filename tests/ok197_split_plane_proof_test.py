#!/usr/bin/env python3
"""Offline tests for the disposable OK-197 split-plane proof helper."""

from __future__ import annotations

import copy
import io
import inspect
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROOF_PATH = ROOT / "tests" / "live" / "ok197_split_plane_proof.py"
FIXTURE = ROOT / "tests" / "fixtures" / "ok130-talos" / "cluster-config.yaml"
OK_LINUX = Path(os.environ.get(
    "OK_LINUX_PATH", str(ROOT.parents[3] / "ok-linux")
)).resolve()
sys.path.insert(0, str(ROOT))


def load_module():
    spec = importlib.util.spec_from_file_location("ok197_split_plane_proof", PROOF_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


proof = load_module()


class StatefulCreateProof(proof.Proof):
    """Small fake API around the real create orchestrator and renderer."""

    def __init__(self, cluster):
        self.c = cluster
        self.configs = {"management": "/configs/management", "provider": "/configs/provider"}
        self.state = {
            "cluster": cluster,
            "planes": {"management": "management-uid", "provider": "provider-uid"},
            "protected": {"captured": True},
            "resources": [],
        }
        self.objects = {"management": {}, "provider": {}}
        self.make_calls = []
        self.ready_configs = []
        self.e = type("EvidenceStub", (), {
            "emit": lambda _self, _message: None,
            "check": lambda _self, _message: None,
        })()
        self.env = dict(os.environ)
        self.fds = ()

    @staticmethod
    def key(obj):
        metadata = obj["metadata"]
        return obj["kind"], metadata.get("namespace"), metadata["name"]

    def save(self):
        pass

    def bind_planes(self):
        return dict(self.state["planes"])

    def obj(self, plane, resource, name=None, namespace=None):
        if plane == "provider" and resource == "volumesnapshots" and namespace == "ok-images":
            return {"items": [
                {"metadata": {"name": "owned-snapshot", "uid": "snapshot-owned-uid",
                               "labels": {"cdi.kubevirt.io/OwnedByUID": "dv-owned-uid"}}},
                {"metadata": {"name": "foreign-snapshot", "uid": "snapshot-foreign-uid",
                               "labels": {"cdi.kubevirt.io/OwnedByUID": "dv-foreign-uid"}}},
            ]}
        aliases = {
            "namespace": "Namespace", "role": "Role", "rolebinding": "RoleBinding",
            "clusterrole": "ClusterRole", "clusterrolebinding": "ClusterRoleBinding",
            "serviceaccount": "ServiceAccount", "secret": "Secret",
        }
        return self.objects[plane].get((aliases.get(resource.lower(), resource), namespace, name))

    def ledger(self, plane="management"):
        del plane
        return None

    def snapshot(self, cluster):
        if cluster != self.c:
            return {"captured": True}
        return {
            "provider/pv": [["owned-pv", "pv-owned-uid"]],
            "provider/datavolumes": [["owned-dv", "dv-owned-uid"]],
        }

    def k(self, plane, args, **_kwargs):
        if args[:3] == ["get", "clusters.cluster.x-k8s.io", "-A"]:
            return subprocess.CompletedProcess(args, 0, json.dumps({"items": [
                {"metadata": {"name": proof.PROTECTED, "uid": "protected-uid"}}
            ]}), "")
        if args[:2] == ["get", "secret"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected fake kubectl call on {plane}: {args}")

    def create_object(self, plane, obj):
        value = copy.deepcopy(obj)
        value.setdefault("metadata", {})["uid"] = "uid-" + str(len(self.state["resources"]) + 1)
        key = self.key(value)
        if key in self.objects[plane]:
            raise AssertionError(f"duplicate object {plane} {key}")
        self.objects[plane][key] = value
        metadata = value["metadata"]
        self.state["resources"].append({
            "plane": plane, "apiVersion": value["apiVersion"], "kind": value["kind"],
            "name": metadata["name"], "namespace": metadata.get("namespace"),
            "uid": metadata["uid"],
        })

    def make(self, target, *, management=None, provider=None, allowed=(0,), output=True, **variables):
        del allowed, output
        self.make_calls.append({
            "target": target,
            "management": management or self.configs["management"],
            "provider": provider or self.configs["provider"],
            "variables": dict(variables),
        })
        if target == "new":
            import render
            from profile_resolvers.talos import resolve_talos_config

            raw = copy.deepcopy(yaml.safe_load(FIXTURE.read_text()))
            raw["name"] = self.c
            raw["infraClusterSecretRef"] = {
                "name": "external-infra-kubeconfig-" + self.c, "namespace": self.c,
            }
            render.render_cluster(self.c, ROOT / self.c, resolve_talos_config(raw, OK_LINUX))
        return subprocess.CompletedProcess([target], 0, "", "")

    def run(self, args, **_kwargs):
        if args[1:3] != ["render.py", "projection"]:
            raise AssertionError(f"unexpected fake process: {args}")
        import render
        from types import SimpleNamespace

        output = Path(args[args.index("--output") + 1])
        old = render.CLUSTERS_DIR
        try:
            render.CLUSTERS_DIR = ROOT
            render.cmd_projection(SimpleNamespace(
                cluster=self.c,
                intent_revision=args[args.index("--intent-revision") + 1],
                output=str(output),
            ))
        finally:
            render.CLUSTERS_DIR = old
        return subprocess.CompletedProcess(args, 0, "", "")

    def credential(self, plane, account):
        if (plane, account) != ("provider", "capk"):
            raise AssertionError("create requested an unexpected credential")
        payload = __import__("base64").urlsafe_b64encode(
            json.dumps({"exp": int(time.time()) + 14400}).encode()
        ).decode().rstrip("=")
        self.provider_token = "e30." + payload + ".signature"
        return {
            "apiVersion": "v1", "kind": "Config", "current-context": "proof",
            "clusters": [{"name": "proof", "cluster": {
                "server": "https://provider.invalid", "certificate-authority-data": "Y2E=",
            }}],
            "users": [{"name": "proof", "user": {"token": self.provider_token}}],
            "contexts": [{"name": "proof", "context": {
                "cluster": "proof", "user": "proof", "namespace": self.c,
            }}],
        }

    def ready(self, config):
        self.ready_configs.append(copy.deepcopy(config))


class SplitPlaneProofTests(unittest.TestCase):
    def setUp(self):
        self.no_process = mock.patch.object(
            proof.subprocess, "run", side_effect=AssertionError("offline test opened a subprocess")
        )
        self.no_process.start()
        self.addCleanup(self.no_process.stop)

    def test_guard_rejects_every_unsafe_precondition_before_accepting_fresh_name(self):
        invalid = [
            (("bad", "management", "provider", set()), "CLUSTER must match"),
            (("ok197-split-abcd", "management", "provider", {"ok197-split-abcd"}), "already exists"),
            (("ok197-split-abcd", "same", "same", set()), "plane UIDs must differ"),
            (("ok197-split-abcd", "", "provider", set()), "plane UIDs must differ"),
            (("ok-cli-mvp-3", "management", "provider", set()), "protected cluster"),
        ]
        for arguments, message in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(proof.ProofError, message) as caught:
                    proof.guard(*arguments)
                print(f"PASS guard rejected {arguments[0]}: {caught.exception}")
        with self.assertRaisesRegex(proof.ProofError, "OK197_SPLIT_CONFIRM=yes required") as caught:
            proof.guard("ok197-split-abcd", "management", "provider", set(), True, "no")
        print(f"PASS guard rejected missing confirmation: {caught.exception}")
        proof.guard("ok197-split-abcd", "management", "provider", set())
        proof.guard("ok197-split-abcd", "management", "provider", set(), True, "yes")
        print("PASS guard accepted fresh split-plane name and explicit confirmation")

    def test_real_talos_render_splits_every_object_to_its_owning_plane(self):
        import render
        from profile_resolvers.talos import resolve_talos_config

        cluster = "ok197-split-test"
        raw = yaml.safe_load(FIXTURE.read_text())
        raw = copy.deepcopy(raw)
        raw["name"] = cluster
        raw["infraClusterSecretRef"] = {
            "name": "external-infra-kubeconfig-" + cluster, "namespace": cluster,
        }
        resolved = resolve_talos_config(raw, OK_LINUX)
        with tempfile.TemporaryDirectory(prefix=".ok197-split-proof-", dir=ROOT) as temporary:
            cluster_dir = Path(temporary) / cluster
            render.render_cluster(cluster, cluster_dir, resolved)
            documents = [
                document
                for document in yaml.safe_load_all((cluster_dir / "cluster-base.yaml").read_text())
                if document
            ]
            split = proof.split_documents(documents, cluster)

        for plane in ("management", "provider"):
            for document in split[plane]:
                metadata = document["metadata"]
                print(
                    f"SPLIT {plane} {document['apiVersion']} {document['kind']} "
                    f"{metadata.get('namespace', '-')}/{metadata['name']}"
                )

        management_kinds = [document["kind"] for document in split["management"]]
        provider_kinds = [document["kind"] for document in split["provider"]]
        self.assertEqual(management_kinds.count("Namespace"), 1)
        self.assertEqual(provider_kinds.count("Namespace"), 1)
        self.assertEqual(
            management_kinds,
            ["Namespace", "Cluster", "KubevirtCluster", "TalosControlPlane",
             "TalosConfigTemplate", "MachineDeployment", "KubevirtMachineTemplate",
             "KubevirtMachineTemplate"],
        )
        self.assertEqual(provider_kinds, ["Namespace", "Role", "RoleBinding"])
        self.assertEqual(
            [document["metadata"]["namespace"] for document in split["provider"][1:]],
            ["ok-images", "ok-images"],
        )

    def test_split_routes_provider_runtime_objects_and_rejects_unknown_input(self):
        cluster = "ok197-split-test"
        namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": cluster}}
        capi = {"apiVersion": "cluster.x-k8s.io/v1beta1", "kind": "Cluster",
                "metadata": {"name": cluster, "namespace": cluster}}
        provider = [
            {"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine",
             "metadata": {"name": "vm", "namespace": cluster}},
            {"apiVersion": "cdi.kubevirt.io/v1beta1", "kind": "DataVolume",
             "metadata": {"name": "disk", "namespace": cluster}},
        ]
        split = proof.split_documents([namespace, capi, *provider], cluster)
        self.assertEqual([item["kind"] for item in split["provider"]],
                         ["Namespace", "VirtualMachine", "DataVolume"])
        with self.assertRaisesRegex(proof.ProofError, "unrecognized split object ConfigMap stray"):
            proof.split_documents([namespace, capi, {
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "stray", "namespace": cluster},
            }], cluster)

    def test_trace_redacts_hosts_and_asserts_exact_plane_identity_reads(self):
        management = proof.trace_requests(
            "debug GET https://mgmt.invalid/api/v1/namespaces/kube-system 200\nignored token=secret",
            "management",
        )
        provider = proof.trace_requests(
            'trace verb="GET" url="https://infra.invalid/api/v1/namespaces/kube-system" status="200"',
            "provider",
        )
        requests = management + provider
        self.assertEqual(requests, [
            {"plane": "management", "method": "GET", "path": "/api/v1/namespaces/kube-system", "status": 200},
            {"plane": "provider", "method": "GET", "path": "/api/v1/namespaces/kube-system", "status": 200},
        ])
        self.assertNotIn("mgmt.invalid", repr(requests))
        self.assertNotIn("infra.invalid", repr(requests))
        proof.assert_trace(requests)

    def test_denied_provider_trace_is_403_and_contains_no_mutation(self):
        requests = proof.trace_requests(
            "GET https://mgmt.invalid/api/v1/namespaces/kube-system 200", "management"
        ) + proof.trace_requests(
            "GET https://infra.invalid/api/v1/namespaces/kube-system 403", "provider"
        )
        proof.assert_trace(requests, denied=True)
        with self.assertRaisesRegex(proof.ProofError, "exactly one"):
            proof.assert_trace(requests[:1], denied=True)
        with self.assertRaisesRegex(proof.ProofError, "exactly one"):
            proof.assert_trace(requests + [{
                "plane": "provider", "method": "GET",
                "path": "/api/v1/namespaces/kube-system/finalize", "status": 403,
            }], denied=True)
        with self.assertRaisesRegex(proof.ProofError, "mutated the API"):
            proof.assert_trace(requests + [{
                "plane": "management", "method": "DELETE",
                "path": "/apis/cluster.x-k8s.io/v1beta1/namespaces/test/clusters/test",
                "status": 200,
            }], denied=True)
        with self.assertRaisesRegex(proof.ProofError, "mutation of protected cluster"):
            proof.assert_trace(requests + [{
                "plane": "management", "method": "PATCH",
                "path": "/apis/cluster.x-k8s.io/v1beta2/namespaces/ok-cli-mvp-3/clusters/ok-cli-mvp-3",
                "status": 200,
            }], denied=False)
        incomplete = proof.trace_requests(
            "DELETE https://infra.invalid/api/v1/namespaces/guest transport closed", "provider"
        )
        self.assertEqual(incomplete, [])
        with self.assertRaisesRegex(proof.ProofError, "exactly one"):
            proof.assert_trace(incomplete, denied=True)

    def test_create_orchestrates_real_render_into_bounded_split_plane_writes(self):
        cluster = "ok197-split-unit"
        cluster_dir = ROOT / cluster
        self.assertFalse(cluster_dir.exists())
        instance = StatefulCreateProof(cluster)
        try:
            with mock.patch.dict(os.environ, {"OK197_SPLIT_CONFIRM": "yes"}, clear=False):
                instance.create()

            calls = {call["target"]: call for call in instance.make_calls}
            self.assertEqual(
                [call["target"] for call in instance.make_calls],
                ["install-teardown-ledger", "install-teardown-provider-reader", "new", "render"],
            )
            self.assertEqual(calls["install-teardown-ledger"]["management"], "/configs/management")
            self.assertEqual(calls["install-teardown-provider-reader"]["provider"], "/configs/provider")
            self.assertEqual(calls["new"]["management"], "/configs/provider")
            self.assertEqual(calls["render"]["management"], "/configs/provider")

            management = list(instance.objects["management"].values())
            provider = list(instance.objects["provider"].values())
            secret = next(item for item in management if item["kind"] == "Secret")
            credential = yaml.safe_load(__import__("base64").b64decode(secret["data"]["kubeconfig"]))
            self.assertTrue(secret["immutable"])
            self.assertEqual(secret["metadata"]["namespace"], cluster)
            self.assertEqual(credential["users"][0]["user"], {"token": instance.provider_token})
            self.assertEqual(credential["contexts"][0]["context"]["namespace"], cluster)

            provider_role = next(item for item in provider if
                item["kind"] == "Role" and item["metadata"].get("namespace") == cluster
                and item["metadata"]["name"].startswith("ok147-"))
            self.assertEqual(provider_role["rules"], [
                {"apiGroups": [""], "resources": ["secrets", "services"],
                 "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]},
                {"apiGroups": ["cdi.kubevirt.io"], "resources": ["datavolumes"],
                 "verbs": ["get", "list", "watch"]},
                {"apiGroups": ["kubevirt.io"], "resources": ["virtualmachineinstances"],
                 "verbs": ["delete", "get"]},
                {"apiGroups": ["kubevirt.io"], "resources": ["virtualmachines"],
                 "verbs": ["create", "delete", "get", "patch", "update"]},
            ])
            self.assertEqual(instance.state["storage_authority"], {
                "volumes": ["owned-pv"], "snapshots": ["owned-snapshot"],
            })
            management_teardown = next(item for item in management if
                item["metadata"]["name"] == cluster + "-management-0")
            self.assertEqual(management_teardown["kind"], "ClusterRole")
            self.assertEqual(management_teardown["rules"], [{
                "apiGroups": ["cluster.x-k8s.io"], "resources": ["clusters"],
                "verbs": ["get", "delete"], "resourceNames": [cluster],
            }])
            storage_rules = [
                rule
                for item in provider
                if item["kind"] in {"Role", "ClusterRole"}
                and item["metadata"]["name"].startswith(cluster + "-provider-")
                for rule in item.get("rules", [])
                if "delete" in rule["verbs"] and rule["resources"] in (
                    ["persistentvolumes"], ["volumes"], ["volumesnapshots"]
                )
            ]
            self.assertEqual(len(storage_rules), 3)
            self.assertTrue(all(rule["resourceNames"] in (["owned-pv"], ["owned-snapshot"])
                                for rule in storage_rules))
            self.assertNotIn("foreign-snapshot", repr(storage_rules))
            candidate_reads = next(item for item in provider if
                item["metadata"]["name"] == cluster + "-provider-0")["rules"]
            self.assertEqual(candidate_reads, [
                {"apiGroups": ["cdi.kubevirt.io"], "resources": ["datavolumes"],
                 "verbs": ["get", "list"]},
                {"apiGroups": [""], "resources": ["persistentvolumeclaims"],
                 "verbs": ["get", "list"]},
            ])
            self.assertIn("Cluster", {item["kind"] for item in management})
            self.assertNotIn("Cluster", {item["kind"] for item in provider})
            self.assertEqual(sum(item["kind"] == "Namespace" for item in management), 2)
            self.assertEqual(sum(item["kind"] == "Namespace" for item in provider), 2)
            self.assertTrue(instance.state["created"])
            self.assertGreater(instance.state["capk_expires_at"], time.time() + 1800)
            self.assertLessEqual(instance.state["capk_expires_at"], time.time() + 14460)
            self.assertEqual(instance.state["provider_namespace_uid"],
                             instance.objects["provider"][("Namespace", None, cluster)]["metadata"]["uid"])
            self.assertEqual(len(instance.ready_configs), 1)
            self.assertEqual(instance.ready_configs[0]["infraClusterSecretRef"]["namespace"], cluster)
        finally:
            if cluster_dir.exists():
                shutil.rmtree(cluster_dir)


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        no_process = mock.patch.object(
            proof.subprocess, "run", side_effect=AssertionError("offline test opened a subprocess"))
        no_process.start()
        self.addCleanup(no_process.stop)

    def teardown_instance(self, cluster_present=True, terminating=False):
        instance = proof.Proof.__new__(proof.Proof)
        instance.c = "ok197-split-test"
        instance.state = {"created": True, "capk_expires_at": time.time() - 1,
                          "resources": [{"plane": "management", "kind": "Cluster",
                                         "name": instance.c, "namespace": instance.c, "uid": "recorded"}]}
        instance.need_state = mock.Mock()
        instance.ledger = mock.Mock(return_value=None)
        def obj(plane, resource, name=None, namespace=None):
            if plane == "management" and resource == "clusters.cluster.x-k8s.io":
                return {"metadata": {"uid": "recorded"}} if cluster_present else None
            if plane == "provider" and resource == "namespace":
                return {"metadata": {"deletionTimestamp": "now"}} if terminating else None
            raise AssertionError((plane, resource, name, namespace))
        instance.obj = mock.Mock(side_effect=obj)
        instance.refresh_teardown_roles = mock.Mock()
        instance.auth = mock.Mock(side_effect=RuntimeError("reached auth"))
        return instance

    def test_b1_floor_enforced_while_recorded_cluster_exists(self):
        instance = self.teardown_instance()
        with self.assertRaisesRegex(proof.ProofError, "30 minutes"):
            instance.teardown()
        instance.auth.assert_not_called()
        instance.state["capk_expires_at"] = time.time() + 2000
        with self.assertRaisesRegex(RuntimeError, "reached auth"):
            instance.teardown()

    def test_b1_expired_capk_allows_provider_cleanup_after_cluster_gone(self):
        instance = self.teardown_instance(cluster_present=False)
        with self.assertRaisesRegex(RuntimeError, "reached auth"):
            instance.teardown()
        instance.auth.assert_called_once_with(after=True)

    def test_b1_replacement_cluster_refused(self):
        instance = self.teardown_instance()
        instance.obj.side_effect = None
        instance.obj.return_value = {"metadata": {"uid": "replacement"}}
        with self.assertRaisesRegex(proof.ProofError, "Cluster UID changed"):
            instance.teardown()
        instance.auth.assert_not_called()

    def test_s2_terminating_namespace_uses_after_auth(self):
        instance = self.teardown_instance(cluster_present=False, terminating=True)
        instance.state["capk_expires_at"] = time.time() + 4000
        with self.assertRaisesRegex(RuntimeError, "reached auth"):
            instance.teardown()
        instance.auth.assert_called_once_with(after=True)

    def test_b1_capk_token_requests_four_hours(self):
        instance = proof.Proof.__new__(proof.Proof)
        instance.c = "ok197-split-test"
        calls = []
        def k(plane, args):
            calls.append((plane, args))
            value = "bounded-token" if args[0] == "create" else json.dumps({
                "server": "https://provider.invalid", "certificate-authority-data": "Y2E="})
            return subprocess.CompletedProcess(args, 0, value, "")
        instance.k = k
        instance.credential("provider", "capk")
        self.assertIn("--duration=4h", calls[0][1])

    def test_new_allocates_endpoint_against_provider_plane(self):
        source = PROOF_PATH.read_text()
        self.assertIn('self.make("new", management=self.configs["provider"]', source)
        instance = proof.Proof.__new__(proof.Proof)
        instance.c = "ok197-split-test"
        instance.configs = {"management": "/configs/management", "provider": "/configs/provider"}
        instance.run = mock.Mock()
        instance.make("new", management=instance.configs["provider"], TYPE="talos")
        argv = instance.run.call_args.args[0]
        self.assertIn("TALOS_INFRA_KUBECONFIG=/configs/provider", argv)

    def test_b1_create_rejects_short_or_unbounded_issuance_and_short_post_ready_lifetime(self):
        for remaining, after_ready, message in [(3600, None, "210-241"),
                                                 (18000, None, "210-241"),
                                                 (14400, 1700, "less than 30 minutes")]:
            with self.subTest(remaining=remaining, after_ready=after_ready):
                instance = StatefulCreateProof("ok197-split-ttl1")
                cluster_dir = ROOT / instance.c
                self.assertFalse(cluster_dir.exists())
                original_credential = instance.credential
                def credential(plane, account):
                    result = original_credential(plane, account)
                    payload = __import__("base64").urlsafe_b64encode(
                        json.dumps({"exp": int(time.time()) + remaining}).encode()).decode().rstrip("=")
                    result["users"][0]["user"]["token"] = "e30." + payload + ".signature"
                    return result
                instance.credential = credential
                if after_ready is not None:
                    instance.ready = lambda _config: instance.state.update(
                        capk_expires_at=time.time() + after_ready)
                try:
                    with mock.patch.dict(os.environ, {"OK197_SPLIT_CONFIRM": "yes"}):
                        with self.assertRaisesRegex(proof.ProofError, message):
                            instance.create()
                    if after_ready is None:
                        self.assertFalse(instance.state.get("created"))
                finally:
                    if cluster_dir.exists():
                        shutil.rmtree(cluster_dir)

    def test_s3_snapshot_and_secret_create_do_not_fetch_secret_contents(self):
        instance = proof.Proof.__new__(proof.Proof)
        instance.c = "ok197-split-test"
        instance.state = {"resources": []}
        instance.save = mock.Mock()
        def obj(plane, resource, name=None, namespace=None):
            self.assertNotIn(resource.lower(), ("secret", "secrets"))
            return None if name else {"items": []}
        instance.obj = obj
        calls = []
        def k(plane, args, **kwargs):
            calls.append(args)
            self.assertFalse(args[0] == "get" and args[1] in ("secret", "secrets"),
                             "get secrets with -o still fetches full contents")
            document = json.loads(kwargs["data"])
            document["metadata"]["uid"] = "created"
            return subprocess.CompletedProcess(args, 0, json.dumps(document), "")
        instance.k = k
        with self.subTest(operation="snapshot"):
            instance.snapshot(proof.PROTECTED)
        with self.subTest(operation="create_secret"):
            instance.create_object("management", {"apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "new", "namespace": instance.c}, "data": {}})
            self.assertEqual([args[0] for args in calls], ["create"])
        # Cover both sensitive call sites even if a future refactor bypasses this fake.
        for method in (proof.Proof.snapshot, proof.Proof.create_object):
            self.assertNotRegex(inspect.getsource(method), r'\["get", "secrets?"')

    def test_s4_evidence_redacts_each_path_and_ipv6(self):
        samples = [str(proof.ROOT), "ok197-kubectl-abcd/kubectl", "/tmp", "/tmp/", "/mnt", "/home", "/tmp/private/file",
                   "/tmp:", "/mnt;", "/home.", "/mnt/private/file", "/home/operator/private", "2001:db8::1234",
                   "::", "::1", "fe80::1%eth0", "::ffff:192.0.2.1", "2001:db8::1.", "2001:db8::1:"]
        for value in samples:
            with self.subTest(value=value):
                evidence = proof.Evidence.__new__(proof.Evidence)
                evidence.log = io.StringIO()
                with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    evidence.emit("failure at " + value)
                self.assertNotIn(value, evidence.log.getvalue())
                if ":" in value and not value.startswith("/"):
                    self.assertIn("failure at <ip>", evidence.log.getvalue())
                self.assertEqual(stdout.getvalue(), evidence.log.getvalue())


class MemoryCredentialTransportTests(unittest.TestCase):
    def test_trace_wrapper_keeps_nested_child_credentials_memory_only(self):
        tokens = ["management-memory-token", "provider-memory-token"]

        def credential(plane, _account):
            token = tokens[0] if plane == "management" else tokens[1]
            return {
                "apiVersion": "v1", "kind": "Config", "current-context": "proof",
                "clusters": [{"name": "proof", "cluster": {
                    "server": "https://example.invalid",
                    "certificate-authority-data": "Y2E=",
                }}],
                "users": [{"name": "proof", "user": {"token": token}}],
                "contexts": [{"name": "proof", "context": {
                    "cluster": "proof", "user": "proof",
                }}],
            }

        with tempfile.TemporaryDirectory(prefix="ok197-memory-test-") as temporary:
            directory = Path(temporary)
            fake = directory / "real-kubectl"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys,yaml\n"
                "args=sys.argv[1:]\n"
                "path=args[args.index('--kubeconfig')+1]\n"
                "doc=yaml.safe_load(pathlib.Path(path).read_text())\n"
                "assert doc['users'][0]['user']['token'].endswith('memory-token')\n"
                "print('GET https://private.invalid/api/v1/namespaces/kube-system 200', file=sys.stderr)\n"
                "print('credential-readable')\n"
            )
            fake.chmod(0o700)
            instance = proof.Proof.__new__(proof.Proof)
            instance.e = type("EvidenceStub", (), {"directory": directory})()
            instance.env = dict(os.environ)
            instance.fds = ()
            instance.credential = credential
            with mock.patch.object(proof.shutil, "which", return_value=str(fake)):
                with instance.traced_identities("memory") as (management, provider, trace):
                    wrapper = instance.env["PATH"].split(os.pathsep, 1)[0] + "/kubectl"
                    for handle in (management, provider):
                        result = subprocess.run(
                            [wrapper, "--kubeconfig", handle, "get", "namespace", "kube-system"],
                            text=True, capture_output=True, env=instance.env,
                            pass_fds=instance.fds, check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), "credential-readable")
                rows = [json.loads(line) for line in trace.read_text().splitlines()]

            proof.assert_trace(rows)
            persisted = "\n".join(
                path.read_text(errors="replace")
                for path in directory.iterdir() if path.is_file()
            )
            for token in tokens:
                self.assertNotIn(token, trace.read_text())
                self.assertNotIn(token, persisted)


if __name__ == "__main__":
    unittest.main()
