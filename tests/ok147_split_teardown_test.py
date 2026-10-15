#!/usr/bin/env python3
"""Offline split-plane teardown integration tests; no real kubectl is used."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ok186_lifecycle_test import CLUSTER, Sandbox, lifecycle, render  # noqa: E402


class SplitTeardownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ok147-split-offline-")
        self.addCleanup(self.temp.cleanup)
        self.box = Sandbox(Path(self.temp.name).resolve() / "box")
        self.provider = self.box.base / "provider.yaml"
        self.provider.write_text("# fake provider kubeconfig\n")
        self.provider_state = self.box.base / "provider.json"
        state = self.box.read_state()
        state["plane_uid"] = "management-system-uid"
        provider = copy.deepcopy(state)
        provider["plane_uid"] = "provider-system-uid"
        provider["namespace"]["metadata"]["uid"] = "provider-namespace-uid"
        provider["cluster"] = None
        self.provider_state.write_text(json.dumps(provider))
        for key in ("role", "rolebinding"):
            state[key] = None
        for key in ("datavolumes", "pvcs", "pvs", "longhorns", "snapshots"):
            state[key] = []
        # Wrong-plane Golden reads must not accidentally succeed.
        state["golden"]["metadata"]["uid"] = "wrong-plane-golden"
        self.box.write_state(state)
        self.map = json.dumps({str(self.box.infra): str(self.box.state_path),
                               str(self.provider): str(self.provider_state)})
        self.evidence = self.box.rendered / "immutable-terminal.json"
        self.evidence.write_text('{"terminal":"STOP"}\n')
        self.initial_files = {path.relative_to(self.box.rendered): path.read_bytes()
                              for path in self.box.rendered.rglob("*") if path.is_file()}

    def run_teardown(self, *extra):
        return self.box.lifecycle("--teardown", "--provider-kubeconfig", str(self.provider),
                                  *extra, FAKE_STATE_MAP=self.map)

    def provider_read(self):
        return json.loads(self.provider_state.read_text())

    def provider_mutate(self, fn):
        state = self.provider_read()
        fn(state)
        self.provider_state.write_text(json.dumps(state))

    def record(self):
        cm = self.box.read_state()["configmaps"][lifecycle.TEARDOWN_LEDGER_PREFIX + CLUSTER]
        return json.loads(cm["data"]["record.json"])

    def assert_preserved(self):
        self.assertEqual(self.initial_files, {
            path.relative_to(self.box.rendered): path.read_bytes()
            for path in self.box.rendered.rglob("*") if path.is_file()
        })

    def assert_no_mutations(self, calls):
        self.assertFalse([call for call in calls if call[0] == "kubectl"
                          and any(verb in call for verb in ("create", "patch", "delete"))])

    def fail_cluster_delete(self):
        self.box.mutate(lambda state: state["faults"].update({"delete:cluster": 1}))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.record()["complete"])
        return calls

    def test_success_routes_and_preserves_evidence(self):
        golden = self.provider_read()["golden"]
        result, calls = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.record()
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(record["planes"], {
            "management_uid": "management-system-uid", "provider_uid": "provider-system-uid",
            "provider_namespace_uid": "provider-namespace-uid"})
        self.assertTrue(record["complete"])
        self.assertIsNone(self.box.read_state()["cluster"])
        self.assertIsNone(self.box.read_state()["namespace"])
        provider = self.provider_read()
        self.assertIsNone(provider["namespace"])
        self.assertEqual(provider["pvs"], [])
        self.assertEqual(provider["longhorns"], [])
        self.assertEqual(provider["golden"], golden)
        self.assertEqual([s["metadata"]["name"] for s in provider["snapshots"]], ["foreign-snapshot"])
        self.assertEqual(provider["configmaps"], {})
        self.assert_preserved()
        deletions = [call for call in calls if call[0] == "kubectl" and "delete" in call]
        self.assertIn("/clusters/", deletions[0][deletions[0].index("--raw") + 1])
        for call in calls:
            if call[0] != "kubectl":
                continue
            plane = call[call.index("--kubeconfig") + 1]
            if "configmap" in call or "cluster" in call:
                self.assertEqual(plane, str(self.box.infra))
            if any(kind in call for kind in ("datavolumes", "pvc", "pv", "role", "rolebinding", "volumesnapshots")):
                self.assertEqual(plane, str(self.provider))
        result, calls = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_no_mutations(calls)
        self.assert_preserved()

    def test_cluster_failure_keeps_both_namespaces_and_retries(self):
        calls = self.fail_cluster_delete()
        self.assertIsNotNone(self.box.read_state()["namespace"])
        self.assertIsNotNone(self.provider_read()["namespace"])
        self.assertFalse([c for c in calls if "delete" in c and str(self.provider) in c])
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_preserved()

    def test_provider_namespace_failure_keeps_management_namespace(self):
        self.provider_mutate(lambda state: state["faults"].update({"delete:namespace": 1}))
        result, _ = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record()["complete"])
        self.assertIsNotNone(self.box.read_state()["namespace"])
        self.assertIsNotNone(self.provider_read()["namespace"])
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_management_namespace_failure_is_incomplete_and_retryable(self):
        self.box.mutate(lambda state: state["faults"].update({"delete:namespace": 1}))
        result, _ = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(self.provider_read()["namespace"])
        self.assertFalse(self.record()["complete"])
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_retry_rejects_changed_provider_authority(self):
        self.fail_cluster_delete()
        self.provider_mutate(lambda state: state.update(plane_uid="another-system"))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plane authority differs", result.stderr)
        self.assert_no_mutations(calls)

    def test_retry_rejects_recreated_provider_namespace(self):
        self.fail_cluster_delete()
        self.provider_mutate(lambda state: state["namespace"]["metadata"].update(uid="recreated"))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different UID", result.stderr)
        self.assert_no_mutations(calls)

    def test_missing_provider_flag_cannot_resume_split_record(self):
        self.fail_cluster_delete()
        result, calls = self.box.lifecycle("--teardown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plane authority differs", result.stderr)
        self.assert_no_mutations(calls)

    def test_external_reference_requires_explicit_provider(self):
        path = self.box.rendered / "cluster-config.yaml"
        config = yaml.safe_load(path.read_text())
        config["infraClusterSecretRef"] = {"name": "provider", "namespace": CLUSTER}
        path.write_text(yaml.safe_dump(config))
        result, calls = self.box.lifecycle("--teardown")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires explicit --provider-kubeconfig", result.stderr)
        self.assert_no_mutations(calls)

    def test_same_plane_flag_rejected(self):
        self.provider_mutate(lambda state: state.update(plane_uid="management-system-uid"))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different plane", result.stderr)
        self.assert_no_mutations(calls)

    def test_teardown_flags_do_not_change_other_modes(self):
        result, calls = self.box.lifecycle("--resume-preconditions",
            "--provider-kubeconfig", str(self.provider), FAKE_STATE_MAP=self.map)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require --teardown", result.stderr)
        self.assertEqual(calls, [])

    def test_fixture_creation_never_invokes_operator_tools(self):
        with mock.patch.object(render.subprocess, "run", side_effect=AssertionError(
            "fixture setup must not execute operator tools"
        )):
            Sandbox(Path(self.temp.name) / "offline-fixture")

    def test_missing_namespace_or_plane_uid_rejected(self):
        for key in ("namespace", "plane_uid"):
            with self.subTest(key=key):
                initial = self.provider_read()
                self.provider_mutate(lambda state: state.update({key: None}))
                result, calls = self.run_teardown()
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_mutations(calls)
                self.provider_state.write_text(json.dumps(initial))

    def test_durable_write_failure_prevents_delete(self):
        self.box.mutate(lambda state: state["faults"].update({"create:configmap": 1}))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse([call for call in calls if "delete" in call])
        self.assertIsNotNone(self.box.read_state()["cluster"])

    def test_provider_pv_failure_retains_incomplete_record(self):
        self.provider_mutate(lambda state: state["faults"].update({"delete:pv": 1}))
        result, _ = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record()["complete"])
        self.assert_preserved()
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_longhorn_failure_cannot_complete_split_teardown(self):
        self.provider_mutate(lambda state: state["faults"].update({"delete:longhorn": 1}))
        result, _ = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record()["complete"])
        self.assertTrue(self.provider_read()["longhorns"])
        self.assert_preserved()
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.provider_read()["longhorns"], [])

    def test_inventory_refresh_failure_protects_namespaces(self):
        self.provider_mutate(lambda state: state.update(fault_after={"get:datavolumes": 2}))
        result, _ = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(self.box.read_state()["cluster"])
        self.assertIsNotNone(self.box.read_state()["namespace"])
        self.assertIsNotNone(self.provider_read()["namespace"])
        self.assertFalse(self.record()["complete"])

    def test_completed_record_rejects_recreated_provider_namespace(self):
        original = self.provider_read()["namespace"]
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        original["metadata"]["uid"] = "replacement-namespace"
        self.provider_mutate(lambda state: state.update(namespace=original))
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutations(calls)
        self.assertTrue(self.record()["complete"])

    def test_legacy_record_not_silently_upgraded(self):
        self.fail_cluster_delete()
        record = self.record()
        record["schema_version"] = 1
        del record["planes"]
        del record["storage_uids"]
        def replace(state):
            state["configmaps"][lifecycle.TEARDOWN_LEDGER_PREFIX + CLUSTER]["data"]["record.json"] = json.dumps(record)
        self.box.mutate(replace)
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plane authority differs", result.stderr)
        self.assert_no_mutations(calls)

    def test_swapped_plane_arguments_cannot_delete(self):
        result, calls = self.box.lifecycle("--teardown", "--kubeconfig", str(self.provider),
            "--provider-kubeconfig", str(self.box.infra), FAKE_STATE_MAP=self.map)
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutations(calls)

    def test_retry_does_not_adopt_recreated_storage(self):
        self.fail_cluster_delete()
        initial = self.provider_read()
        for key in ("pvs", "longhorns"):
            with self.subTest(key=key):
                state = copy.deepcopy(initial)
                state[key][0]["metadata"].update(uid="replacement-must-survive", resourceVersion="999")
                self.provider_state.write_text(json.dumps(state))
                result, calls = self.run_teardown()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("differs from durable storage UID", result.stderr)
                self.assert_no_mutations(calls)
                self.assertEqual(self.provider_read()[key][0]["metadata"]["uid"], "replacement-must-survive")
                self.assertFalse(self.record()["complete"])
                self.assert_preserved()

    def test_storage_uid_is_checked_again_at_cleanup(self):
        replacement = {"metadata": {"uid": "replacement", "name": "pv-owned-1"}}
        for reads in ([replacement], [None, replacement]):
            with self.subTest(reads=reads), \
                 mock.patch.object(lifecycle, "kubectl_json_optional", side_effect=reads), \
                 mock.patch.object(lifecycle, "preconditioned_delete") as delete:
                failures = lifecycle.cleanup_retained_volumes(self.provider, ["pv-owned-1"],
                    storage_uids={"pv-owned-1": {"pv": "original", "longhorn": "original-lh"}})
                self.assertTrue(failures)
                delete.assert_not_called()

    def test_missing_storage_provenance_is_not_accepted(self):
        self.fail_cluster_delete()
        record = self.record()
        for storage in ({}, {"pv-owned-1": {"pv": "", "longhorn": None}}):
            with self.subTest(storage=storage):
                candidate = {**record, "storage_uids": storage}
                with self.assertRaises(lifecycle.TalosLifecycleError):
                    lifecycle.validate_teardown_record(candidate, CLUSTER)

    def test_new_storage_is_bound_before_namespace_delete(self):
        self.fail_cluster_delete()
        def add(state):
            state["pvs"].append({"apiVersion": "v1", "kind": "PersistentVolume",
                "metadata": {"name": "late-pv", "uid": "late-pv-uid", "resourceVersion": "65"},
                "spec": {"persistentVolumeReclaimPolicy": "Retain"}})
            state["pvcs"].append({"metadata": {"name": "late-pvc"}, "spec": {"volumeName": "late-pv"}})
        self.provider_mutate(add)
        result, calls = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.record()["storage_uids"]["late-pv"], {"pv": "late-pv-uid", "longhorn": None})
        # The provenance patch must precede the first namespace deletion.
        namespace_index = next(i for i, call in enumerate(calls)
                               if "delete" in call and any(str(v).endswith("/namespaces/" + CLUSTER) for v in call))
        self.assertTrue(any("patch" in call and "late-pv-uid" in " ".join(map(str, call))
                            for call in calls[:namespace_index]))

    def test_previously_absent_longhorn_is_not_adopted_on_retry(self):
        self.provider_mutate(lambda state: state.update(longhorns=[]))
        self.fail_cluster_delete()
        def add(state):
            state["longhorns"].append({"metadata": {"name": "pv-owned-1", "uid": "new-volume"}})
        self.provider_mutate(add)
        result, calls = self.run_teardown()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutations(calls)

    def test_resume_without_local_render_uses_durable_provider_identity(self):
        self.fail_cluster_delete()
        # Simulate a different operator without local config, without deleting evidence.
        saved = self.box.rendered / "cluster-config.yaml"
        saved.rename(self.box.rendered / "cluster-config.saved")
        result, _ = self.run_teardown()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.record()["complete"])
        self.assertTrue(self.evidence.exists())

    def test_legacy_preserve_local_opt_in(self):
        box = Sandbox(Path(self.temp.name) / "legacy")
        result, _ = box.lifecycle("--teardown", "--preserve-local")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(box.rendered.exists())
        result, _ = box.lifecycle("--teardown", "--preserve-local")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(box.rendered.exists())

    def test_make_passes_explicit_provider_and_preserve_options(self):
        result, calls = self.box.make("teardown", "CONFIRM=yes",
            f"TALOS_TEARDOWN_PROVIDER_KUBECONFIG={self.provider}",
            "TALOS_TEARDOWN_PRESERVE_LOCAL=yes", FAKE_STATE_MAP=self.map)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.record()["complete"])
        self.assert_preserved()


if __name__ == "__main__":
    unittest.main(verbosity=2)
