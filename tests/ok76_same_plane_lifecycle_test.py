#!/usr/bin/env python3
"""Same-plane real lifecycle integration against fake APIs; never live kubectl."""

import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import select
import time
import tempfile
import unittest

import ok186_lifecycle_test as fixtures
from scripts import talos_golden_lifecycle as life


class SamePlaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.certs.cleanup)
        root = Path(cls.certs.name)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                str(root / "key"),
                "-out",
                str(root / "ca"),
                "-subj",
                "/CN=offline-test",
                "-days",
                "1",
            ],
            check=True,
            capture_output=True,
        )
        cls.ca = base64.b64encode((root / "ca").read_bytes()).decode()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.box = fixtures.Sandbox(Path(temp.name) / "fixture")
        self.original = self.box.read_state()
        self.original["plane_uid"] = "original-plane"
        self.original["kubeconfig"] = {
            "clusters": [
                {
                    "name": "infra",
                    "cluster": {
                        "server": "https://infra.example.test:6443",
                        "certificate-authority-data": self.ca,
                    },
                }
            ],
            "contexts": [
                {"name": "infra", "context": {"cluster": "infra", "user": "operator"}}
            ],
            "users": [{"name": "operator", "user": {}}],
            "current-context": "infra",
        }
        cluster = self.original["cluster"]
        self.original["kvc"] = {
            "metadata": {
                "name": cluster["spec"]["infrastructureRef"]["name"],
                "ownerReferences": [
                    {"kind": "Cluster", "uid": cluster["metadata"]["uid"]}
                ],
            },
            "spec": {},
        }
        self.original["virtualmachines.kubevirt.io"] = []
        self.original["kubevirtmachines.infrastructure.cluster.x-k8s.io"] = []
        self.original["machines"] = []
        for i, dv in enumerate(self.original["datavolumes"]):
            dv["metadata"]["ownerReferences"] = [
                {"kind": "VirtualMachine", "uid": f"vm-{i}"}
            ]
            self.original["virtualmachines.kubevirt.io"].append(
                {
                    "metadata": {
                        "name": f"vm-{i}",
                        "namespace": fixtures.CLUSTER,
                        "uid": f"vm-{i}",
                        "labels": {
                            "capk.cluster.x-k8s.io/kubevirt-machine-name": f"kvm-{i}",
                            "capk.cluster.x-k8s.io/kubevirt-machine-namespace": fixtures.CLUSTER,
                            "cluster.x-k8s.io/cluster-name": fixtures.CLUSTER,
                        },
                    }
                }
            )
            self.original["kubevirtmachines.infrastructure.cluster.x-k8s.io"].append(
                {
                    "metadata": {
                        "name": f"kvm-{i}",
                        "uid": f"kvm-{i}",
                        "ownerReferences": [{"kind": "Machine", "uid": f"machine-{i}"}],
                        "labels": {"cluster.x-k8s.io/cluster-name": fixtures.CLUSTER},
                    }
                }
            )
            self.original["machines"].append(
                {
                    "metadata": {
                        "uid": f"machine-{i}",
                        "labels": {"cluster.x-k8s.io/cluster-name": fixtures.CLUSTER},
                    },
                    "spec": {
                        "infrastructureRef": {
                            "kind": "KubevirtMachine",
                            "name": f"kvm-{i}",
                        }
                    },
                }
            )
        for i, pvc in enumerate(self.original["pvcs"]):
            pvc["metadata"].update(
                uid=f"pvc-{i}",
                namespace=fixtures.CLUSTER,
                ownerReferences=[
                    {
                        "kind": "DataVolume",
                        "uid": self.original["datavolumes"][i]["metadata"]["uid"],
                    }
                ],
            )
            pv = self.original["pvs"][i]
            pv["spec"].update(
                claimRef={
                    "namespace": fixtures.CLUSTER,
                    "name": pvc["metadata"]["name"],
                    "uid": f"pvc-{i}",
                },
                csi={
                    "driver": "driver.longhorn.io",
                    "volumeHandle": pv["metadata"]["name"],
                },
            )
            pv["status"] = {"phase": "Bound"}
            self.original["longhorns"][i].update(
                status={"state": "detached"}, spec={"nodeID": ""}
            )
        fake = fixtures.FAKE_KUBECTL
        fake = fake.replace(
            "args = list(raw)",
            """if "auth" in raw:
    print("yes")
    sys.exit(0)
if "config" in raw:
    print(json.dumps(state["kubeconfig"]))
    sys.exit(0)
args = list(raw)""",
        )
        fake = fake.replace(
            '    if resource == "cluster":\n        obj = state.get("cluster")',
            """    if resource == "kubevirtcluster":
        obj = state.get("kvc")
    elif resource in ("volumeattachments.storage.k8s.io", "persistentvolumeclaims", "pods", "engines.longhorn.io", "volumeattachments.longhorn.io", "replicas.longhorn.io", "snapshots.longhorn.io", "virtualmachines.kubevirt.io", "kubevirtmachines.infrastructure.cluster.x-k8s.io"):
        print(json.dumps({"items": state.get(resource, [])}))
        sys.exit(0)
    elif resource == "cluster":
        obj = state.get("cluster")""",
        )
        fake = fake.replace(
            '        state["cluster"] = None',
            """        state["cluster"] = None
        state["datavolumes"] = []
        state["pvcs"] = []
        for pv in state["pvs"]: pv["status"] = {"phase": "Released"}""",
        )
        (self.box.bin / "kubectl").write_text(fake)
        initial = copy.deepcopy(self.original)
        initial["namespace"] = None
        initial["cluster"] = None
        self.box.write_state(initial)
        self.args = (
            "--topology",
            "same-plane",
            "--provider-kubeconfig",
            str(self.box.infra),
            "--backend-timeout-seconds",
            "0.01",
        )
        result, _ = self.box.lifecycle("--same-plane-preflight", *self.args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.box.write_state(self.original)
        result, _ = self.box.lifecycle("--same-plane-capture", *self.args)
        self.assertEqual(result.returncode, 0, result.stderr)

    def destroy(self):
        return self.box.lifecycle("--teardown", *self.args)

    def record(self):
        value = next(iter(self.box.read_state()["configmaps"].values()))
        return json.loads(value["data"]["record.json"])

    def test_complete_and_idempotent_preserves_original_evidence_and_golden(self):
        golden = copy.deepcopy(self.original["golden"])
        before = {
            p.name: p.read_bytes() for p in self.box.rendered.iterdir() if p.is_file()
        }
        result, _ = self.destroy()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self.box.read_state()
        self.assertIsNone(state["namespace"])
        self.assertEqual(state["pvs"], [])
        self.assertEqual(state["longhorns"], [])
        self.assertEqual(state["golden"], golden)
        self.assertEqual(self.record()["schema_version"], 3)
        self.assertTrue(self.record()["complete"])
        self.assertEqual(
            before,
            {
                p.name: p.read_bytes()
                for p in self.box.rendered.iterdir()
                if p.is_file()
            },
        )
        result, calls = self.destroy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_plane_drift_rejected_before_mutation(self):
        self.box.mutate(lambda s: s.update(plane_uid="replacement"))
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_external_provider_rejected_before_preparation_or_bootstrap(self):
        import yaml

        path = self.box.rendered / "cluster-config.yaml"
        cfg = yaml.safe_load(path.read_text())
        cfg["infraClusterSecretRef"] = {
            "name": "external",
            "namespace": fixtures.CLUSTER,
        }
        path.write_text(yaml.safe_dump(cfg))
        result, calls = self.box.lifecycle("--same-plane-preflight", *self.args)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_longhorn_failure_never_completes_and_retry_is_bound(self):
        self.box.mutate(lambda s: s.update(faults={"delete:longhorn": 1}))
        result, _ = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record()["complete"])
        self.box.mutate(
            lambda s: s["longhorns"][0]["metadata"].update(uid="replacement")
        )
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_namespace_recreation_rejected(self):
        self.box.mutate(lambda s: s.update(faults={"delete:cluster": 1}))
        result, _ = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.box.mutate(lambda s: s["namespace"]["metadata"].update(uid="replacement"))
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_claimref_mismatch_rejected_before_any_mutation(self):
        self.box.mutate(lambda s: s["pvs"][0]["spec"]["claimRef"].update(uid="foreign"))
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_backend_or_attachment_prevents_completion(self):
        for kind in (
            "replicas.longhorn.io",
            "engines.longhorn.io",
            "snapshots.longhorn.io",
            "volumeattachments.storage.k8s.io",
        ):
            with self.subTest(kind=kind):
                obj = {
                    "metadata": {"name": "backend"},
                    "spec": {
                        "volumeName": "pv-owned-1",
                        "source": {"persistentVolumeName": "pv-owned-1"},
                    },
                }
                self.box.write_state({**copy.deepcopy(self.original), kind: [obj]})
                result, _ = self.destroy()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.record()["complete"])

    def test_record_artifact_tampering_and_legacy_rejected(self):
        self.box.mutate(lambda s: s.update(faults={"delete:cluster": 1}))
        self.destroy()
        record = self.record()
        changed = copy.deepcopy(record)
        changed["artifacts"]["cluster-base.yaml"]["content"] += "# tampered"
        with self.assertRaises(life.TalosLifecycleError):
            life.validate_teardown_record(changed, fixtures.CLUSTER)
        self.box.mutate(lambda s: s["pvs"][0]["metadata"].update(uid="replacement"))
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_transport_and_context_drift_rejected_without_mutations(self):
        for field in ("endpoint", "CA", "context"):
            with self.subTest(field=field):
                state = copy.deepcopy(self.original)
                cfg = state["kubeconfig"]
                if field == "endpoint":
                    cfg["clusters"][0]["cluster"]["server"] = (
                        "https://other.example.test:6443"
                    )
                elif field == "CA":
                    cfg["clusters"][0]["cluster"]["certificate-authority-data"] = (
                        "invalid"
                    )
                else:
                    cfg["current-context"] = cfg["contexts"][0]["name"] = (
                        "other-context"
                    )
                self.box.write_state(state)
                result, calls = self.destroy()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_vm_and_golden_ownership_drift_rejected(self):
        for target in ("VM", "Golden"):
            with self.subTest(target=target):
                state = copy.deepcopy(self.original)
                if target == "VM":
                    state["virtualmachines.kubevirt.io"][0]["metadata"]["labels"][
                        "capk.cluster.x-k8s.io/kubevirt-machine-name"
                    ] = "foreign"
                else:
                    state["golden"]["metadata"]["uid"] = "replacement"
                self.box.write_state(state)
                result, calls = self.destroy()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_legacy_record_is_not_reinterpreted(self):
        self.box.mutate(lambda s: s.update(faults={"delete:cluster": 1}))
        self.destroy()

        def change(state):
            cm = next(iter(state["configmaps"].values()))
            record = json.loads(cm["data"]["record.json"])
            for field in ("topology", "identity", "artifacts", "storage_bindings"):
                del record[field]
            record["schema_version"] = 1
            cm["data"]["record.json"] = json.dumps(record)

        self.box.mutate(change)
        result, calls = self.destroy()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refuses legacy/split", result.stderr)
        self.assertEqual(fixtures.mutation_calls(calls), [])

    def test_real_cli_explicit_same_plane_destroy(self):
        binary = Path(
            os.environ.get("OK_CLI_TEST_BINARY", fixtures.ROOT / ".tools/bin/ok")
        )
        self.assertTrue(
            binary.is_file(), "build the CLI before running the lifecycle suite"
        )
        master, slave = os.openpty()
        args = [
            str(binary),
            "cluster",
            "destroy",
            fixtures.CLUSTER,
            "--topology",
            "same-plane",
            "--management-kubeconfig",
            str(self.box.infra),
            "--provider-kubeconfig",
            str(self.box.infra),
            "--cluster-dir",
            str(self.box.rendered),
            "--lifecycle-root",
            str(fixtures.ROOT),
            "--ok-linux-path",
            str(fixtures.OK_LINUX_PATH),
        ]
        env = {
            **os.environ,
            "HOME": str(self.box.home),
            "PATH": str(self.box.bin) + os.pathsep + os.environ["PATH"],
            "FAKE_STATE": str(self.box.state_path),
            "FAKE_LOG": str(self.box.log),
        }
        process = subprocess.Popen(
            args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        os.close(slave)
        output = b""
        try:
            deadline = time.monotonic() + 15
            while b"Type ok to delete" not in output:
                self.assertLess(time.monotonic(), deadline)
                if select.select([process.stdout], [], [], 0.5)[0]:
                    chunk = os.read(process.stdout.fileno(), 4096)
                    self.assertTrue(chunk, "CLI exited before approval")
                    output += chunk
            os.write(master, b"ok\n")
            stdout, stderr = process.communicate(timeout=90)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertTrue(self.record()["complete"])
            self.assertIn(b"independently observed complete", stdout)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
            os.close(master)

    def test_make_orders_preflight_apply_and_capture(self):
        result, _ = self.box.make(
            "bootstrap", "TALOS_LIFECYCLE_TOPOLOGY=same-plane", dry_run=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout
        self.assertLess(text.index("--same-plane-preflight"), text.index("apply -f"))
        self.assertLess(text.index("apply -f"), text.index("--same-plane-capture"))
        self.assertLess(
            text.index("--same-plane-capture"), text.rindex("bootstrap-post-apply")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
