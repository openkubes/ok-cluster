#!/usr/bin/env python3
"""Offline contract tests for the OK-197 teardown ledger boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(ROOT))

from ok186_lifecycle_test import (  # noqa: E402
    CLUSTER,
    LEDGER_NAMESPACE,
    Sandbox,
    ledger,
    mutation_calls,
)
from scripts import talos_golden_lifecycle as lifecycle  # noqa: E402


LEDGER_NAME = f"ok-cluster-teardown-{CLUSTER}"
LEGACY_NAMESPACE = "kube-system"
MANIFEST = ROOT / "deploy" / "talos-teardown-ledger.yaml"
SOURCE = ROOT / "scripts" / "talos_golden_lifecycle.py"
CHECKS: list[tuple[bool, str]] = []


def check(condition: bool, message: str) -> None:
    CHECKS.append((bool(condition), message))
    print(f"{'PASS' if condition else 'FAIL'} {message}")


def cm_key(namespace: str) -> str:
    return f"{namespace}/{LEDGER_NAME}"


def valid_record(box: Sandbox, *, complete: bool) -> dict:
    state = box.read_state()
    config = yaml.safe_load((box.rendered / "cluster-config.yaml").read_text())
    golden = state["golden"]["metadata"]
    return {
        "schema_version": 1,
        "cluster": {
            "name": CLUSTER,
            "namespace": CLUSTER,
            "uid": "cluster-original-uid",
        },
        "namespace_uid": "namespace-original-uid",
        "config": lifecycle.teardown_config_subset(config),
        "golden_before": {
            "uid": golden["uid"],
            "digest": golden["annotations"]["ok-linux.openkubes.io/image-sha256"],
            "identity": golden["annotations"]["ok-linux.openkubes.io/os-identity"],
        },
        "data_volume_uids": ["dv-owned-1", "dv-owned-2"],
        "persistent_volumes": ["pv-owned-1", "pv-owned-2"],
        "complete": complete,
    }


def configmap(namespace: str, record_text: str, *, uid: str, rv: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": LEDGER_NAME,
            "namespace": namespace,
            "uid": uid,
            "resourceVersion": rv,
            "labels": {
                "app.kubernetes.io/managed-by": "ok-cluster",
                "openkubes.io/consumer-cluster": CLUSTER,
            },
        },
        "data": {"record.json": record_text},
    }


def seed_record(
    box: Sandbox,
    namespace: str,
    record: dict,
    *,
    text: str | None = None,
    uid: str = "receipt-uid",
    rv: str = "70",
) -> str:
    record_text = text if text is not None else json.dumps(record, sort_keys=True)

    def seed(state: dict) -> None:
        state.setdefault("configmaps", {})[cm_key(namespace)] = configmap(
            namespace, record_text, uid=uid, rv=rv
        )

    box.mutate(seed)
    return record_text


def call_namespace(call: list) -> str:
    for flag in ("-n", "--namespace"):
        if flag in call:
            return str(call[call.index(flag) + 1])
    for value in call:
        if isinstance(value, str) and "/namespaces/" in value:
            return value.split("/namespaces/", 1)[1].split("/", 1)[0]
    return "default"


def call_verb(call: list) -> str:
    for verb in ("get", "create", "patch", "delete", "apply", "annotate"):
        if verb in call:
            return verb
    return ""


def kubectl_calls(calls: list[list]) -> list[list]:
    return [call for call in calls if call and call[0] == "kubectl"]


def is_configmap_call(call: list) -> bool:
    return any(value in call for value in ("configmap", "configmaps")) or (
        "create" in call and "-f" in call
    ) or any(
        isinstance(value, str) and "/configmaps/" in value for value in call
    )


def delete_options(calls: list[list]) -> list[dict]:
    return [
        call[1]
        for call in calls
        if call
        and call[0] == "kubectl-stdin"
        and isinstance(call[1], dict)
        and call[1].get("kind") == "DeleteOptions"
    ]


def exact_legacy_access(calls: list[list]) -> bool:
    legacy_calls = [
        call
        for call in kubectl_calls(calls)
        if call_namespace(call) == LEGACY_NAMESPACE
    ]
    return bool(legacy_calls) and all(
        (
            call_verb(call) == "get"
            and "configmap" in call
            and LEDGER_NAME in call
        )
        or (
            call_verb(call) == "delete"
            and any(
                isinstance(value, str)
                and value.endswith(f"/configmaps/{LEDGER_NAME}")
                for value in call
            )
        )
        for call in legacy_calls
    )


def absent_workload(box: Sandbox) -> None:
    def remove(state: dict) -> None:
        state["cluster"] = None
        state["namespace"] = None

    box.mutate(remove)


def rbac_tests(base: Path) -> None:
    docs = [item for item in yaml.safe_load_all(MANIFEST.read_text()) if item]
    namespaces = [item for item in docs if item.get("kind") == "Namespace"]
    roles = [item for item in docs if item.get("kind") == "Role"]
    cluster_roles = [item for item in docs if item.get("kind") == "ClusterRole"]
    role_verbs = set(roles[0]["rules"][0]["verbs"]) if len(roles) == 1 else set()
    check(
        len(namespaces) == 1
        and namespaces[0].get("metadata", {}).get("name") == LEDGER_NAMESPACE
        and namespaces[0].get("metadata", {}).get("annotations", {}).get(
            "openkubes.io/teardown-ledger-schema"
        )
        == "1",
        "RBAC manifest owns the dedicated schema-1 teardown namespace",
    )
    check(
        len(roles) == 1
        and roles[0].get("metadata", {}).get("namespace") == LEDGER_NAMESPACE
        and roles[0].get("rules")
        == [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "create", "patch"]}],
        "ledger Role grants only get/create/patch on ConfigMaps in the owned namespace",
    )
    check(
        len(cluster_roles) == 1
        and cluster_roles[0].get("rules")
        == [{
            "apiGroups": [""],
            "resources": ["namespaces"],
            "resourceNames": [LEDGER_NAMESPACE],
            "verbs": ["get"],
        }],
        "namespace guard authority is one exact-name get",
    )

    install = Sandbox(base / "install-target")
    refused, refused_calls = install.make(
        "install-teardown-ledger",
        CONFIRM="false",
        INFRA_KUBECONFIG=str(install.infra),
    )
    plan, _ = install.make(
        "install-teardown-ledger",
        dry_run=True,
        CONFIRM="yes",
        INFRA_KUBECONFIG=str(install.infra),
    )
    check(
        refused.returncode != 0
        and not refused_calls
        and plan.returncode == 0
        and str(MANIFEST) in plan.stdout
        and str(install.infra) in plan.stdout,
        "install target is confirmation-gated and applies the reviewed manifest with an explicit kubeconfig",
    )

    box = Sandbox(base / "successful-teardown")
    result, calls = box.lifecycle("--teardown")
    actual_verbs = {
        call_verb(call)
        for call in kubectl_calls(calls)
        if call_namespace(call) == LEDGER_NAMESPACE and is_configmap_call(call)
    }
    check(
        result.returncode == 0 and actual_verbs == role_verbs == {"get", "create", "patch"},
        "successful teardown ConfigMap verbs exactly equal the Role get/create/patch set",
    )


def teardown_boundary_tests(base: Path) -> None:
    happy = Sandbox(base / "happy")
    result, calls = happy.lifecycle("--teardown")
    api_calls = kubectl_calls(calls)
    first_ledger = next(
        (call for call in api_calls if LEDGER_NAMESPACE in call), []
    )
    check(
        result.returncode == 0
        and first_ledger
        and call_verb(first_ledger) == "get"
        and "namespace" in first_ledger
        and all(LEGACY_NAMESPACE not in call for call in api_calls),
        "teardown guards the exact ledger namespace first and never accesses kube-system",
    )

    fallback = Sandbox(base / "legacy-fallback-trap")
    seed_record(
        fallback,
        LEGACY_NAMESPACE,
        valid_record(fallback, complete=False),
        uid="legacy-trap-uid",
    )
    result, calls = fallback.lifecycle("--teardown")
    check(
        result.returncode == 0
        and ledger(fallback.read_state())["complete"] is True
        and cm_key(LEGACY_NAMESPACE) in fallback.read_state()["configmaps"]
        and all(LEGACY_NAMESPACE not in call for call in kubectl_calls(calls)),
        "teardown ignores a valid legacy receipt and never falls back to kube-system",
    )

    for name, mutate in (
        ("absent", lambda state: state.__setitem__("ledger_namespace", None)),
        (
            "unreadable",
            lambda state: state.setdefault("faults", {}).__setitem__(
                f"get:namespace:default:{LEDGER_NAMESPACE}", 1
            ),
        ),
        (
            "terminating",
            lambda state: state["ledger_namespace"]["metadata"].__setitem__(
                "deletionTimestamp", "2026-10-12T00:00:00Z"
            ),
        ),
    ):
        box = Sandbox(base / name)
        box.mutate(mutate)
        result, calls = box.lifecycle("--teardown")
        check(
            result.returncode != 0
            and LEDGER_NAMESPACE in result.stderr
            and "install-teardown-ledger" in result.stderr
            and not any(call_verb(call) == "delete" for call in kubectl_calls(calls))
            and not any(is_configmap_call(call) for call in kubectl_calls(calls)),
            f"{name} ledger namespace aborts before ConfigMap reads and every delete",
        )

    for name, mutate in (
        (
            "absent",
            lambda item: item["metadata"].pop("labels", None),
        ),
        (
            "foreign",
            lambda item: item["metadata"]["labels"].__setitem__(
                "openkubes.io/consumer-cluster", "foreign"
            ),
        ),
    ):
        box = Sandbox(base / f"labels-{name}")
        seed_record(box, LEDGER_NAMESPACE, valid_record(box, complete=False))
        box.mutate(
            lambda state, operation=mutate: operation(
                state["configmaps"][cm_key(LEDGER_NAMESPACE)]
            )
        )
        result, calls = box.lifecycle("--teardown")
        check(
            result.returncode != 0
            and "ownership labels are invalid" in result.stderr
            and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
            f"{name} new-namespace ownership labels fail closed before every delete",
        )


def recovery_test(base: Path) -> None:
    box = Sandbox(base / "missing-local-render")
    box.mutate(
        lambda state: state.setdefault("faults", {}).__setitem__("delete:role", 1)
    )
    first, _ = box.lifecycle("--teardown")
    shutil.rmtree(box.rendered)
    retry, calls = box.lifecycle("--teardown")
    check(
        first.returncode != 0
        and retry.returncode == 0
        and ledger(box.read_state())["complete"] is True
        and all(LEGACY_NAMESPACE not in call for call in kubectl_calls(calls)),
        "retry without local render recovers only from the new-namespace ledger",
    )


def schema_tests(base: Path) -> None:
    cases = (
        (2, "unsupported teardown ledger schema 2; supported: 1", "newer integer"),
        (0, "unsupported teardown ledger schema 0; supported: 1", "unknown integer"),
        (True, "teardown record schema is invalid", "boolean"),
        ("2", "teardown record schema is invalid", "string"),
        (None, "teardown record schema is invalid", "missing"),
    )
    for index, (schema, expected, description) in enumerate(cases):
        box = Sandbox(base / str(index))
        record = valid_record(box, complete=False)
        if schema is None:
            record.pop("schema_version")
        else:
            record["schema_version"] = schema
        seed_record(box, LEDGER_NAMESPACE, record)
        result, calls = box.lifecycle("--teardown")
        check(
            result.returncode != 0
            and expected in result.stderr
            and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
            f"{description} schema fails closed with the required diagnostic",
        )
    malformed = (
        ("{not-json", "Expecting property name", "malformed JSON"),
        (json.dumps([1]), "not an object", "non-object JSON"),
        (
            json.dumps({**valid_record(Sandbox(base / "extra-template"), complete=False), "extra": True}),
            "schema is invalid",
            "extra-field record",
        ),
    )
    for index, (record_text, expected, description) in enumerate(malformed):
        box = Sandbox(base / f"malformed-{index}")
        box.mutate(
            lambda state, value=record_text: state.setdefault("configmaps", {}).__setitem__(
                cm_key(LEDGER_NAMESPACE),
                configmap(LEDGER_NAMESPACE, value, uid="malformed-uid", rv="75"),
            )
        )
        result, calls = box.lifecycle("--teardown")
        check(
            result.returncode != 0
            and expected in result.stderr
            and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
            f"{description} fails closed before every delete",
        )


def migration_tests(base: Path) -> None:
    refused = Sandbox(base / "confirm-refused")
    result, calls = refused.lifecycle(
        "--migrate-teardown-ledger", confirm="no"
    )
    check(
        result.returncode != 0
        and "requires --confirm yes" in result.stderr
        and not calls,
        "migration refuses without literal --confirm yes before every API call",
    )

    missing = Sandbox(base / "clean-missing")
    result, calls = missing.lifecycle("--migrate-teardown-ledger")
    check(
        result.returncode == 0
        and "SKIP" in result.stdout
        and not mutation_calls(calls)
        and exact_legacy_access(calls)
        and cm_key(LEDGER_NAMESPACE) not in missing.read_state()["configmaps"],
        "clean migration with source and destination absent is a named-read-only SKIP",
    )

    box = Sandbox(base / "success")
    record = valid_record(box, complete=True)
    legacy_text = json.dumps(record, indent=2, sort_keys=False) + "\n"
    seed_record(
        box,
        LEGACY_NAMESPACE,
        record,
        text=legacy_text,
        uid="legacy-uid",
        rv="81",
    )
    box.mutate(
        lambda state: state["configmaps"][cm_key(LEGACY_NAMESPACE)][
            "metadata"
        ].pop("labels", None)
    )
    result, calls = box.lifecycle("--migrate-teardown-ledger")
    state = box.read_state()
    api_calls = kubectl_calls(calls)
    destination = state.get("configmaps", {}).get(cm_key(LEDGER_NAMESPACE))
    create_index = next(
        (i for i, call in enumerate(api_calls) if call_verb(call) == "create"),
        None,
    )
    verify_index = next(
        (
            i
            for i, call in enumerate(api_calls)
            if create_index is not None
            and i > create_index
            and call_namespace(call) == LEDGER_NAMESPACE
            and call_verb(call) == "get"
            and is_configmap_call(call)
        ),
        None,
    )
    delete_index = next(
        (
            i
            for i, call in enumerate(api_calls)
            if call_namespace(call) == LEGACY_NAMESPACE
            and call_verb(call) == "delete"
        ),
        None,
    )
    options = delete_options(calls)
    check(
        result.returncode == 0
        and destination is not None
        and destination["data"]["record.json"] == legacy_text
        and destination["metadata"]["labels"]
        == {
            "app.kubernetes.io/managed-by": "ok-cluster",
            "openkubes.io/consumer-cluster": CLUSTER,
        }
        and cm_key(LEGACY_NAMESPACE) not in state["configmaps"]
        and verify_index is not None
        and delete_index is not None
        and verify_index < delete_index
        and exact_legacy_access(calls)
        and options
        and options[-1].get("preconditions")
        == {"uid": "legacy-uid", "resourceVersion": "81"},
        "migration accepts unlabeled legacy input, copies exact bytes with owned labels, rereads, then UID/RV-deletes legacy",
    )
    second, second_calls = box.lifecycle("--migrate-teardown-ledger")
    check(
        second.returncode == 0
        and "SKIP" in second.stdout
        and not mutation_calls(second_calls),
        "migration is idempotent after the legacy receipt is absent",
    )

    interrupted = Sandbox(base / "interrupted-delete")
    record = valid_record(interrupted, complete=True)
    interrupted_text = json.dumps(record, indent=2) + "\n"
    seed_record(
        interrupted,
        LEGACY_NAMESPACE,
        record,
        text=interrupted_text,
        uid="legacy-retry-uid",
        rv="82",
    )
    interrupted.mutate(
        lambda state: state.setdefault("faults", {}).__setitem__(
            "delete:configmap", 1
        )
    )
    first, _ = interrupted.lifecycle("--migrate-teardown-ledger")
    after_first = interrupted.read_state()
    first_destination = after_first.get("configmaps", {}).get(
        cm_key(LEDGER_NAMESPACE)
    )
    retry, retry_calls = interrupted.lifecycle("--migrate-teardown-ledger")
    after_retry = interrupted.read_state()
    retry_destination = after_retry.get("configmaps", {}).get(
        cm_key(LEDGER_NAMESPACE)
    )
    check(
        first.returncode != 0
        and cm_key(LEGACY_NAMESPACE) in after_first["configmaps"]
        and first_destination is not None
        and first_destination["data"]["record.json"] == interrupted_text
        and retry.returncode == 0
        and cm_key(LEGACY_NAMESPACE) not in after_retry["configmaps"]
        and retry_destination is not None
        and retry_destination["data"]["record.json"] == interrupted_text
        and any(call_verb(call) == "patch" for call in kubectl_calls(retry_calls)),
        "migration retry accepts identical copied bytes after an interrupted legacy delete",
    )

    conflict = Sandbox(base / "conflict")
    record = valid_record(conflict, complete=True)
    legacy_text = json.dumps(record, indent=2) + "\n"
    seed_record(conflict, LEGACY_NAMESPACE, record, text=legacy_text, uid="legacy-uid")
    seed_record(
        conflict,
        LEDGER_NAMESPACE,
        record,
        text=json.dumps(record, sort_keys=True),
        uid="destination-uid",
    )
    result, calls = conflict.lifecycle("--migrate-teardown-ledger")
    check(
        result.returncode != 0
        and "differs from legacy" in result.stderr
        and cm_key(LEGACY_NAMESPACE) in conflict.read_state()["configmaps"]
        and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
        "migration refuses a byte-different destination without deleting legacy",
    )

    corrupt = Sandbox(base / "corrupt-readback")
    record = valid_record(corrupt, complete=True)
    seed_record(corrupt, LEGACY_NAMESPACE, record, uid="legacy-uid")
    corrupt.mutate(
        lambda state: state.setdefault("corrupt_configmap_reads", {}).__setitem__(
            cm_key(LEDGER_NAMESPACE), 1
        )
    )
    result, calls = corrupt.lifecycle("--migrate-teardown-ledger")
    check(
        result.returncode != 0
        and "did not persist exactly" in result.stderr
        and cm_key(LEGACY_NAMESPACE) in corrupt.read_state()["configmaps"]
        and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
        "migration refuses corrupt destination readback before deleting legacy",
    )


def prune_tests(base: Path) -> None:
    refused = Sandbox(base / "confirm-refused")
    result, calls = refused.lifecycle("--prune-teardown-ledger", confirm="no")
    check(
        result.returncode != 0
        and "requires --confirm yes" in result.stderr
        and not calls,
        "prune refuses without literal --confirm yes before every API call",
    )

    completed = Sandbox(base / "completed")
    seed_record(completed, LEDGER_NAMESPACE, valid_record(completed, complete=True), uid="prune-uid", rv="91")
    absent_workload(completed)
    result, calls = completed.lifecycle("--prune-teardown-ledger")
    options = delete_options(calls)
    check(
        result.returncode == 0
        and cm_key(LEDGER_NAMESPACE) not in completed.read_state()["configmaps"]
        and options
        and options[-1].get("preconditions")
        == {"uid": "prune-uid", "resourceVersion": "91"},
        "prune deletes a completed receipt only after absent Cluster and Namespace guards",
    )

    incomplete = Sandbox(base / "incomplete")
    seed_record(incomplete, LEDGER_NAMESPACE, valid_record(incomplete, complete=False))
    absent_workload(incomplete)
    result, calls = incomplete.lifecycle("--prune-teardown-ledger")
    check(
        result.returncode != 0
        and "incomplete teardown record" in result.stderr
        and cm_key(LEDGER_NAMESPACE) in incomplete.read_state()["configmaps"]
        and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
        "prune never deletes an incomplete receipt",
    )

    live_cluster = Sandbox(base / "live-cluster")
    seed_record(live_cluster, LEDGER_NAMESPACE, valid_record(live_cluster, complete=True))
    live_cluster.mutate(lambda state: state.__setitem__("namespace", None))
    result, calls = live_cluster.lifecycle("--prune-teardown-ledger")
    check(
        result.returncode != 0
        and "CAPI Cluster" in result.stderr
        and cm_key(LEDGER_NAMESPACE) in live_cluster.read_state()["configmaps"]
        and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
        "prune preserves a completed receipt while its CAPI Cluster is live",
    )

    live_namespace = Sandbox(base / "live-namespace")
    seed_record(live_namespace, LEDGER_NAMESPACE, valid_record(live_namespace, complete=True))
    live_namespace.mutate(lambda state: state.__setitem__("cluster", None))
    result, calls = live_namespace.lifecycle("--prune-teardown-ledger")
    check(
        result.returncode != 0
        and f"Namespace {CLUSTER}" in result.stderr
        and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
        "prune preserves a completed receipt while its workload Namespace is live",
    )

    for resource, setup, fault in (
        (
            "Cluster",
            lambda state: state.__setitem__("namespace", None),
            "get:cluster",
        ),
        (
            "Namespace",
            lambda state: state.__setitem__("cluster", None),
            f"get:namespace:default:{CLUSTER}",
        ),
    ):
        box = Sandbox(base / f"unreadable-{resource.lower()}")
        seed_record(box, LEDGER_NAMESPACE, valid_record(box, complete=True))

        def prepare(state: dict, mutate=setup, key=fault) -> None:
            mutate(state)
            state.setdefault("faults", {})[key] = 1

        box.mutate(prepare)
        result, calls = box.lifecycle("--prune-teardown-ledger")
        check(
            result.returncode != 0
            and cm_key(LEDGER_NAMESPACE) in box.read_state()["configmaps"]
            and not any(call_verb(call) == "delete" for call in kubectl_calls(calls)),
            f"prune refuses an unreadable {resource} guard without deleting the receipt",
        )


CASES = {
    "rbac": rbac_tests,
    "teardown": teardown_boundary_tests,
    "recovery": recovery_test,
    "schema": schema_tests,
    "migration": migration_tests,
    "prune": prune_tests,
}


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(
            f"mutation anchor count for {path.name} is {text.count(old)}, expected 1"
        )
    path.write_text(text.replace(old, new, 1))


def mutation_proofs(selected: str | None = None) -> int:
    ledger_read = """    if configmap is not None:
"""
    legacy_fallback = """    if configmap is None:
        configmap = kubectl_json_optional(
            kubeconfig,
            [
                "-n",
                LEGACY_TEARDOWN_LEDGER_NAMESPACE,
                "get",
                "configmap",
                teardown_ledger_name(cluster),
            ],
        )
    if configmap is not None:
"""
    early_delete = """    destination = write_teardown_configmap(
"""
    injected_delete = """    preconditioned_delete(
        kubeconfig,
        legacy,
        api_path(legacy, "configmaps"),
        ["-n", LEGACY_TEARDOWN_LEDGER_NAMESPACE, "get", "configmap", name],
        "mutated early legacy delete",
    )
    destination = write_teardown_configmap(
"""
    mutations = (
        (
            "fallback",
            "teardown kube-system fallback",
            SOURCE,
            ledger_read,
            legacy_fallback,
            "teardown",
        ),
        (
            "prune-incomplete",
            "prune incomplete",
            SOURCE,
            '    if record["complete"] is not True:',
            '    if False and record["complete"] is not True:',
            "prune",
        ),
        (
            "prune-live",
            "prune live Cluster",
            SOURCE,
            "    if cluster is not None or namespace is not None:",
            "    if namespace is not None:",
            "prune",
        ),
        (
            "migration-order",
            "migration delete before verification",
            SOURCE,
            early_delete,
            injected_delete,
            "migration",
        ),
        (
            "schema",
            "schema validation removed",
            SOURCE,
            '    schema = record.get("schema_version")',
            "    schema = TEARDOWN_LEDGER_SCHEMA",
            "schema",
        ),
        (
            "role-verbs",
            "Role verb drift",
            MANIFEST,
            "    verbs: [get, create, patch]",
            "    verbs: [get, create, patch, update]",
            "rbac",
        ),
    )
    failures: list[str] = []
    chosen = [item for item in mutations if selected is None or item[0] == selected]
    live_hashes = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (SOURCE, MANIFEST)
    }
    isolated_parent = Path(tempfile.mkdtemp(prefix="ok197-mutations-"))
    isolated_root = isolated_parent / "ok-cluster"
    try:
        shutil.copytree(
            ROOT,
            isolated_root,
            ignore=shutil.ignore_patterns(
                ".git", ".tools", "build", "__pycache__", "*.pyc"
            ),
        )
        (isolated_parent / "ok-linux").symlink_to(
            ROOT.parent / "ok-linux", target_is_directory=True
        )
        for _, description, live_path, old, new, case in chosen:
            path = isolated_root / live_path.relative_to(ROOT)
            original = path.read_bytes()
            try:
                replace_once(path, old, new)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(isolated_root / "tests" / Path(__file__).name),
                        "--case",
                        case,
                    ],
                    cwd=isolated_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            finally:
                path.write_bytes(original)
            assertion_failed = any(
                line.startswith("FAIL ") for line in result.stdout.splitlines()
            )
            if result.returncode == 0 or not assertion_failed:
                failures.append(description)
                print(
                    "FAIL mutation proof did not reach a failing assertion: "
                    f"{description}"
                )
            else:
                print(f"PASS mutation rejected: {description}")
    finally:
        shutil.rmtree(isolated_parent)
    live_after = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in live_hashes
    }
    if live_after != live_hashes:
        failures.append("live source changed during isolated mutation proofs")
        print("FAIL isolated mutation proofs changed live source")
    else:
        print("PASS isolated mutation proofs left live source bytes unchanged")
    if failures:
        print(f"FAIL {len(failures)} mutations survived", file=sys.stderr)
        return 1
    print(f"PASS all {len(chosen)} mutation proofs")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES))
    parser.add_argument("--mutation-proofs", action="store_true")
    parser.add_argument(
        "--mutation-proof",
        choices=(
            "fallback",
            "prune-incomplete",
            "prune-live",
            "migration-order",
            "schema",
            "role-verbs",
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mutation_proofs or args.mutation_proof:
        return mutation_proofs(args.mutation_proof)
    base = Path(tempfile.mkdtemp(prefix="ok197-"))
    selected = [args.case] if args.case else list(CASES)
    for name in selected:
        CASES[name](base / name)
    failed = [message for condition, message in CHECKS if not condition]
    if failed:
        print(f"FAIL {len(failed)} OK-197 checks failed; sandbox kept at {base}", file=sys.stderr)
        return 1
    shutil.rmtree(base)
    print(f"PASS all {len(CHECKS)} OK-197 checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
