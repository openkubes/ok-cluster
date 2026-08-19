#!/usr/bin/env python3
"""Unit tests for the OK-129 installer-side access guard."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

import ok129_access as access


def profile(**write_overrides):
    write = {
        "scope": "namespaces",
        "namespaces": ["kagent-lab"],
        "resources": {"configmaps": ["get", "patch"]},
        "requireApproval": True,
        "toolServer": {
            "namespace": "kagent-write",
            "releaseName": "kagent-write-tools",
            "port": 8084,
            "metricsPort": 8085,
        },
        "agentName": "cluster-operator-gated",
    }
    write.update(write_overrides)
    return {
        "kind": "KagentAccessProfile",
        "mode": "read-write",
        "install": {"namespace": "kagent"},
        "write": write,
    }


class ValidationTests(unittest.TestCase):
    def test_evidenced_profile_is_allowed(self):
        access.validate_ok129(profile())

    def test_read_only_may_park_only_the_evidenced_write_profile(self):
        raw = profile()
        raw["mode"] = "read-only"
        access.validate_ok129(raw)

    def test_cluster_scope_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "cluster scope"):
            access.validate_ok129(profile(scope="cluster", namespaces=[]))

    def test_ungated_write_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "requireApproval=true"):
            access.validate_ok129(profile(requireApproval=False))

    def test_supported_resource_verbs_are_allowed(self):
        access.validate_ok129(
            profile(resources={"deployments": ["get", "patch"], "pods": ["get", "delete"], "services": ["get", "update"]})
        )

    def test_unsupported_resource_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "unsupported resource"):
            access.validate_ok129(profile(resources={"configmaps": ["get"], "widgets": ["get"]}))

    def test_empty_resource_mapping_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "non-empty mapping"):
            access.validate_ok129(profile(resources={}))

    def test_duplicate_resource_verb_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "duplicate verb"):
            access.validate_ok129(profile(resources={"pods": ["get", "get"]}))

    def test_unsupported_resource_verb_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "unsupported verb"):
            access.validate_ok129(profile(resources={"pods": ["exec"]}))

    def test_non_lab_namespace_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "exactly: kagent-lab"):
            access.validate_ok129(profile(namespaces=["team-a"]))

    def test_shell_syntax_in_sourced_names_is_refused(self):
        """profile.env is sourced, so these names may not carry shell syntax."""
        for name in ("tools; rm -rf /", "tools$(id)", "tools`id`", "tools name", "Tools"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(access.AccessError, "releaseName"):
                    access.validate_ok129(
                        profile(
                            toolServer={
                                "namespace": "kagent-write",
                                "releaseName": name,
                                "port": 8084,
                                "metricsPort": 8085,
                            }
                        )
                    )
                with self.assertRaisesRegex(access.AccessError, "agentName"):
                    access.validate_ok129(profile(agentName=name))

    def test_non_dns_tool_server_namespace_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "toolServer.namespace"):
            access.validate_ok129(
                profile(
                    toolServer={
                        "namespace": "Kagent_Write",
                        "releaseName": "kagent-write-tools",
                        "port": 8084,
                        "metricsPort": 8085,
                    }
                )
            )

    def test_non_integer_port_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "toolServer.port"):
            access.validate_ok129(
                profile(
                    toolServer={
                        "namespace": "kagent-write",
                        "releaseName": "kagent-write-tools",
                        "port": "8084; id",
                        "metricsPort": 8085,
                    }
                )
            )


class ProfileGuardTests(unittest.TestCase):
    """check-profile inspects the artefact the Makefile sources with `.`."""

    def _check(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.env"
            path.write_text(text, encoding="utf-8")
            access.check_profile(path)

    def test_rendered_profile_is_accepted(self):
        """The renderer's current single-quoted form, and the older shapes."""
        self._check(
            "# Generated by render-access.py — source, do not edit.\n"
            "KAGENT_ACCESS_MODE='read-write'\n"
            "KAGENT_WRITE_NAMESPACES='kagent-lab team-a'\n"
            "KAGENT_WRITE_RESOURCES=''\n"
            "KAGENT_WRITE_REQUIRE_APPROVAL='true'\n"
            "KAGENT_LEGACY_BARE=read-only\n"
            "KAGENT_LEGACY_DOUBLE=\"kagent-lab\"\n"
        )

    def test_injection_shapes_are_refused(self):
        for line in (
            'KAGENT_WRITE_AGENT=a; rm -rf /',
            'KAGENT_WRITE_AGENT=$(id)',
            'KAGENT_WRITE_AGENT=`id`',
            'KAGENT_WRITE_AGENT="a" && id',
            "KAGENT_WRITE_AGENT='a'; id",
            "KAGENT_WRITE_AGENT='a'\"$(id)\"",
            'KAGENT_WRITE_AGENT=$IFS',
            'export KAGENT_WRITE_AGENT=a',
            'id',
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(access.AccessError, "must not be sourced"):
                    self._check("KAGENT_ACCESS_MODE=read-write\n" + line + "\n")


class MatrixTests(unittest.TestCase):
    def test_allowed_verbs_come_from_rendered_role(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "custom-tools", "namespace": "kagent-lab"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["get", "patch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list"],
                },
            ],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "custom-tools", "namespace": "kagent-lab"},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "custom-tools",
                    "namespace": "custom-write-ns",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            rbac = Path(directory) / "rbac.yaml"
            rbac.write_text(yaml.safe_dump_all([role, binding]), encoding="utf-8")
            rows = access.verification_matrix(profile(), rbac)

        allowed = {
            (row[2], row[3]) for row in rows if row[0] == "configured-allow"
        }
        self.assertEqual(allowed, {("get", "configmaps"), ("patch", "configmaps")})
        denied = [row for row in rows if row[0] == "nonconfigured-denied"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0][1], "system:serviceaccount:custom-write-ns:custom-tools")
        self.assertEqual(denied[0][2], "patch")
        self.assertNotIn(denied[0][3], profile()["write"]["resources"])
        self.assertEqual(denied[0][4:], ("no", "namespace", "kagent-lab"))

    def test_every_configured_namespace_is_tested(self):
        """The matrix must not stop at the first configured namespace."""
        docs = []
        for namespace in ("kagent-lab", "kagent-lab-2"):
            docs.append(
                {
                    "kind": "Role",
                    "metadata": {"name": "tools", "namespace": namespace},
                    "rules": [{"resources": ["configmaps"], "verbs": ["get", "patch"]}],
                }
            )
            docs.append(
                {
                    "kind": "RoleBinding",
                    "metadata": {"name": "tools", "namespace": namespace},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
                    ],
                }
            )
        raw = profile(namespaces=["kagent-lab", "kagent-lab-2"])
        original = access.ALLOWED_WRITE_NAMESPACES
        access.ALLOWED_WRITE_NAMESPACES = {"kagent-lab", "kagent-lab-2"}
        try:
            with tempfile.TemporaryDirectory() as directory:
                rbac = Path(directory) / "rbac.yaml"
                rbac.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
                rows = access.verification_matrix(raw, rbac)
        finally:
            access.ALLOWED_WRITE_NAMESPACES = original

        allowed = {row[6] for row in rows if row[0] == "configured-allow"}
        self.assertEqual(allowed, {"kagent-lab", "kagent-lab-2"})
        denied = {row[6] for row in rows if row[0] == "nonconfigured-denied"}
        self.assertEqual(denied, {"kagent-lab", "kagent-lab-2"})

    def test_missing_role_for_a_configured_namespace_is_refused(self):
        docs = [
            {
                "kind": "Role",
                "metadata": {"name": "tools", "namespace": "kagent-lab"},
                "rules": [{"resources": ["configmaps"], "verbs": ["get", "patch"]}],
            },
            {
                "kind": "RoleBinding",
                "metadata": {"name": "tools", "namespace": "kagent-lab"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
                ],
            },
        ]
        raw = profile(namespaces=["kagent-lab", "kagent-lab-2"])
        original = access.ALLOWED_WRITE_NAMESPACES
        access.ALLOWED_WRITE_NAMESPACES = {"kagent-lab", "kagent-lab-2"}
        try:
            with tempfile.TemporaryDirectory() as directory:
                rbac = Path(directory) / "rbac.yaml"
                rbac.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
                with self.assertRaisesRegex(access.AccessError, "kagent-lab-2"):
                    access.verification_matrix(raw, rbac)
        finally:
            access.ALLOWED_WRITE_NAMESPACES = original

    def test_unexpected_mutation_is_rejected(self):
        role = {
            "kind": "Role",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "rules": [
                {"resources": ["configmaps"], "verbs": ["get", "patch"]},
                {"resources": ["pods"], "verbs": ["get", "delete"]},
            ],
        }
        binding = {
            "kind": "RoleBinding",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            rbac = Path(directory) / "rbac.yaml"
            rbac.write_text(yaml.safe_dump_all([role, binding]), encoding="utf-8")
            with self.assertRaisesRegex(access.AccessError, "non-configured"):
                access.verification_matrix(profile(), rbac)

    def test_rendered_verbs_must_match_the_resource_mapping(self):
        role = {
            "kind": "Role",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "rules": [{"resources": ["configmaps"], "verbs": ["get", "patch", "delete"]}],
        }
        binding = {
            "kind": "RoleBinding",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            rbac = Path(directory) / "rbac.yaml"
            rbac.write_text(yaml.safe_dump_all([role, binding]), encoding="utf-8")
            with self.assertRaisesRegex(access.AccessError, "does not match the configured resource verbs"):
                access.verification_matrix(profile(), rbac)


# --------------------------------------------------------------------------- #
# Subprocess-level stub cluster
#
# The cleanup path depends on how kubectl and helm behave, not only on what they
# print: `auth can-i` reports a denial as exit status 1, and `helm uninstall`
# fails on an already-removed release. An in-process fake that returns strings
# cannot show either, so these stubs are real executables driven by a JSON state
# file, and the tests below run the real Runtime through them.
# --------------------------------------------------------------------------- #

STUB_KUBECTL = r'''#!/usr/bin/env python3
import json, os, pathlib, sys

state = pathlib.Path(os.environ["OK129_STUB_STATE"])
data = json.loads(state.read_text())
args = [a for a in sys.argv[1:] if not a.startswith("--kubeconfig")]
data["calls"].append(args)


def save():
    state.write_text(json.dumps(data))


def items(resource):
    return data["objects"].get(resource, [])


def matches(obj, selector):
    labels = obj.get("labels") or {}
    return all(labels.get(k) == v for k, v in (p.split("=", 1) for p in selector.split(",")))


def grants(subject, verb, resource, namespace):
    """Minimal RBAC evaluation over whatever bindings still exist."""
    for kind, role_kind in (
        ("rolebindings.rbac.authorization.k8s.io", "roles.rbac.authorization.k8s.io"),
        ("clusterrolebindings.rbac.authorization.k8s.io", "clusterroles.rbac.authorization.k8s.io"),
    ):
        for binding in items(kind):
            bound = [
                "system:serviceaccount:%s:%s" % (s.get("namespace"), s.get("name"))
                for s in binding.get("subjects") or []
                if s.get("kind") == "ServiceAccount"
            ]
            if subject not in bound:
                continue
            scope = binding.get("ns")
            if scope is not None and namespace not in (scope, None):
                continue
            for role in items(role_kind):
                if role["name"] != (binding.get("roleRef") or {}).get("name"):
                    continue
                if role.get("ns") is not None and role.get("ns") != binding.get("ns"):
                    continue
                for rule in role.get("rules") or []:
                    if verb in (rule.get("verbs") or []) and resource in (rule.get("resources") or []):
                        return True
    return False


if args[:2] == ["config", "current-context"]:
    save()
    print("ok-kagent-admin@ok-kagent")
    sys.exit(0)

if args[:2] == ["auth", "can-i"]:
    verb, resource = args[2], args[3]
    subject = next(a[len("--as="):] for a in args if a.startswith("--as="))
    namespace = None if "--all-namespaces" in args else args[args.index("--namespace") + 1]
    allowed = grants(subject, verb, resource, namespace)
    save()
    print("yes" if allowed else "no")
    # kubectl's documented contract: 0 for yes, 1 for no.
    sys.exit(0 if allowed else 1)

if args[0] == "get" and "--output" in args:
    resource = args[1]
    if resource in data["unknown_resources"]:
        save()
        sys.stderr.write('error: the server doesn\'t have a resource type "%s"\n' % resource)
        sys.exit(1)
    selector = args[args.index("--selector") + 1]
    out = []
    for obj in items(resource):
        if not matches(obj, selector):
            continue
        metadata = {"name": obj["name"]}
        if obj.get("ns"):
            metadata["namespace"] = obj["ns"]
        metadata["labels"] = obj.get("labels") or {}
        out.append(
            {
                "metadata": metadata,
                "rules": obj.get("rules") or [],
                "roleRef": obj.get("roleRef") or {},
                "subjects": obj.get("subjects") or [],
                "spec": obj.get("spec") or {},
            }
        )
    save()
    print(json.dumps({"items": out}))
    sys.exit(0)

if args[0] == "delete":
    resource, name = args[1], args[2]
    namespace = args[args.index("--namespace") + 1] if "--namespace" in args else None
    if resource == "namespace":
        resource, namespace = "namespaces", None
    data["objects"][resource] = [
        o for o in items(resource) if not (o["name"] == name and o.get("ns") == namespace)
    ]
    data["deleted"].append("%s/%s/%s" % (resource, namespace or "-", name))
    save()
    sys.exit(0)

save()
sys.exit(0)
'''

STUB_HELM = r'''#!/usr/bin/env python3
import json, os, pathlib, sys

state = pathlib.Path(os.environ["OK129_STUB_STATE"])
data = json.loads(state.read_text())
args = [a for a in sys.argv[1:] if not a.startswith("--kubeconfig")]
data["calls"].append(["helm"] + args)


def save():
    state.write_text(json.dumps(data))


if args[0] == "list":
    save()
    print(json.dumps(data["releases"]))
    sys.exit(0)

if args[0] == "uninstall":
    name = args[1]
    namespace = args[args.index("--namespace") + 1]
    remaining = [
        r for r in data["releases"] if not (r["name"] == name and r["namespace"] == namespace)
    ]
    if len(remaining) == len(data["releases"]):
        data["deleted"].append("helm-miss/%s/%s" % (namespace, name))
        save()
        # helm's real behaviour for an already-removed release.
        sys.stderr.write("Error: uninstall: Release not loaded: %s: release: not found\n" % name)
        sys.exit(1)
    data["releases"] = remaining
    data["deleted"].append("helm/%s/%s" % (namespace, name))
    save()
    sys.exit(0)

save()
sys.exit(0)
'''

MANAGED = {
    "app.kubernetes.io/part-of": "kagent-standalone",
    "app.kubernetes.io/managed-by": "render-access.py",
    "openkubes.io/ticket": "OK-129",
}
LEGACY = {
    "app.kubernetes.io/part-of": "kagent-standalone",
    "openkubes.io/ticket": "OK-129",
}
TOOLS_NS_LABELS = dict(MANAGED, **{"openkubes.io/purpose": "kagent-write-tools"})


class StubClusterTestCase(unittest.TestCase):
    """Runs the real Runtime against stub kubectl/helm executables."""

    def build(self, *, objects=None, releases=None, unknown_resources=()):
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: None)
        for name, body in (("kubectl", STUB_KUBECTL), ("helm", STUB_HELM)):
            path = Path(directory) / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        self.state = Path(directory) / "state.json"
        empty = {
            resource: []
            for resource in (
                "agents.kagent.dev",
                "remotemcpservers.kagent.dev",
                "roles.rbac.authorization.k8s.io",
                "rolebindings.rbac.authorization.k8s.io",
                "clusterroles.rbac.authorization.k8s.io",
                "clusterrolebindings.rbac.authorization.k8s.io",
                "namespaces",
            )
        }
        empty.update(objects or {})
        self.state.write_text(
            json.dumps(
                {
                    "objects": empty,
                    "releases": list(releases or []),
                    "unknown_resources": list(unknown_resources),
                    "calls": [],
                    "deleted": [],
                }
            )
        )

        previous_path = os.environ["PATH"]
        previous_state = os.environ.get("OK129_STUB_STATE")
        os.environ["PATH"] = directory + os.pathsep + previous_path
        os.environ["OK129_STUB_STATE"] = str(self.state)

        def restore():
            os.environ["PATH"] = previous_path
            if previous_state is None:
                os.environ.pop("OK129_STUB_STATE", None)
            else:
                os.environ["OK129_STUB_STATE"] = previous_state

        self.addCleanup(restore)
        return access.Runtime(Path(directory) / "kubeconfig")

    def read_state(self):
        return json.loads(self.state.read_text())


def labelled_write_profile(
    *, tool_namespace, tool_labels, release, agent, target, install_namespace="kagent"
):
    """One installed write profile, as the renderer would leave it behind."""
    subject = {"kind": "ServiceAccount", "name": release, "namespace": tool_namespace}
    return {
        "agents.kagent.dev": [
            {
                "name": agent,
                "ns": install_namespace,
                "labels": dict(MANAGED),
                "spec": {
                    "declarative": {
                        "tools": [
                            {
                                "mcpServer": {
                                    "name": release,
                                    "requireApproval": ["k8s_apply_manifest"],
                                }
                            }
                        ]
                    }
                },
            }
        ],
        "remotemcpservers.kagent.dev": [
            {"name": release, "ns": install_namespace, "labels": dict(MANAGED)}
        ],
        "roles.rbac.authorization.k8s.io": [
            {
                "name": release,
                "ns": target,
                "labels": dict(MANAGED),
                "rules": [
                    {"resources": ["configmaps"], "verbs": ["get", "patch", "delete"]}
                ],
            }
        ],
        "rolebindings.rbac.authorization.k8s.io": [
            {
                "name": release,
                "ns": target,
                "labels": dict(MANAGED),
                "roleRef": {"name": release},
                "subjects": [subject],
            }
        ],
        "namespaces": (
            [{"name": tool_namespace, "labels": dict(tool_labels)}] if tool_labels is not None else []
        ),
    }


class CanIExitCodeTests(StubClusterTestCase):
    """`kubectl auth can-i` answers a denial with exit status 1, not a failure."""

    def test_denial_is_an_answer_not_an_error(self):
        runtime = self.build()
        check = access.PermissionCheck("system:serviceaccount:x:y", "patch", "configmaps", "ns")
        self.assertFalse(runtime.can_i(check))

    def test_grant_is_reported_as_yes(self):
        runtime = self.build(
            objects=labelled_write_profile(
                tool_namespace="w",
                tool_labels=TOOLS_NS_LABELS,
                release="r",
                agent="a",
                target="t",
            )
        )
        check = access.PermissionCheck("system:serviceaccount:w:r", "patch", "configmaps", "t")
        self.assertTrue(runtime.can_i(check))

    def test_a_real_kubectl_failure_still_raises(self):
        runtime = self.build()
        broken = Path(os.environ["PATH"].split(os.pathsep)[0]) / "kubectl"
        broken.write_text(
            "#!/bin/sh\necho 'error: connection refused' >&2\nexit 1\n", encoding="utf-8"
        )
        check = access.PermissionCheck("system:serviceaccount:x:y", "patch", "configmaps", "ns")
        with self.assertRaisesRegex(access.AccessError, "connection refused"):
            runtime.can_i(check)


class CleanupAgainstStubClusterTests(StubClusterTestCase):
    def test_successful_cleanup_does_not_fail_on_the_denial_exit_code(self):
        """Regression: the revocation check must survive `can-i` exiting 1."""
        runtime = self.build(
            objects=labelled_write_profile(
                tool_namespace="legacy-write-ns",
                tool_labels=TOOLS_NS_LABELS,
                release="legacy-release",
                agent="legacy-agent",
                target="legacy-target",
            ),
            releases=[
                {"name": "legacy-release", "namespace": "legacy-write-ns", "chart": "kagent-tools-0.2.0"},
                {"name": "unrelated", "namespace": "legacy-write-ns", "chart": "redis-1.2.3"},
            ],
        )
        access.cleanup(runtime)

        deleted = self.read_state()["deleted"]
        self.assertIn("agents.kagent.dev/kagent/legacy-agent", deleted)
        self.assertIn("namespaces/-/legacy-write-ns", deleted)
        self.assertIn("helm/legacy-write-ns/legacy-release", deleted)
        self.assertNotIn("helm/legacy-write-ns/unrelated", deleted)
        # The revocation loop actually ran, through a kubectl that exits 1.
        self.assertTrue(
            any(
                call[:2] == ["auth", "can-i"]
                for call in self.read_state()["calls"]
                if isinstance(call, list)
            )
        )

    def test_surviving_permission_is_reported(self):
        objects = labelled_write_profile(
            tool_namespace="legacy-write-ns",
            tool_labels=TOOLS_NS_LABELS,
            release="legacy-release",
            agent="legacy-agent",
            target="legacy-target",
        )
        # An unlabelled ClusterRoleBinding keeps the identity's write access
        # alive, and cannot be discovered — cleanup must notice and say so.
        objects["clusterroles.rbac.authorization.k8s.io"] = [
            {
                "name": "shadow",
                "ns": None,
                "labels": {},
                "rules": [{"resources": ["configmaps"], "verbs": ["patch"]}],
            }
        ]
        objects["clusterrolebindings.rbac.authorization.k8s.io"] = [
            {
                "name": "shadow",
                "ns": None,
                "labels": {},
                "roleRef": {"name": "shadow"},
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "legacy-release",
                        "namespace": "legacy-write-ns",
                    }
                ],
            }
        ]
        runtime = self.build(objects=objects)
        with self.assertRaisesRegex(access.AccessError, "can still patch configmaps"):
            access.cleanup(runtime)

    def test_legacy_unlabelled_namespace_is_found_via_the_binding_subject(self):
        """A namespace from a run that predates the ownership labels."""
        objects = labelled_write_profile(
            tool_namespace="pre-fix-write-ns",
            tool_labels=None,  # no labels at all: invisible to the selector
            release="pre-fix-release",
            agent="pre-fix-agent",
            target="pre-fix-target",
        )
        objects["namespaces"] = [{"name": "pre-fix-write-ns", "labels": {}}]
        runtime = self.build(
            objects=objects,
            releases=[
                {
                    "name": "pre-fix-release",
                    "namespace": "pre-fix-write-ns",
                    "chart": "kagent-tools-0.2.0",
                }
            ],
        )
        access.cleanup(runtime)

        deleted = self.read_state()["deleted"]
        self.assertIn("namespaces/-/pre-fix-write-ns", deleted)
        self.assertIn("helm/pre-fix-write-ns/pre-fix-release", deleted)

    def test_release_only_candidate_is_reported_but_not_changed(self):
        """A chart-name match alone is not ownership evidence."""
        runtime = self.build(
            objects={"namespaces": [{"name": "orphan-write-ns", "labels": {}}]},
            releases=[
                {
                    "name": "orphan-release",
                    "namespace": "orphan-write-ns",
                    "chart": "kagent-tools-0.2.1",
                }
            ],
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            access.cleanup(runtime)

        deleted = self.read_state()["deleted"]
        self.assertNotIn("helm/orphan-write-ns/orphan-release", deleted)
        self.assertNotIn("namespaces/-/orphan-write-ns", deleted)
        self.assertIn("unowned kagent-tools release candidate", stderr.getvalue())
        self.assertIn("orphan-write-ns/orphan-release", stderr.getvalue())

    def test_colocated_legacy_release_is_removed_without_deleting_write_target(self):
        """Regression for the real pre-renderer state found in kagent-lab.

        The old chart release and its ServiceAccount lived in the write target
        itself. Its Role/RoleBinding had ticket/part-of labels but no managed-by
        label. Cleanup must remove the whole write path while preserving the
        namespace and its failure fixtures.
        """
        objects = labelled_write_profile(
            tool_namespace="kagent-lab",
            tool_labels=None,
            release="kagent-lab-tools",
            agent="cluster-operator-gated",
            target="kagent-lab",
        )
        for resource in (
            "agents.kagent.dev",
            "remotemcpservers.kagent.dev",
            "roles.rbac.authorization.k8s.io",
            "rolebindings.rbac.authorization.k8s.io",
        ):
            for item in objects[resource]:
                item["labels"] = dict(LEGACY)
        objects["namespaces"] = [{"name": "kagent-lab", "labels": {}}]
        # This is the dangerous historical permission observed on the cluster.
        objects["roles.rbac.authorization.k8s.io"][0]["rules"].append(
            {"resources": ["deployments"], "verbs": ["patch"]}
        )
        runtime = self.build(
            objects=objects,
            releases=[
                {
                    "name": "kagent-lab-tools",
                    "namespace": "kagent-lab",
                    "chart": "kagent-tools-0.2.1",
                }
            ],
        )

        access.cleanup(runtime)

        deleted = self.read_state()["deleted"]
        self.assertIn("helm/kagent-lab/kagent-lab-tools", deleted)
        self.assertIn(
            "rolebindings.rbac.authorization.k8s.io/kagent-lab/kagent-lab-tools",
            deleted,
        )
        self.assertIn(
            "roles.rbac.authorization.k8s.io/kagent-lab/kagent-lab-tools",
            deleted,
        )
        self.assertNotIn("namespaces/-/kagent-lab", deleted)
        self.assertTrue(
            any(
                call[:4] == ["auth", "can-i", "patch", "deployments"]
                for call in self.read_state()["calls"]
                if isinstance(call, list)
            )
        )

    def test_legacy_read_agent_is_not_mistaken_for_a_write_agent(self):
        runtime = self.build(
            objects={
                "agents.kagent.dev": [
                    {
                        "name": "cluster-inspector",
                        "ns": "kagent",
                        "labels": dict(LEGACY),
                        "spec": {
                            "declarative": {
                                "tools": [
                                    {"mcpServer": {"name": "kagent-tool-server"}}
                                ]
                            }
                        },
                    }
                ]
            }
        )

        access.cleanup(runtime)

        self.assertNotIn(
            "agents.kagent.dev/kagent/cluster-inspector",
            self.read_state()["deleted"],
        )

    def test_assert_clean_reports_legacy_rbac_after_release_is_gone(self):
        objects = labelled_write_profile(
            tool_namespace="kagent-lab",
            tool_labels=None,
            release="kagent-lab-tools",
            agent="legacy-agent",
            target="kagent-lab",
        )
        objects["agents.kagent.dev"] = []
        objects["remotemcpservers.kagent.dev"] = []
        for resource in (
            "roles.rbac.authorization.k8s.io",
            "rolebindings.rbac.authorization.k8s.io",
        ):
            objects[resource][0]["labels"] = dict(LEGACY)
        runtime = self.build(objects=objects)

        with self.assertRaisesRegex(access.AccessError, "kagent-lab-tools"):
            access.assert_clean(runtime)

    def test_assert_clean_surfaces_unowned_candidate_without_failing(self):
        runtime = self.build(
            releases=[
                {"name": "orphan", "namespace": "orphan-ns", "chart": "kagent-tools-0.2.1"}
            ]
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            access.assert_clean(runtime)
        self.assertIn("orphan-ns/orphan", stderr.getvalue())

    def test_a_vanished_release_is_not_an_error(self):
        runtime = self.build(
            objects={"namespaces": [{"name": "w", "labels": dict(TOOLS_NS_LABELS)}]},
            releases=[],
        )
        access._uninstall_release(runtime, "already-gone", "w")

    def test_missing_crds_are_tolerated(self):
        runtime = self.build(
            unknown_resources=["agents.kagent.dev", "remotemcpservers.kagent.dev"]
        )
        access.assert_clean(runtime)


class NamespaceDiscoveryTests(unittest.TestCase):
    def test_union_of_the_two_ownership_proven_discovery_paths(self):
        self.assertEqual(
            access.tool_namespaces(
                labelled=["by-label"],
                subjects={"by-subject"},
                protected=set(),
            ),
            ["by-label", "by-subject"],
        )

    def test_install_and_target_namespaces_are_never_deleted(self):
        agents = [{"metadata": {"name": "a", "namespace": "kagent"}}]
        roles = [{"metadata": {"name": "r", "namespace": "kagent-lab"}}]
        protected = access.protected_namespaces(agents, roles)
        self.assertEqual(
            access.tool_namespaces(
                labelled=["kagent", "kagent-lab", "kagent-write"],
                subjects={"kagent-lab"},
                protected=protected,
            ),
            ["kagent-write"],
        )

    def test_system_namespaces_are_never_deleted(self):
        self.assertEqual(
            access.tool_namespaces(
                labelled=["kube-system", "kube-anything", "default", "keep-me"],
                subjects=set(),
                protected=access.protected_namespaces(),
            ),
            ["keep-me"],
        )

    def test_only_the_write_tool_chart_is_matched(self):
        class OnlyHelm:
            def helm(self, args, *, capture=False):
                return json.dumps(
                    [
                        {"name": "w", "namespace": "wns", "chart": "kagent-tools-0.2.1"},
                        {"name": "read-path", "namespace": "kagent", "chart": "kagent-0.9.12"},
                        {"name": "crds", "namespace": "kagent", "chart": "kagent-crds-0.9.12"},
                        {"name": "other", "namespace": "x", "chart": "redis-1.0.0"},
                    ]
                )

        self.assertEqual(access.discover_tool_releases(OnlyHelm()), {"wns": ["w"]})

    def test_release_candidates_require_namespace_or_subject_ownership(self):
        candidates = {
            "label-owned": ["release-a"],
            "subject-owned": ["release-b", "same-chart-but-not-bound"],
            "unrelated": ["release-c"],
        }
        owned, unowned = access.classify_tool_releases(
            candidates,
            labelled_namespaces={"label-owned"},
            subject_identities={("subject-owned", "release-b")},
        )
        self.assertEqual(
            owned,
            {
                "label-owned": ["release-a"],
                "subject-owned": ["release-b"],
            },
        )
        self.assertEqual(
            unowned,
            {
                "subject-owned": ["same-chart-but-not-bound"],
                "unrelated": ["release-c"],
            },
        )


class SubjectDiscoveryTests(unittest.TestCase):
    def test_former_permissions_follow_returned_names_and_subjects(self):
        role = {
            "metadata": {"name": "old-release", "namespace": "old-target"},
            "rules": [{"resources": ["configmaps"], "verbs": ["get", "patch", "delete"]}],
        }
        binding = {
            "metadata": {"name": "old-binding", "namespace": "old-target"},
            "roleRef": {"name": "old-release"},
            "subjects": [
                {"kind": "ServiceAccount", "namespace": "old-tools-ns", "name": "old-release"}
            ],
        }
        self.assertEqual(
            access.discover_permission_checks([role], [binding], [], []),
            {
                access.PermissionCheck(
                    "system:serviceaccount:old-tools-ns:old-release",
                    "patch",
                    "configmaps",
                    "old-target",
                ),
                access.PermissionCheck(
                    "system:serviceaccount:old-tools-ns:old-release",
                    "delete",
                    "configmaps",
                    "old-target",
                ),
            },
        )

    def test_subject_namespaces_are_collected_from_both_binding_kinds(self):
        namespaced = {
            "subjects": [{"kind": "ServiceAccount", "name": "a", "namespace": "ns-a"}]
        }
        clustered = {
            "subjects": [
                {"kind": "ServiceAccount", "name": "b", "namespace": "ns-b"},
                {"kind": "User", "name": "someone"},
            ]
        }
        self.assertEqual(
            access.subject_namespaces([namespaced], [clustered]), {"ns-a", "ns-b"}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
