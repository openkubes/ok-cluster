#!/usr/bin/env python3
"""OK-129-specific access validation, verification data, and cleanup.

The generic access renderer deliberately supports more profiles than the
evidenced OK-129 lab.  This installer-side guard narrows that generic schema to
the capability actually exercised here: approval-gated ConfigMap changes in
the kagent-lab namespace.

Verification expectations are derived from the rendered RBAC rules.  Cleanup
discovers managed objects by stable labels and uses their returned names, so it
does not depend on a newly rendered profile or historical defaults.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


MANAGED_SELECTOR = (
    "app.kubernetes.io/managed-by=render-access.py,openkubes.io/ticket=OK-129"
)
TOOLS_NAMESPACE_SELECTOR = MANAGED_SELECTOR + ",openkubes.io/purpose=kagent-write-tools"
ALLOWED_WRITE_NAMESPACES = {"kagent-lab"}
ALLOWED_WRITE_RESOURCES = {"configmaps"}
READ_VERBS = {"get", "list", "watch"}

# Only the standalone write tool server uses this chart. The read path ships
# kagent-tools as a subchart of the `kagent` release, whose chart is kagent-*,
# so this prefix cannot match the read path.
TOOLS_CHART_PREFIX = "kagent-tools-"

# Namespaces cleanup must never delete, whatever a label or release claims.
NEVER_DELETE_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease"}
NEVER_DELETE_PREFIXES = ("kube-",)

# RFC 1123 label. Every name that reaches profile.env — and from there a shell —
# must match this, so the sourced file cannot carry shell syntax.
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

# The only shape a generated profile.env line may have: an upper-case key and a
# bare, single- or double-quoted value built from DNS-safe characters and spaces.
# No command substitution, no expansion, no metacharacters. Single quotes are the
# renderer's current form and the strongest one — nothing expands inside them.
PROFILE_LINE = re.compile(
    r"^[A-Z][A-Z0-9_]*=(?:'[a-zA-Z0-9 ._:-]*'|\"[a-zA-Z0-9 ._:-]*\"|[a-zA-Z0-9._:-]*)$"
)


class AccessError(RuntimeError):
    """A fail-closed validation, discovery, or verification error."""


def load_config(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AccessError(f"access config not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise AccessError(f"invalid access config YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise AccessError("access config must be a YAML mapping")
    return raw


def validate_ok129(raw: dict[str, Any]) -> None:
    """Refuse every write capability not evidenced by OK-129."""
    mode = raw.get("mode")
    if mode not in {"read-only", "read-write"}:
        raise AccessError("mode must be read-only or read-write")

    write = raw.get("write") or {}
    if not isinstance(write, dict):
        raise AccessError("write must be a mapping")
    if not write:
        if mode == "read-write":
            raise AccessError("write is required in read-write mode")
        return

    scope = write.get("scope")
    namespaces = write.get("namespaces")
    resources = write.get("resources")
    approval = write.get("requireApproval")

    if scope != "namespaces":
        raise AccessError(
            "OK-129 only supports write.scope=namespaces; cluster scope is not evidenced"
        )
    expected_namespaces = sorted(ALLOWED_WRITE_NAMESPACES)
    if namespaces != expected_namespaces:
        raise AccessError(
            "OK-129 write.namespaces must be exactly: "
            + ", ".join(sorted(ALLOWED_WRITE_NAMESPACES))
        )
    expected_resources = sorted(ALLOWED_WRITE_RESOURCES)
    if resources != expected_resources:
        raise AccessError(
            "OK-129 write.resources must be exactly: "
            + ", ".join(sorted(ALLOWED_WRITE_RESOURCES))
        )
    if approval is not True:
        raise AccessError("OK-129 requires write.requireApproval=true")

    _validate_sourced_names(write)


def _validate_sourced_names(write: dict[str, Any]) -> None:
    """Constrain every name that ends up in profile.env, which a shell sources.

    The generic renderer validates its namespace fields but not the release or
    Agent name, and the Makefile sources the generated profile.env. Anything
    that is not a plain DNS label is refused here, before a render exists.
    """
    tool_server = write.get("toolServer") or {}
    if not isinstance(tool_server, dict):
        raise AccessError("write.toolServer must be a mapping")

    for field, value in (
        ("write.toolServer.namespace", tool_server.get("namespace")),
        ("write.toolServer.releaseName", tool_server.get("releaseName")),
        ("write.agentName", write.get("agentName")),
    ):
        if value is None:
            raise AccessError(f"{field} is required")
        if not isinstance(value, str) or not DNS_LABEL.match(value):
            raise AccessError(
                f"{field} must be a plain DNS-1123 label (a-z, 0-9, '-'); got {value!r}. "
                "This name is written to profile.env, which the installer sources."
            )

    for field, value in (
        ("write.toolServer.port", tool_server.get("port")),
        ("write.toolServer.metricsPort", tool_server.get("metricsPort")),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
            raise AccessError(f"{field} must be an integer between 1 and 65535; got {value!r}")


def check_profile(path: Path) -> None:
    """Assert the generated profile.env is safe to `.` from a shell.

    validate_ok129 constrains the config, but this checks the artefact that is
    actually sourced, so a renderer change cannot reintroduce shell syntax
    without failing here first.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AccessError(f"profile not found: {path}") from exc

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not PROFILE_LINE.match(stripped):
            raise AccessError(
                f"{path}:{number} is not a plain assignment and must not be sourced: {line!r}"
            )


def yaml_documents(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    return [doc for doc in docs if isinstance(doc, dict)]


def _matrix_row(
    label: str,
    subject: str,
    verb: str,
    resource: str,
    expected: str,
    scope: str,
    namespace: str = "-",
) -> tuple[str, ...]:
    fields = (label, subject, verb, resource, expected, scope, namespace)
    if any("\t" in field or "\n" in field for field in fields):
        raise AccessError("verification matrix fields may not contain tabs or newlines")
    return fields


def _declared_verbs(
    docs: list[dict[str, Any]], namespace: str, resources: set[str]
) -> dict[str, set[str]]:
    """Read the verbs the rendered Role actually grants in one namespace."""
    roles = [
        doc
        for doc in docs
        if doc.get("kind") == "Role"
        and (doc.get("metadata") or {}).get("namespace") == namespace
    ]
    if len(roles) != 1:
        raise AccessError(
            f"expected exactly one rendered Role in {namespace}, found {len(roles)}"
        )

    declared: dict[str, set[str]] = {resource: set() for resource in resources}
    nonconfigured_mutating: set[str] = set()
    for rule in roles[0].get("rules") or []:
        verbs = {str(verb) for verb in (rule.get("verbs") or [])}
        for resource in (str(value) for value in (rule.get("resources") or [])):
            if resource in declared:
                declared[resource].update(verbs)
            elif verbs - READ_VERBS:
                nonconfigured_mutating.add(resource)

    missing = sorted(resource for resource, verbs in declared.items() if not verbs)
    if missing:
        raise AccessError(
            f"rendered Role in {namespace} has no rules for configured resource(s): "
            + ", ".join(missing)
        )
    if nonconfigured_mutating:
        raise AccessError(
            f"rendered Role in {namespace} grants mutations to non-configured resource(s): "
            + ", ".join(sorted(nonconfigured_mutating))
        )
    return declared


def _rendered_writer(docs: list[dict[str, Any]], namespace: str) -> str:
    """The ServiceAccount identity the rendered RoleBinding actually binds."""
    for binding in docs:
        if binding.get("kind") != "RoleBinding":
            continue
        if (binding.get("metadata") or {}).get("namespace") != namespace:
            continue
        service_accounts = [
            item
            for item in (binding.get("subjects") or [])
            if item.get("kind") == "ServiceAccount"
        ]
        if len(service_accounts) == 1:
            subject = service_accounts[0]
            return (
                "system:serviceaccount:"
                f"{subject.get('namespace')}:{subject.get('name')}"
            )
    raise AccessError(f"rendered RBAC has no ServiceAccount subject in {namespace}")


def verification_matrix(
    raw: dict[str, Any], rbac_path: Path
) -> list[tuple[str, ...]]:
    """Build executable checks from the rendered policy rules."""
    validate_ok129(raw)
    install_ns = str((raw.get("install") or {}).get("namespace", "kagent"))
    reader = f"system:serviceaccount:{install_ns}:kagent-tools"
    rows = [
        _matrix_row("reader-read", reader, "get", "pods", "yes", "all-namespaces"),
        _matrix_row("reader-write-denied", reader, "patch", "deployments", "no", "all-namespaces"),
        _matrix_row(
            "reader-delete-denied",
            reader,
            "delete",
            "deployments",
            "no",
            "all-namespaces",
        ),
        _matrix_row("reader-secrets-denied", reader, "get", "secrets", "no", "all-namespaces"),
        _matrix_row("reader-wildcard-denied", reader, "*", "*", "no", "all-namespaces"),
    ]
    if raw.get("mode") == "read-only":
        return rows

    write = raw["write"]
    namespaces = [str(value) for value in write["namespaces"]]
    resources = set(write["resources"])
    docs = yaml_documents(rbac_path)
    writers: set[str] = set()

    for namespace in namespaces:
        declared = _declared_verbs(docs, namespace, resources)
        writer = _rendered_writer(docs, namespace)
        writers.add(writer)

        mutating_verbs: set[str] = set()
        for resource in sorted(declared):
            for verb in sorted(declared[resource]):
                rows.append(
                    _matrix_row(
                        "configured-allow", writer, verb, resource, "yes", "namespace", namespace
                    )
                )
                rows.append(
                    _matrix_row(
                        "outside-scope-denied",
                        writer,
                        verb,
                        resource,
                        "no",
                        "namespace",
                        install_ns,
                    )
                )
                if verb not in READ_VERBS:
                    mutating_verbs.add(verb)

        for verb in sorted(mutating_verbs):
            rows.append(
                _matrix_row(
                    "nonconfigured-denied",
                    writer,
                    verb,
                    "deployments",
                    "no",
                    "namespace",
                    namespace,
                )
            )

    if len(writers) != 1:
        raise AccessError(
            "rendered RBAC binds more than one write identity: " + ", ".join(sorted(writers))
        )
    writer = writers.pop()
    rows.extend(
        [
            _matrix_row("writer-secrets-denied", writer, "get", "secrets", "no", "all-namespaces"),
            _matrix_row(
                "writer-rbac-denied",
                writer,
                "create",
                "rolebindings",
                "no",
                "all-namespaces",
            ),
            _matrix_row("writer-wildcard-denied", writer, "*", "*", "no", "all-namespaces"),
        ]
    )
    return rows


def write_matrix(raw: dict[str, Any], rbac_path: Path, out_path: Path) -> None:
    rows = verification_matrix(raw, rbac_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join("\t".join(row) for row in rows) + "\n"
    out_path.write_text(text, encoding="utf-8")


@dataclass(frozen=True)
class PermissionCheck:
    subject: str
    verb: str
    resource: str
    namespace: str | None


class Runtime:
    def __init__(self, kubeconfig: Path):
        self.kubeconfig = str(kubeconfig)

    def run(self, argv: list[str], *, capture: bool = False) -> str:
        completed = subprocess.run(
            argv,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        return completed.stdout if capture else ""

    def kubectl(self, args: list[str], *, capture: bool = False) -> str:
        return self.run(["kubectl", f"--kubeconfig={self.kubeconfig}", *args], capture=capture)

    def helm(self, args: list[str], *, capture: bool = False) -> str:
        return self.run(["helm", f"--kubeconfig={self.kubeconfig}", *args], capture=capture)

    def can_i(self, check: PermissionCheck) -> bool:
        """Answer one `kubectl auth can-i`, honouring its exit-code contract.

        `auth can-i` reports a denial as exit status 1 — that is its documented
        interface, not a failure. Running it through a checked subprocess would
        raise on exactly the answer a revocation check wants to see, so this
        never uses check=True: the printed answer decides, and the exit status
        is only used to tell a real error apart from a denial.
        """
        argv = [
            "kubectl",
            f"--kubeconfig={self.kubeconfig}",
            "auth",
            "can-i",
            check.verb,
            check.resource,
            f"--as={check.subject}",
        ]
        if check.namespace is None:
            argv.append("--all-namespaces")
        else:
            argv += ["--namespace", check.namespace]

        completed = subprocess.run(
            argv, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        lines = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
        answer = lines[-1] if lines else ""
        if answer in {"yes", "no"} and completed.returncode in {0, 1}:
            return answer == "yes"
        raise AccessError(
            f"kubectl auth can-i {check.verb} {check.resource} --as={check.subject} "
            f"failed (exit {completed.returncode}): "
            + ((completed.stderr or "").strip() or answer or "no output")
        )

    def get_json(
        self,
        resource: str,
        *,
        all_namespaces: bool = False,
        selector: str = MANAGED_SELECTOR,
    ) -> dict[str, Any]:
        args = ["get", resource]
        if all_namespaces:
            args.append("--all-namespaces")
        args += ["--selector", selector, "--output", "json"]
        try:
            return json.loads(self.kubectl(args, capture=True))
        except subprocess.CalledProcessError as exc:
            message = (exc.stderr or "").lower()
            if (
                "doesn't have a resource type" in message
                or "could not find the requested resource" in message
            ):
                return {"items": []}
            raise AccessError((exc.stderr or str(exc)).strip()) from exc


def _items(document: dict[str, Any]) -> list[dict[str, Any]]:
    values = document.get("items") or []
    return [value for value in values if isinstance(value, dict)]


def _name(item: dict[str, Any]) -> str:
    return str((item.get("metadata") or {}).get("name", ""))


def _namespace(item: dict[str, Any]) -> str:
    return str((item.get("metadata") or {}).get("namespace", ""))


def discover_permission_checks(
    roles: Iterable[dict[str, Any]],
    bindings: Iterable[dict[str, Any]],
    cluster_roles: Iterable[dict[str, Any]],
    cluster_bindings: Iterable[dict[str, Any]],
) -> set[PermissionCheck]:
    role_map = {(_namespace(role), _name(role)): role for role in roles}
    cluster_role_map = {_name(role): role for role in cluster_roles}
    checks: set[PermissionCheck] = set()

    def add(binding: dict[str, Any], role: dict[str, Any] | None, namespace: str | None) -> None:
        if role is None:
            return
        subjects = binding.get("subjects") or []
        for subject in subjects:
            if subject.get("kind") != "ServiceAccount":
                continue
            identity = (
                "system:serviceaccount:"
                f"{subject.get('namespace')}:{subject.get('name')}"
            )
            for rule in role.get("rules") or []:
                for verb in rule.get("verbs") or []:
                    if verb in READ_VERBS:
                        continue
                    for resource in rule.get("resources") or []:
                        checks.add(PermissionCheck(identity, str(verb), str(resource), namespace))

    for binding in bindings:
        ref = binding.get("roleRef") or {}
        namespace = _namespace(binding)
        add(binding, role_map.get((namespace, str(ref.get("name", "")))), namespace)
    for binding in cluster_bindings:
        ref = binding.get("roleRef") or {}
        add(binding, cluster_role_map.get(str(ref.get("name", ""))), None)
    return checks


def _delete_namespaced(runtime: Runtime, resource: str, objects: Iterable[dict[str, Any]]) -> None:
    for item in objects:
        runtime.kubectl(
            [
                "delete",
                resource,
                _name(item),
                "--namespace",
                _namespace(item),
                "--ignore-not-found",
            ]
        )


def _delete_cluster(runtime: Runtime, resource: str, objects: Iterable[dict[str, Any]]) -> None:
    for item in objects:
        runtime.kubectl(["delete", resource, _name(item), "--ignore-not-found"])


def assert_clean(runtime: Runtime) -> None:
    leftovers: list[str] = []
    for resource, all_namespaces in (
        ("agents.kagent.dev", True),
        ("remotemcpservers.kagent.dev", True),
        ("roles.rbac.authorization.k8s.io", True),
        ("rolebindings.rbac.authorization.k8s.io", True),
        ("clusterroles.rbac.authorization.k8s.io", False),
        ("clusterrolebindings.rbac.authorization.k8s.io", False),
        ("namespaces", False),
    ):
        selector = TOOLS_NAMESPACE_SELECTOR if resource == "namespaces" else MANAGED_SELECTOR
        document = runtime.get_json(
            resource, all_namespaces=all_namespaces, selector=selector
        )
        for item in _items(document):
            location = f"{_namespace(item)}/" if _namespace(item) else ""
            leftovers.append(f"{resource}/{location}{_name(item)}")

    # Label-independent: a write tool server from a run that predates the
    # ownership labels has no label to select on, but it still has a release.
    for namespace, names in sorted(discover_tool_releases(runtime).items()):
        for name in sorted(names):
            leftovers.append(f"helm-release/{namespace}/{name}")

    if leftovers:
        raise AccessError("managed write objects remain: " + ", ".join(sorted(leftovers)))


def subject_namespaces(
    bindings: Iterable[dict[str, Any]], cluster_bindings: Iterable[dict[str, Any]]
) -> set[str]:
    """Namespaces that host a bound write ServiceAccount.

    A tool-server namespace created before the manifests carried ownership
    labels is invisible to a label selector, but the RoleBinding that granted it
    permissions names it in its subject. That is a second, independent path to
    the same namespace.
    """
    found: set[str] = set()
    for binding in (*bindings, *cluster_bindings):
        for subject in binding.get("subjects") or []:
            if subject.get("kind") != "ServiceAccount":
                continue
            namespace = str(subject.get("namespace") or "")
            if namespace:
                found.add(namespace)
    return found


def discover_tool_releases(runtime: Runtime) -> dict[str, list[str]]:
    """Namespace -> write tool-server release names, found by chart name.

    Third path to a legacy namespace: even with every label and RoleBinding
    already gone, the Helm release itself still identifies where the write tool
    server lives.
    """
    raw = runtime.helm(["list", "--all-namespaces", "--output", "json"], capture=True)
    releases = json.loads(raw.strip() or "[]")
    found: dict[str, list[str]] = {}
    for release in releases:
        if not str(release.get("chart", "")).startswith(TOOLS_CHART_PREFIX):
            continue
        namespace = str(release.get("namespace") or "")
        name = str(release.get("name") or "")
        if namespace and name:
            found.setdefault(namespace, []).append(name)
    return found


def protected_namespaces(*object_groups: Iterable[dict[str, Any]]) -> set[str]:
    """Namespaces cleanup must never delete.

    The install namespace (it hosts the Agent and RemoteMCPServer) and the write
    targets (they host the Roles and RoleBindings, and are owned by the read
    path) are derived from the discovered objects themselves rather than named,
    so a renamed profile keeps the same protection.
    """
    protected = set(NEVER_DELETE_NAMESPACES)
    for group in object_groups:
        for item in group:
            namespace = _namespace(item)
            if namespace:
                protected.add(namespace)
    return protected


def tool_namespaces(
    labelled: Iterable[str],
    subjects: Iterable[str],
    releases: Iterable[str],
    protected: Iterable[str],
) -> list[str]:
    """The union of all three discovery paths, minus what must never be deleted."""
    blocked = set(protected)
    candidates = {*labelled, *subjects, *releases}
    return sorted(
        namespace
        for namespace in candidates
        if namespace
        and namespace not in blocked
        and not namespace.startswith(NEVER_DELETE_PREFIXES)
    )


def _uninstall_release(runtime: Runtime, name: str, namespace: str) -> None:
    """Remove one Helm release, tolerating a release that vanished meanwhile.

    `helm uninstall` exits non-zero when the release is already gone, which is
    the desired end state, not a failure.
    """
    try:
        runtime.helm(
            ["uninstall", name, "--namespace", namespace, "--wait", "--timeout", "5m"],
            capture=True,
        )
    except subprocess.CalledProcessError as exc:
        message = ((exc.stderr or "") + (exc.stdout or "")).lower()
        if "not found" not in message:
            raise AccessError((exc.stderr or str(exc)).strip()) from exc


def cleanup(runtime: Runtime) -> None:
    agents = _items(runtime.get_json("agents.kagent.dev", all_namespaces=True))
    servers = _items(runtime.get_json("remotemcpservers.kagent.dev", all_namespaces=True))
    roles = _items(runtime.get_json("roles.rbac.authorization.k8s.io", all_namespaces=True))
    bindings = _items(
        runtime.get_json("rolebindings.rbac.authorization.k8s.io", all_namespaces=True)
    )
    cluster_roles = _items(runtime.get_json("clusterroles.rbac.authorization.k8s.io"))
    cluster_bindings = _items(runtime.get_json("clusterrolebindings.rbac.authorization.k8s.io"))
    labelled = _items(runtime.get_json("namespaces", selector=TOOLS_NAMESPACE_SELECTOR))

    # Everything is discovered before anything is deleted: the RoleBinding
    # subjects and the rules are the only record of where the write identity
    # lived and what it could do.
    permission_checks = discover_permission_checks(
        roles, bindings, cluster_roles, cluster_bindings
    )
    tool_releases = discover_tool_releases(runtime)
    targets = tool_namespaces(
        labelled=[_name(item) for item in labelled],
        subjects=subject_namespaces(bindings, cluster_bindings),
        releases=tool_releases.keys(),
        protected=protected_namespaces(agents, servers, roles, bindings),
    )

    _delete_namespaced(runtime, "agents.kagent.dev", agents)
    _delete_namespaced(runtime, "remotemcpservers.kagent.dev", servers)
    _delete_namespaced(runtime, "rolebindings.rbac.authorization.k8s.io", bindings)
    _delete_cluster(runtime, "clusterrolebindings.rbac.authorization.k8s.io", cluster_bindings)
    _delete_namespaced(runtime, "roles.rbac.authorization.k8s.io", roles)
    _delete_cluster(runtime, "clusterroles.rbac.authorization.k8s.io", cluster_roles)

    for namespace in targets:
        for name in sorted(tool_releases.get(namespace, [])):
            _uninstall_release(runtime, name, namespace)
        runtime.kubectl(
            [
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=3m",
            ]
        )

    assert_clean(runtime)
    failures: list[str] = []
    for check in sorted(
        permission_checks,
        key=lambda value: (value.subject, value.namespace or "", value.resource, value.verb),
    ):
        if runtime.can_i(check):
            failures.append(
                f"{check.subject} can still {check.verb} {check.resource} "
                f"in {check.namespace or 'all namespaces'}"
            )
    if failures:
        raise AccessError("cleanup left former write permissions: " + "; ".join(failures))


def git_value(repo: Path, args: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise AccessError((exc.stderr or str(exc)).strip()) from exc


def evidence(
    ok_cluster: Path,
    openkubes: Path,
    config: Path,
    out: Path,
    kagent_version: str,
    tools_version: str,
    result: str,
) -> None:
    data = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "result": result,
        "ok_cluster_commit": git_value(ok_cluster, ["rev-parse", "HEAD"]),
        "ok_cluster_dirty": bool(git_value(ok_cluster, ["status", "--porcelain"])),
        "openkubes_assets_commit": git_value(openkubes, ["rev-parse", "HEAD"]),
        "openkubes_assets_dirty": bool(git_value(openkubes, ["status", "--porcelain"])),
        "access_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "versions": {
            "kagent_chart": kagent_version,
            "kagent_tools_chart": tools_version,
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--config", required=True, type=Path)

    matrix_parser = subparsers.add_parser("matrix")
    matrix_parser.add_argument("--config", required=True, type=Path)
    matrix_parser.add_argument("--rbac", required=True, type=Path)
    matrix_parser.add_argument("--out", required=True, type=Path)

    profile_parser = subparsers.add_parser("check-profile")
    profile_parser.add_argument("--profile", required=True, type=Path)

    for name in ("cleanup", "assert-clean"):
        runtime_parser = subparsers.add_parser(name)
        runtime_parser.add_argument("--kubeconfig", required=True, type=Path)

    evidence_parser = subparsers.add_parser("evidence")
    evidence_parser.add_argument("--ok-cluster", required=True, type=Path)
    evidence_parser.add_argument("--openkubes", required=True, type=Path)
    evidence_parser.add_argument("--config", required=True, type=Path)
    evidence_parser.add_argument("--out", required=True, type=Path)
    evidence_parser.add_argument("--kagent-version", required=True)
    evidence_parser.add_argument("--tools-version", required=True)
    evidence_parser.add_argument("--result", default="OBSERVED")

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            validate_ok129(load_config(args.config))
        elif args.command == "matrix":
            raw = load_config(args.config)
            write_matrix(raw, args.rbac, args.out)
        elif args.command == "check-profile":
            check_profile(args.profile)
        elif args.command == "cleanup":
            cleanup(Runtime(args.kubeconfig))
        elif args.command == "assert-clean":
            assert_clean(Runtime(args.kubeconfig))
        elif args.command == "evidence":
            evidence(
                args.ok_cluster,
                args.openkubes,
                args.config,
                args.out,
                args.kagent_version,
                args.tools_version,
                args.result,
            )
    except (AccessError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
