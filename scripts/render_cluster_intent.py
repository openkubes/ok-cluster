#!/usr/bin/env python3
"""Local create-only adapter to the owning renderer, never a full-run binder."""
import argparse
import contextlib
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from types import SimpleNamespace


def denied(*args, **kwargs):
    raise RuntimeError('network and child processes are forbidden in intent render')


def digest(path):
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    args = argparse.ArgumentParser()
    args.add_argument('--output', required=True)
    args.add_argument('--ok-linux-path', required=True)
    args.add_argument('--bind', action='store_true')
    options = args.parse_args()
    maximum = 2 * 1024 * 1024 if options.bind else 65536
    raw = sys.stdin.buffer.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('oversized intent')
    payload = json.loads(raw)
    if options.bind:
        assert set(payload) == {'intent', 'contract', 'intentRevision'}
        assert re.fullmatch(r'sha256:[0-9a-f]{64}', payload['intentRevision'])
        intent = payload['intent']
    else:
        intent = payload
    assert set(intent) == {'apiVersion', 'kind', 'metadata', 'spec'}
    assert intent['apiVersion'] == 'cli.openkubes.io/v1alpha1' and intent['kind'] == 'Cluster'
    assert set(intent['metadata']) == {'name'} and set(intent['spec']) == {'profile', 'network'}
    name = intent['metadata']['name']
    assert isinstance(name, str) and re.fullmatch(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?', name) and len(name) <= 63
    assert name != 'default' and not name.startswith('kube-')
    assert intent['spec']['profile'] == 'talos-kubevirt-mvp'
    network = intent['spec']['network']
    assert set(network) == {'endpoint', 'podCIDR', 'serviceCIDR'}
    endpoint = ipaddress.IPv4Address(network['endpoint'])
    pod, service = ipaddress.IPv4Network(network['podCIDR']), ipaddress.IPv4Network(network['serviceCIDR'])
    assert not pod.overlaps(service) and endpoint not in pod and endpoint not in service
    assert not (endpoint.is_loopback or endpoint.is_multicast or endpoint.is_unspecified or endpoint.is_link_local)
    assert str(endpoint) != '255.255.255.255'
    output = Path(options.output)
    assert output.is_absolute() and output.parent.is_dir()
    assert not output.exists() and not output.is_symlink()
    root = Path(__file__).resolve().parents[1]
    # Install guards before importing the owning implementation. Never call its
    # online resolver/allocator entry point, nor execute generated helpers.
    socket.socket = denied
    socket.create_connection = denied
    subprocess.Popen = denied
    sys.path.insert(0, str(root))
    import render
    from profile_resolvers.talos import resolve_talos_config
    render.live_metallb_allocations = denied
    render.resolve_config = denied
    config = {'name': name, 'type': 'talos', 'provider': 'kubevirt',
        'controlPlane': {'replicas': 1, 'cores': 2, 'memory': '4Gi', 'disk': '20Gi'},
        'workers': {'replicas': 1, 'cores': 2, 'memory': '4Gi', 'disk': '20Gi'},
        'versions': {'kubernetes': 'v1.34.1'}, 'network': network,
        'infraClusterSecretRef': {'name': 'external-infra-kubeconfig-' + name, 'namespace': name}}
    render.validate_registry_trust(config)
    render.validate_workload_user_namespaces(config)
    config = resolve_talos_config(config, Path(options.ok_linux_path))
    if options.bind:
        # The Go entry point already canonicalized this normalized Contract with
        # the owning versioned schema. Compare it against the actual resolved
        # recipe, never a renamed historical Candidate or copied stage receipt.
        contract = payload['contract']
        assert contract['metadata'] == {'name': name, 'namespace': name}
        spec = contract['spec']
        assert spec['kubernetesVersion'] == config['versions']['kubernetes']
        infrastructure = spec['infrastructure']
        assert infrastructure['provider'] == config['provider']
        assert infrastructure['profile'] == config['providerProfile']
        assert infrastructure['providerAccess'] == {
            'mode': 'external-cluster-secret', 'managementPlane': 'ok-mgmt', 'providerPlane': 'ok-infra',
            'secretRef': {'apiVersion': 'v1', 'kind': 'Secret', **config['infraClusterSecretRef']},
            'targetNamespace': name}
        for role in ('controlPlane', 'workers'):
            assert spec['topology'][role] == {'replicas': config[role]['replicas'],
                'machine': {k: config[role][k] for k in ('cores', 'memory', 'disk')}}
        assert spec['connectivity']['podCIDR'] == network['podCIDR']
        assert spec['connectivity']['serviceCIDR'] == network['serviceCIDR']
        os_config = config['os']
        assert spec['operatingSystem'] == {
            'distribution': os_config['distribution'], 'profile': os_config['profile'],
            'version': config['versions']['talos'], 'architecture': os_config['architecture'],
            'schematicID': os_config['schematic_id'], 'imageDigest': os_config['imageDigest'],
            'identity': os_config['identity'],
            'goldenImage': {k: os_config['goldenImage'][k] for k in ('namespace', 'claim', 'storageClass')}}
    # Resolve profile/template inputs before reserving output. Any later failure
    # retains the new directory; the next call must not replay over partial data.
    output.mkdir(mode=0o700)
    render.SCRIPT_DIR = output
    render.CLUSTERS_DIR = output
    with contextlib.redirect_stdout(io.StringIO()):
        render.render_cluster(name, output / name, config)
        if options.bind:
            render.cmd_projection(SimpleNamespace(cluster=name, intent_revision=payload['intentRevision'],
                                                  output=str(output / 'projection')))
    for path in output.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    files = {str(p.relative_to(output)): digest(p) for p in sorted(output.rglob('*')) if p.is_file()}
    receipt = {'format': 'ok-cli-cluster-intent-render/v1', 'state': 'RENDERED_NO_GO',
        'name': name, 'profile': intent['spec']['profile'], 'outputDirectory': str(output),
        'files': files, 'normalizedIntentDigest': 'sha256:' + hashlib.sha256(
            json.dumps(intent, separators=(',', ':')).encode() if options.bind else raw).hexdigest(),
        'sourceDigests': {'adapter': digest(Path(__file__).resolve()), 'renderer': digest(root / 'render.py'),
            'resolver': digest(root / 'profile_resolvers/talos.py'),
            'okLinuxProfile': digest(Path(options.ok_linux_path) / 'profiles/kubevirt/profile.yaml')},
        'apiContacted': False, 'authorizationConsumed': False, 'mutationAllowed': False,
        'runnerReady': False, 'collisionChecked': False, 'generatedHelpersExecuted': False,
        'nextAction': ('Static Contract/projection generated; full Plan/fixture/authority/credential binding is still missing.' if options.bind else
                       'Use ok up --file <cluster.yaml> --prepare --contract <reviewed-contract.yaml> --output <new-private-directory>; preparation remains incomplete until full Plan/fixture/authority/credential binding exists.') +
                      ' Do not execute generated helpers or apply these files; this is not full-run prepare or live approval.'}
    path = output / 'render-receipt.json'
    with path.open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No input/credential contents in diagnostics. Failed output is retained.
        print('Local intent render stopped: ' + type(error).__name__ + '; no replay or live action.', file=sys.stderr)
        sys.exit(2)
