#!/usr/bin/env python3
"""Read-only network proposal adapter. Allocation policy belongs to render.py.

No apply, TokenRequest, runner, reservation, lifecycle or fallback operation.
"""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAXIMUM = 8 * 1024 * 1024


def denied(*args, **kwargs):
    raise ValueError('offline network/process access forbidden')


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key)
        if name in result or name == '<<':
            raise ValueError('ambiguous inventory YAML')
        result[name] = loader.construct_object(value)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def address_ranges(values):
    ranges = []
    for value in values:
        if '/' in value:
            network = ipaddress.IPv4Network(value)
            first, last = network.network_address, network.broadcast_address
        else:
            parts = value.split('-')
            first = ipaddress.IPv4Address(parts[0])
            last = ipaddress.IPv4Address(parts[1]) if len(parts) == 2 else first
            if len(parts) > 2:
                raise ValueError('invalid endpoint range')
        if int(last) < int(first) or int(last) - int(first) > 65535:
            raise ValueError('invalid or oversized endpoint range')
        ranges.append((first, last))
    if not ranges or sum(int(last) - int(first) + 1 for first, last in ranges) > 65536:
        raise ValueError('missing or oversized endpoint pool')
    return ranges


def inventory_paths(root, managed=False):
    if not root.exists() and managed:
        return []
    if root.is_symlink() or not root.is_dir():
        raise ValueError('inventory must be an existing real directory')
    result = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        candidate = (directory / 'preparation' / directory.name / 'cluster-config.yaml'
                     if managed else directory / 'cluster-config.yaml')
        # A symlink must not hide an allocation or lead outside the inventory.
        if candidate.exists() or candidate.is_symlink():
            for parent in (directory, *candidate.relative_to(directory).parents):
                if parent == Path('.'):
                    continue
                path = parent if parent.is_absolute() else directory / parent
                if path.is_symlink():
                    raise ValueError('symlink inventory is not supported')
            if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 1024 * 1024:
                raise ValueError('invalid inventory file')
            result.append(candidate)
    return result


def propose(payload):
    online = payload['online']
    if not online:
        socket.socket = denied
        socket.create_connection = denied
        subprocess.Popen = denied
    sys.path.insert(0, str(ROOT))
    import render

    addresses, networks, sources = set(), set(), []
    name = payload['intent']['metadata']['name']

    def add_address(value):
        if value and value != 'auto':
            address = ipaddress.ip_address(value)
            if address.version == 4:
                addresses.add(str(address))

    def add_network(value):
        if value and value != 'auto':
            network = ipaddress.ip_network(value)
            if network.version == 4:
                networks.add(str(network))

    paths = inventory_paths(Path(payload['inventory']))
    if payload.get('managedRuns'):
        paths += inventory_paths(Path(payload['managedRuns']), managed=True)
    for path in sorted(set(paths)):
        raw = path.read_bytes()
        config = yaml.load(raw, Loader=UniqueLoader)
        if not isinstance(config, dict) or not isinstance(config.get('network'), dict):
            raise ValueError('incomplete local network inventory')
        if config.get('name', path.parent.name) == name:
            raise ValueError('cluster name already present in retained local inventory')
        network = config['network']
        if not all(network.get(field) and network[field] != 'auto'
                   for field in ('endpoint', 'podCIDR', 'serviceCIDR')):
            raise ValueError('unresolved local network inventory')
        add_address(network['endpoint'])
        add_network(network['podCIDR'])
        add_network(network['serviceCIDR'])
        sources.append({'kind': 'local-cluster-config', 'path': str(path), 'digest': digest(raw)})

    def query(plane, resource):
        reference = payload['intent']['spec'][plane]
        # Context is selected locally by the CLI; never rely on current-context,
        # KUBECONFIG, shell interpolation, a default API or a saved credential.
        # Spool public resource lists privately instead of buffering an
        # unbounded subprocess response (or any credential-bearing stderr).
        with tempfile.TemporaryFile() as snapshot:
            subprocess.run(['kubectl', '--kubeconfig', reference['kubeconfig'],
                '--context', reference['context'], 'get', resource, '-A', '-o', 'json',
                '--request-timeout=10s'], stdout=snapshot, stderr=subprocess.DEVNULL,
                timeout=20, check=True)
            snapshot.seek(0)
            raw = snapshot.read(MAXIMUM + 1)
        if len(raw) > MAXIMUM:
            raise ValueError('oversized API snapshot')
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            raise ValueError('invalid API list')
        sources.append({'kind': 'api-list', 'plane': plane, 'resource': resource,
                        'digest': digest(raw), 'count': len(data['items'])})
        return data['items']

    selected_pool = None
    if online:
        # Standard kubectl authentication may run executables or renew cached
        # credentials. This proposal boundary deliberately permits neither.
        # Check BOTH selected users before opening either API.
        for plane in ('management', 'infrastructure'):
            reference = payload['intent']['spec'][plane]
            raw = Path(reference['kubeconfig']).read_bytes()
            if len(raw) > 1024 * 1024:
                raise ValueError('oversized kubeconfig')
            config = yaml.load(raw, Loader=UniqueLoader)
            contexts = [item for item in config['contexts'] if item['name'] == reference['context']]
            if len(contexts) != 1:
                raise ValueError('selected context changed')
            users = [item for item in config['users'] if item['name'] == contexts[0]['context']['user']]
            if len(users) != 1 or any(key in users[0].get('user', {}) for key in ('exec', 'auth-provider')):
                raise ValueError('online proposals require existing static credentials, not auth plugins')
        for plane in ('management', 'infrastructure'):
            for item in query(plane, 'services'):
                spec = item.get('spec', {})
                add_address(spec.get('loadBalancerIP'))
                for ingress in (item.get('status', {}).get('loadBalancer', {}) or {}).get('ingress', []) or []:
                    add_address(ingress.get('ip'))
                for address in spec.get('clusterIPs', []) or []:
                    if address != 'None':
                        add_address(address)
            for item in query(plane, 'clusters.cluster.x-k8s.io'):
                if item.get('metadata', {}).get('name') == name:
                    raise ValueError('cluster name already present in API snapshot')
                spec = item.get('spec', {})
                host = spec.get('controlPlaneEndpoint', {}).get('host')
                if host:
                    try:
                        add_address(host)
                    except ValueError:
                        # DNS endpoints are not evidence that an IPv4 is unused.
                        raise ValueError('DNS CAPI endpoint requires separate address inventory')
                cluster_network = spec.get('clusterNetwork', {}) or {}
                for role in ('pods', 'services'):
                    for network in (cluster_network.get(role, {}) or {}).get('cidrBlocks', []) or []:
                        add_network(network)
        pools = query('infrastructure', 'ipaddresspools.metallb.io')
        eligible = []
        for pool in pools:
            identity = pool['metadata']['namespace'] + '/' + pool['metadata']['name']
            if payload['pool'] and identity != payload['pool']:
                continue
            spec = pool['spec']
            if spec.get('serviceAllocation'):
                # Namespace/service selectors and priorities need an explicit
                # consumer-aware contract; do not guess their applicability.
                continue
            if not payload['pool'] and spec.get('autoAssign') is False:
                continue
            values = [value for value in spec['addresses'] if ':' not in value]
            if values:
                eligible.append((identity, spec, address_ranges(values)))
        if len(eligible) != 1:
            candidates = ', '.join(item[0] for item in eligible) or 'none (missing, IPv6-only or selector-constrained)'
            raise ValueError('select exactly one applicable IPv4 MetalLB pool with --pool namespace/name; candidates: ' + candidates)
        selected_pool, spec, ranges = eligible[0]
        if spec.get('avoidBuggyIPs'):
            for first, last in ranges:
                for number in range(int(first), int(last) + 1):
                    if number % 256 in (0, 255):
                        addresses.add(str(ipaddress.IPv4Address(number)))
    else:
        ranges = address_ranges([payload['endpointPool']])

    network = render.suggest_network(ranges, addresses, networks)
    return {'format': 'ok-cli-network-proposal/v1', 'state': 'PROPOSED_NOT_RESERVED',
        'name': name, 'before': payload['intent']['spec']['network'], 'proposedNetwork': network,
        'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'endpointPoolSource': selected_pool or 'explicit-offline-range',
        'endpointRanges': [str(first) + '-' + str(last) for first, last in ranges],
        'podPool': str(render.POD_CIDR_POOL), 'servicePool': str(render.SERVICE_CIDR_POOL),
        'inventoryRoots': [payload['inventory']] + ([payload['managedRuns']] if payload.get('managedRuns') else []),
        'policySourceDigests': {'renderer': digest((ROOT / 'render.py').read_bytes()),
                               'adapter': digest(Path(__file__).read_bytes())},
        'sources': sources, 'targets': payload.get('targets'),
        'apiContacted': online, 'observedCollisionCheckCompleted': online,
        'globalAvailabilityProven': False, 'reservationCreated': False,
        'authorizationConsumed': False, 'mutationAllowed': False, 'runnerReady': False,
        'limitations': ['Only listed inventories and snapshots are covered; DHCP, external hosts, DNS, '
                        'untracked preparations and other management planes are not reserved or proven absent.',
                        'Snapshots may race with other creators. Recheck before authorized execution.',
                        'Offline proposals use local inventory only; they are not live collision evidence.'],
        'nextAction': 'Review proposed network and source coverage; use --output for a NEW YAML, '
                      'then prepare separately reviewed Contract/runtime authorities for that exact intent.'}


def main():
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError('oversized proposal request')
    print(json.dumps(propose(json.loads(raw))))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No kubectl output, kubeconfig contents or credential diagnostics.
        message = str(error) if type(error) is ValueError else type(error).__name__
        print('Network proposal stopped: ' + message + '; no fallback or live execution.', file=sys.stderr)
        sys.exit(2)
