# Ingress — `make install-ingress`

> **Contract:** `ingressClassName: ok-ingress` · hostname `<app>.<cluster>.internal` · one IP from `ok-pool` per cluster
>
> Defined in [ADR-Platform-010](../openkubes/architecture/decisions/ADR-Platform-010-ingress-contract.md)

## What it does

`make install-ingress CLUSTER=<name>` sets up HTTP(S) ingress for a Talos guest cluster in two steps:

1. **Traefik** — deployed as a NodePort in the guest cluster (`ingress` namespace, ports 30080/30443, IngressClass `ok-ingress`).
2. **Host-cluster proxy Service** — a `LoadBalancer` Service created in the cluster's namespace on the RKE2 host cluster. MetalLB assigns one IP from `ok-pool` (`192.168.100.200–209`). It forwards `:80 → 30080` and `:443 → 30443` into the KubeVirt `virt-launcher` pods.

## Traffic path

```
client
  → 192.168.100.20X:80          (MetalLB on RKE2 host cluster)
  → virt-launcher pod:30080     (KubeVirt — bridges host network → VM eth0)
  → Traefik NodePort            (inside Talos guest cluster)
  → Ingress routing             (ingressClassName: ok-ingress)
  → app ClusterIP Service
  → app pod
```

### Why this design?

Talos VMs deployed by CAPK (Cluster API Provider KubeVirt) have a **single `eth0`** in the Cilium overlay (`10.44.x.x`). They have no direct interface on the vSwitch (`192.168.100.0/24`), so Cilium LB-IPAM + L2 Announcements cannot ARP-announce an IP on the host network.

The host-proxy pattern reuses the same mechanism as the CAPI-managed control-plane LB (`<cluster>-lb`): MetalLB on RKE2 announces the IP, traffic flows through the `virt-launcher` Pod into the VM. No Multus, no L2 Announcements, no additional networking components required.

## Usage

```bash
# Install Traefik + host proxy Service
make install-ingress CLUSTER=ok1-talos

# Output:
# ✅ Ingress ready for ok1-talos
#    Entry point : 192.168.100.203
#    Traffic path: client → 192.168.100.203:80 → virt-launcher:30080 → Traefik → <app>.ok1-talos.internal
#    Contract    : ingressClassName: ok-ingress, hostname <app>.ok1-talos.internal
#    Interim DNS : echo "192.168.100.203 <app>.ok1-talos.internal" | sudo tee -a /etc/hosts
```

## Deploying an application

Any app Ingress must set `ingressClassName: ok-ingress` — the class is **not** the default.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  namespace: my-ns
spec:
  ingressClassName: ok-ingress
  rules:
    - host: my-app.ok1-talos.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-app
                port:
                  number: 80
```

## DNS

Until `ok-dns` / dnsmasq on `ok-vpn` is set up (follow-up), resolve hostnames manually:

```bash
# Interim: /etc/hosts
echo "192.168.100.203 my-app.ok1-talos.internal" | sudo tee -a /etc/hosts
```

Permanent solution: dnsmasq on `ok-vpn` (`167.233.52.138`) with `address=/.ok1-talos.internal/192.168.100.203`.

## IP allocation

| Resource | IP range | Managed by |
|---|---|---|
| `ok-pool` (host MetalLB) | `192.168.100.200–209` | MetalLB on RKE2 |
| Guest cluster endpoints (CAPI) | `.200`, `.201`, ... | MetalLB on RKE2 |
| Guest cluster ingress (this) | next free in `.200–.209` | MetalLB on RKE2 |

One IP per cluster with ingress installed (~3 IPs in use, pool has 10 total — no pressure).

## Future: Cilium Gateway API (v2, OK-57)

Once OK-57 adds Multus NADs to CAPK Machine Templates (second vSwitch NIC per VM), Talos nodes will have a `192.168.100.x` address. This enables:

- Cilium LB-IPAM + L2 Announcements (in-cluster LB, no host proxy needed)
- Cilium Gateway API (`Gateway` / `HTTPRoute` instead of `Ingress`)

Migration path: enable `gatewayAPI.enabled=true` in Cilium values, deploy `Gateway`/`HTTPRoute` resources, migrate apps, retire Traefik. Hostname convention and IP allocation remain unchanged — contract stability guaranteed.
