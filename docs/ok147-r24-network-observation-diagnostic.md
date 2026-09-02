# OK-147 R24 network-observation diagnostic

## Outcome

R24 passed provider prerequisites, cluster lifecycle, lifecycle observation,
and enablement, then stopped fail-closed before persisting a network-observation
receipt. No retry or cleanup was performed.

The retained CAAPH state became fully ready 21 seconds after the executor
stopped. This repeated the R23 timing pattern but exposed a second valid
Kubernetes representation of the pre-ready state: an empty
`HelmReleaseProxyList` may carry `items: null`, not only `items: []`.

## Correction

`normalizeHRPList` now treats an absent or explicit-null `items` field as the
same bounded zero-object collection as an empty array. This produces a
pollable pre-ready snapshot and does not contact the workload cluster early.
Non-null non-array values, oversized collections, foreign objects, and
ambiguous multi-object collections remain fail-closed.

Regression coverage proves that explicit-null HRP collections behave like the
already covered empty HRP collection while the functional probe remains
uninvoked.

## Classification

```text
R24 result:                       STOPPED at network-observation
Network receipt persisted:       no
CAAPH ready after executor stop:  21 seconds
Root cause:                       valid empty-list representation rejected
Infrastructure repair performed: no
Retry performed:                 no
```
