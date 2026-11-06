# `ok local diagnose bootstrap`

This E2E-only workflow performs one Kind bootstrap attempt with `--retain`. It
does not build or deploy the Console. A failed attempt is terminal; the CLI does
not retry, adopt or clean up resources. A successful diagnostic cluster is also
left running and blocks `ok local down`.

The receipt contains only the logical/Kind names, owner ID, pinned Docker
provider identity, Kind-config SHA-256, allowlisted failure code, safe resource
state and exact matching container identities. Raw Kind or kubeadm output,
credentials, certificates and tokens are never written to the receipt.

## Log export is a separate approval

The CLI does not run `kind export logs`. A future explicit export operation
should verify the receipt, daemon ID and exact retained container before
exporting to a newly created private directory. Treat the entire exported
directory as confidential: do not print its contents, attach it to a ticket,
upload it or share it without a separate owner decision. Log text may contain
sensitive configuration; regular-expression redaction is not a reliable
sanitization boundary.

No diagnostic resource is removed automatically. Cleanup requires a separate
owner authorization bound to the recorded Colima daemon and exact container ID.
The normal `ok local down` command refuses diagnostic receipts, including a
successful bootstrap receipt.
