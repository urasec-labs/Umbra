# Disclaimer

Umbra is a **defensive** monitoring tool. Use it only on assets you own or are explicitly authorized to assess.

- Port checks and HTTP probes touch the hosts you list in `scope`. Shared CDN ranges are skipped by default,
  but you remain responsible for confirming that every resolved IP belongs to you (`scope.exclude`).
- Findings are automated signals. Validate them before acting; false positives and negatives happen.
- Reports and inventories contain hostnames, ports and vulnerability details. Store them as sensitive data.
- Secret values are redacted in reports, but the files themselves still contain real secrets: rotate them.
- Provided as-is, with no warranty. You are responsible for how you use it.
