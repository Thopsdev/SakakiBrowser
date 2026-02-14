# Threat Model

Threats
- Raw secret leakage in payloads or logs
- Confused deputy and over-privileged execution
- Replay attacks on signed messages
- Message tampering in transit
- Cross-agent data exfiltration

Mitigations
- Signed safety envelope with short TTL
- Nonce replay protection
- Allowlist constraints and tool scoping
- Vault references for sensitive data
- Audit logs with hashes only
