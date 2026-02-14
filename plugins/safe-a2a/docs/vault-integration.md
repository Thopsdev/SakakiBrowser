# Vault Integration

Use Vault references to avoid sending secrets in payloads.

Vault Reference Object
- type: vault_wrap
- token: wrapped secret reference
- hint: optional label for operators
- ttl_sec: short TTL for safety

Rules
- classification VAULT requires vault_refs when payload is non-empty in strict or vault_only
- vault_refs should expire quickly and be single-use when possible
- Do not log wrapped tokens in plaintext logs
