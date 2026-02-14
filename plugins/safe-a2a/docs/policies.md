# Policy Rules

Outbound Rules
- Envelope must exist and validate against schema
- Signature must be present
- exp must be within the max TTL window
- purpose must be on the allowlist
- payload_hash must match the payload
- classification VAULT forbids raw secrets in payload

Inbound Rules
- Signature must verify
- iat and exp must be valid and within allowed drift
- nonce must be unique for the replay window
- aud must match the receiver
- purpose must be allowed
- constraints must be enforced at runtime

Strict Mode
- Enforce allowlist for all outbound proxy calls
- Require vault_refs when classification is VAULT and payload is non-empty
- Deny any raw secret when classification is VAULT
- Require data_tags for CONFIDENTIAL and VAULT

Vault Only Mode
- All sensitive data must be represented as vault_refs
- Raw secrets always denied
