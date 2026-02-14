# Safety Envelope v1

The safety envelope is required metadata for every A2A message.

Envelope Key
Use metadata key `sakai:safety-envelope/1`.

Required Fields
- ver
- iss
- aud
- iat
- exp
- nonce
- trace_id
- purpose
- classification
- payload_hash
- sig

Payload Hash
- `payload_hash` is `sha256` or `blake3` of the payload
- For objects, hash canonical JSON with sorted keys
- Format: `sha256:<hex>` or `blake3:<hex>`

Recommended Fields
- data_tags
- constraints
- vault_refs

Signature Payload
- Canonical JSON of the full envelope with `sig.value` removed
- All constraints and tags are covered by the signature

The signature must be verified before any action is taken.

Sakaki Browser Integration (HMAC)
- Use HMAC-SHA256 over `canonical_json(envelope_without_sig_value)`
- Default algorithm is `hmac-sha256` unless you provide a custom verifier
