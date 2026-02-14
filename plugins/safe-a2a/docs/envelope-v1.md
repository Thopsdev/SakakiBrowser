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

Recommended Fields
- data_tags
- constraints
- vault_refs

Signature Payload
- METHOD (uppercase)
- FULL_URL (scheme + host + path + query)
- TIMESTAMP (iat)
- BODY (raw bytes or body hash)

The signature must be verified before any action is taken.

Sakaki Browser Integration (HMAC)
- Use HMAC-SHA256 over the envelope fields:
  ver, iss, aud, iat, exp, nonce, trace_id, purpose, classification, payload_hash
- Join fields with `\\n` in the listed order
