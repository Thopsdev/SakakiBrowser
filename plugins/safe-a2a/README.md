# Safe A2A Rail Plugin (MVP)

Purpose
Safe A2A provides a secure envelope and enforcement layer for agent-to-agent messages.
It is spec-first and can be used inside Sakaki Browser or as a standalone middleware.

Goals
- Enforce a signed safety envelope on every message
- Prevent raw secrets in payloads by requiring Vault references
- Make risk controls machine-enforceable, not optional
- Emit audit logs without storing sensitive content

Non-Goals
- Full policy engine or advanced DLP
- Transport protocol replacement

Quick Start
1. Attach the safety envelope in message metadata using key `sakai:safety-envelope/1`.
2. Sign the envelope and include a payload hash.
3. Run outbound and inbound middleware to enforce the policy.

When You Need This
- Multiple agents hand off tasks or data
- External APIs are called with delegated authority
- Customer, personal, medical, or financial data is involved
- You need scope limits like purpose, tool allowlist, and domain allowlist
- You need auditability without logging raw secrets

Examples
```bash
node plugins/safe-a2a/examples/quickstart.js
node plugins/safe-a2a/examples/run-vectors.js
node plugins/safe-a2a/examples/send-navigate.js
```

Sakaki Browser Integration
1. Enable the guard
```
SAKAKI_A2A_ENABLE=1
SAKAKI_A2A_MODE=strict
SAKAKI_A2A_SHARED_SECRET=change-me
SAKAKI_A2A_ALLOWED_PURPOSES=research.compile_brief
SAKAKI_A2A_RECEIVER_AUD=agent:sakai://worker/search
```

2. Send an envelope in the request body or header
- Body: `{ \"envelope\": { ... }, \"payload\": ... }`
- Header: `X-Sakaki-Envelope: <base64(JSON)>`

3. Domain allowlist is enforced via the envelope
```
\"constraints\": { \"allowed_domains\": [\"example.com\"] }
```
Exact match is the default. Use `*.example.com` to allow subdomains.

3. Signature (HMAC-SHA256)
```
payload = canonical_json(envelope_without_sig_value)

sig.alg = \"hmac-sha256\"
sig.value = \"hex:\" + hex(hmac_sha256(SAKAKI_A2A_SHARED_SECRET, payload))
```
`payload_hash` can be `sha256` or `blake3` of the payload (canonical JSON for objects), formatted as `sha256:<hex>` or `blake3:<hex>`.

Envelope Example
```json
{
  "ver": "sakai:safety-envelope/1",
  "iss": "agent:sakai://orchestrator",
  "aud": "agent:sakai://worker/search",
  "iat": "2026-02-14T12:00:00Z",
  "exp": "2026-02-14T12:10:00Z",
  "nonce": "b64url:9hQ1...",
  "trace_id": "trc_01HT...",
  "purpose": "research.compile_brief",
  "classification": "VAULT",
  "data_tags": ["PII", "COMMS"],
  "constraints": {
    "allowed_domains": ["example.com"],
    "allowed_tools": ["http_fetch"],
    "max_cost_usd": 1.50,
    "max_calls": 20,
    "max_output_chars": 12000
  },
  "vault_refs": [
    {
      "type": "vault_wrap",
      "token": "hvs.wrap...",
      "hint": "email_thread_export",
      "ttl_sec": 300
    }
  ],
  "payload_hash": "sha256:4c3b...",
  "sig": {
    "alg": "hmac-sha256",
    "kid": "local:test",
    "value": "hex:..."
  }
}
```

Repository Layout
- docs/ contains spec notes and policies
- spec/ contains JSON schemas and test vectors
- src/ contains the middleware skeleton
- tests/ contains example tests

Integration Points
- Outbound middleware validates envelope and DLP before sending
- Inbound middleware verifies signature, nonce, and constraints
- Vault references are required for secrets in VAULT classification

If you integrate into Sakaki Browser, map the envelope to the message metadata and
call outbound and inbound middleware at the edges.
