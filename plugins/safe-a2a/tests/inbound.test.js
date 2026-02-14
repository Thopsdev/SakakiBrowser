const assert = require('assert');
const { inboundGuard } = require('../src/middleware/inbound');
const { computePayloadHash } = require('../src/middleware/crypto');

(async () => {
  const payload = 'hello';
  const envelope = {
    ver: 'sakai:safety-envelope/1',
    iss: 'agent:sakai://orchestrator',
    aud: 'agent:sakai://worker/search',
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    nonce: 'b64url:test-nonce',
    trace_id: 'trc_test',
    purpose: 'research.compile_brief',
    classification: 'PUBLIC',
    payload_hash: computePayloadHash(payload),
    sig: { alg: 'hmac-sha256', kid: 'local:test', value: 'hex:signature' },
    constraints: { allowed_domains: ['example.com'], allowed_tools: ['http_fetch'] }
  };

  const config = {
    max_ttl_sec: 600,
    max_clock_skew_sec: 30,
    require_allowlist: true,
    allowed_purposes: ['research.compile_brief'],
    trusted_kids: ['local:test'],
    replay_window_sec: 600,
    dlp_mode: 'deny',
    audit_mode: 'none',
    verify_signature: async () => ({ ok: true }),
    receiver_aud: 'agent:sakai://worker/search'
  };

  const res = await inboundGuard({ envelope, payload }, config);
  assert.strictEqual(res.allowed, true);
})();
