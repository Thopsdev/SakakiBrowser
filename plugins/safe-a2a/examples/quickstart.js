const crypto = require('crypto');
const { createSafeA2A } = require('../src');
const { canonicalizeEnvelope, computePayloadHash } = require('../src/middleware/crypto');

const SHARED_SECRET = 'dev-secret-change-me';

function signEnvelope(env) {
  const payload = canonicalizeEnvelope(env);
  return crypto.createHmac('sha256', SHARED_SECRET).update(payload).digest('hex');
}

const safeA2A = createSafeA2A({
  mode: 'strict',
  require_allowlist: true,
  allowed_purposes: ['research.compile_brief'],
  verify_signature: async (env) => {
    const expected = signEnvelope(env);
    const provided = (env.sig && env.sig.value) || '';
    return { ok: provided === expected, reason: provided === expected ? null : 'SIG_INVALID' };
  }
});

const payload = 'hello';
const envelope = {
  ver: 'sakai:safety-envelope/1',
  iss: 'agent:sakai://orchestrator',
  aud: 'agent:sakai://worker/search',
  iat: new Date().toISOString(),
  exp: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  nonce: 'b64url:quickstart',
  trace_id: 'trc_quickstart',
  purpose: 'research.compile_brief',
  classification: 'PUBLIC',
  payload_hash: computePayloadHash(payload),
  sig: { alg: 'hmac-sha256', kid: 'local:test', value: '' },
  constraints: { allowed_domains: ['example.com'], allowed_tools: ['http_fetch'] }
};
envelope.sig.value = signEnvelope(envelope);

(async () => {
  const outbound = await safeA2A.outbound({ envelope, payload });
  console.log('outbound', outbound);

  const inbound = await safeA2A.inbound({ envelope, payload });
  console.log('inbound', inbound);
})();
