const crypto = require('crypto');
const { canonicalizeEnvelope, computePayloadHash } = require('../src/middleware/crypto');

const SERVER = process.env.SAKAKI_URL || 'http://127.0.0.1:18800';
const SHARED_SECRET = process.env.SAKAKI_A2A_SHARED_SECRET || 'change-me';
const TARGET_URL = process.env.SAKAKI_TARGET_URL || 'https://example.com';

function signEnvelope(env) {
  const payload = canonicalizeEnvelope(env);
  return crypto.createHmac('sha256', SHARED_SECRET).update(payload).digest('hex');
}

async function main() {
  const payload = { url: TARGET_URL };
  const payloadHash = computePayloadHash(payload);

  const envelope = {
    ver: 'sakai:safety-envelope/1',
    iss: 'agent:sakai://orchestrator',
    aud: 'agent:sakai://worker/search',
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    nonce: 'b64url:nav-' + Math.random().toString(36).slice(2),
    trace_id: 'trc_nav',
    purpose: 'research.compile_brief',
    classification: 'PUBLIC',
    payload_hash: payloadHash,
    constraints: { allowed_domains: ['example.com'], allowed_tools: ['navigate'] },
    sig: { alg: 'hmac-sha256', kid: 'local:test', value: '' }
  };

  envelope.sig.value = signEnvelope(envelope);

  const res = await fetch(`${SERVER}/navigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      envelope,
      payload,
      url: TARGET_URL
    })
  });

  const json = await res.json().catch(() => ({}));
  console.log('status', res.status);
  console.log(json);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
