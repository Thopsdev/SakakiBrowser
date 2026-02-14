const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { outboundGuard } = require('../src/middleware/outbound');
const { inboundGuard } = require('../src/middleware/inbound');
const { createNonceStore } = require('../src/middleware/replay');
const { canonicalizeEnvelope } = require('../src/middleware/crypto');

const vectorDir = path.join(__dirname, '..', 'spec', 'test-vectors');
const files = fs.readdirSync(vectorDir).filter((f) => f.endsWith('.json'));

const SHARED_SECRET = 'vector-secret';

function normalizeSigValue(raw) {
  if (!raw) return '';
  const val = String(raw).trim();
  if (val.startsWith('hex:')) return val.slice(4);
  return val;
}

function verifySignatureHmac(env, trustedKids) {
  if (!env || !env.sig || !env.sig.value) return { ok: false, reason: 'SIG_MISSING' };
  if (String(env.sig.alg || '').toLowerCase() !== 'hmac-sha256') return { ok: false, reason: 'SIG_ALG' };
  if (trustedKids.length > 0 && (!env.sig.kid || !trustedKids.includes(env.sig.kid))) {
    return { ok: false, reason: 'SIG_KID_NOT_ALLOWED' };
  }
  const payload = canonicalizeEnvelope(env);
  const expected = crypto.createHmac('sha256', SHARED_SECRET).update(payload).digest('hex');
  const provided = normalizeSigValue(env.sig.value);
  if (!expected || !provided || expected !== provided) {
    return { ok: false, reason: 'SIG_INVALID' };
  }
  return { ok: true };
}

const baseConfig = {
  mode: 'strict',
  max_ttl_sec: 600,
  max_clock_skew_sec: 31536000,
  require_allowlist: false,
  allowed_purposes: ['research.compile_brief'],
  trusted_kids: ['local:test'],
  replay_window_sec: 600,
  dlp_mode: 'deny',
  audit_mode: 'none',
  verify_signature: async (env) => verifySignatureHmac(env, ['local:test']),
  receiver_aud: 'agent:sakai://worker/search'
};

(async () => {
  for (const file of files) {
    const vector = JSON.parse(fs.readFileSync(path.join(vectorDir, file), 'utf8'));
    const envelope = JSON.parse(JSON.stringify(vector.envelope || {}));
    const payload = vector.payload;
    let res;

    const now = Date.now();
    envelope.iat = new Date(now - 1000).toISOString();
    envelope.exp = new Date(now + 5 * 60 * 1000).toISOString();
    if (!file.includes('tampered-constraints')) {
      const payloadStr = canonicalizeEnvelope(envelope);
      const sig = crypto.createHmac('sha256', SHARED_SECRET).update(payloadStr).digest('hex');
      envelope.sig = envelope.sig || {};
      envelope.sig.alg = 'hmac-sha256';
      envelope.sig.kid = envelope.sig.kid || 'local:test';
      envelope.sig.value = `hex:${sig}`;
    }

    if (file.includes('replay')) {
      const nonceStore = createNonceStore(600);
      const nonceKey = `${envelope.iss || ''}:${envelope.aud || ''}:${envelope.nonce || ''}`;
      nonceStore.check(nonceKey, envelope.exp);
      res = await inboundGuard({ envelope, payload }, { ...baseConfig, nonce_store: nonceStore });
    } else if (file.includes('ok-minimal')) {
      res = await outboundGuard({ envelope, payload }, baseConfig);
    } else {
      res = await outboundGuard({ envelope, payload }, baseConfig);
    }

    const decision = res.allowed ? 'allow' : 'deny';
    const ok = decision === vector.expected;
    const reasons = res.reasons || [];
    const reasonOk = !vector.reason_codes || vector.reason_codes.every((r) => reasons.includes(r));

    if (ok && reasonOk) {
      console.log(`PASS ${file}`);
    } else {
      console.log(`FAIL ${file} expected=${vector.expected} got=${decision} reasons=${reasons.join(',')}`);
      process.exitCode = 1;
    }
  }
})();
