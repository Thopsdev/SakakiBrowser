const path = require('path');
const fs = require('fs');
const { outboundGuard } = require('../src/middleware/outbound');
const { inboundGuard } = require('../src/middleware/inbound');
const { createNonceStore } = require('../src/middleware/replay');

const vectorDir = path.join(__dirname, '..', 'spec', 'test-vectors');
const files = fs.readdirSync(vectorDir).filter((f) => f.endsWith('.json'));

const baseConfig = {
  mode: 'strict',
  max_ttl_sec: 600,
  max_clock_skew_sec: 30,
  require_allowlist: false,
  allowed_purposes: ['research.compile_brief'],
  trusted_kids: ['local:test'],
  replay_window_sec: 600,
  dlp_mode: 'deny',
  audit_mode: 'none',
  verify_signature: async () => ({ ok: true }),
  receiver_aud: 'agent:sakai://worker/search'
};

(async () => {
  for (const file of files) {
    const vector = JSON.parse(fs.readFileSync(path.join(vectorDir, file), 'utf8'));
    const envelope = vector.envelope;
    const payload = vector.payload;
    let res;

    if (file.includes('replay')) {
      const nonceStore = createNonceStore(600);
      nonceStore.check(envelope.nonce, envelope.exp);
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
