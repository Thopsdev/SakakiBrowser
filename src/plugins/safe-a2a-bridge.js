const crypto = require('crypto');
const path = require('path');

function loadSafeA2A() {
  try {
    const modPath = path.resolve(__dirname, '..', '..', 'plugins', 'safe-a2a', 'src');
    return require(modPath);
  } catch (err) {
    console.warn('[Sakaki-Browser] Safe A2A plugin not found:', err.message);
    return null;
  }
}

function parseListValue(raw) {
  if (!raw) return [];
  const sep = raw.includes(';') ? ';' : ',';
  return raw.split(sep).map(s => s.trim()).filter(Boolean);
}

function buildSignaturePayload(envelope) {
  return [
    envelope.ver,
    envelope.iss,
    envelope.aud,
    envelope.iat,
    envelope.exp,
    envelope.nonce,
    envelope.trace_id,
    envelope.purpose,
    envelope.classification,
    envelope.payload_hash
  ].join('\n');
}

function decodeSigValue(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed.startsWith('hex:')) {
    return Buffer.from(trimmed.slice(4), 'hex');
  }
  if (trimmed.startsWith('b64url:')) {
    const b64 = trimmed.slice(7).replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(b64, 'base64');
  }
  if (/^[a-f0-9]+$/i.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }
  return Buffer.from(trimmed, 'base64');
}

function createSignatureVerifier(sharedSecret) {
  return async (envelope) => {
    if (!sharedSecret) {
      return { ok: false, reason: 'SIG_SECRET_MISSING' };
    }
    if (!envelope || !envelope.sig || !envelope.sig.value) {
      return { ok: false, reason: 'SIG_MISSING' };
    }
    if (String(envelope.sig.alg || '').toLowerCase() !== 'hmac-sha256') {
      return { ok: false, reason: 'SIG_ALG' };
    }
    const payload = buildSignaturePayload(envelope);
    const expected = crypto.createHmac('sha256', sharedSecret).update(payload).digest();
    const provided = decodeSigValue(envelope.sig.value);
    if (!provided || provided.length !== expected.length) {
      return { ok: false, reason: 'SIG_INVALID' };
    }
    const ok = crypto.timingSafeEqual(expected, provided);
    return { ok, reason: ok ? null : 'SIG_INVALID' };
  };
}

function extractEnvelope(req) {
  if (req.body && req.body.envelope) {
    return req.body.envelope;
  }
  if (req.body && req.body.metadata) {
    const env = req.body.metadata['sakai:safety-envelope/1'] || req.body.metadata['sakai:safety-envelope/v1'];
    if (env) return env;
  }
  const header = req.headers['x-sakaki-envelope'] || req.headers['x-sakai-envelope'];
  if (!header) return null;
  if (typeof header === 'string') {
    try {
      return JSON.parse(header);
    } catch {
      try {
        const raw = Buffer.from(header, 'base64').toString('utf8');
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }
  }
  return null;
}

function buildPathMatcher(paths) {
  const list = paths.map(p => p.trim()).filter(Boolean);
  return (path) => list.some(p => path === p || path.startsWith(p + '/') || path.startsWith(p));
}

function createSafeA2ABridge(env, options = {}) {
  const { onBlock } = options;
  const enabled = env.SAKAKI_A2A_ENABLE === '1';
  if (!enabled) {
    return { enabled: false, middleware: (req, res, next) => next() };
  }

  const mod = loadSafeA2A();
  if (!mod || typeof mod.createSafeA2A !== 'function') {
    console.warn('[Sakaki-Browser] Safe A2A plugin missing createSafeA2A. Disabled.');
    return { enabled: false, middleware: (req, res, next) => next() };
  }

  const sharedSecret = env.SAKAKI_A2A_SHARED_SECRET || '';
  const safeA2A = mod.createSafeA2A({
    mode: env.SAKAKI_A2A_MODE || 'strict',
    max_ttl_sec: parseInt(env.SAKAKI_A2A_MAX_TTL_SEC || '600', 10),
    max_clock_skew_sec: parseInt(env.SAKAKI_A2A_MAX_CLOCK_SKEW_SEC || '30', 10),
    require_allowlist: env.SAKAKI_A2A_REQUIRE_ALLOWLIST !== '0',
    allowed_purposes: parseListValue(env.SAKAKI_A2A_ALLOWED_PURPOSES || ''),
    trusted_kids: parseListValue(env.SAKAKI_A2A_TRUSTED_KIDS || ''),
    replay_window_sec: parseInt(env.SAKAKI_A2A_REPLAY_WINDOW_SEC || '600', 10),
    dlp_mode: env.SAKAKI_A2A_DLP_MODE || 'deny',
    audit_mode: env.SAKAKI_A2A_AUDIT_MODE || 'metadata',
    receiver_aud: env.SAKAKI_A2A_RECEIVER_AUD || '',
    verify_signature: createSignatureVerifier(sharedSecret)
  });

  const protectedPaths = parseListValue(
    env.SAKAKI_A2A_PROTECTED_PATHS ||
    '/navigate,/click,/type,/secure,/fast,/vault/proxy,/vault/browser/execute,/remote'
  );
  const matchesPath = buildPathMatcher(protectedPaths);

  const middleware = async (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }
    if (!matchesPath(req.path || '')) {
      return next();
    }
    const envelope = extractEnvelope(req);
    if (!envelope) {
      if (typeof onBlock === 'function') {
        onBlock({ req, reason: 'A2A_ENVELOPE_REQUIRED', context: req.path });
      }
      return res.status(401).json({
        error: 'A2A envelope required',
        hint: 'Attach sakai:safety-envelope/1 in body or x-sakaki-envelope header'
      });
    }
    const payload = req.body && (req.body.payload !== undefined ? req.body.payload : req.body);
    const result = await safeA2A.inbound({ envelope, payload, metadata: req.body && req.body.metadata });
    if (!result.allowed) {
      if (typeof onBlock === 'function') {
        onBlock({ req, reason: 'A2A_GUARD_BLOCKED', reasons: result.reasons, context: req.path });
      }
      return res.status(403).json({
        error: 'A2A guard blocked request',
        reasons: result.reasons || []
      });
    }
    req.a2aEnvelope = envelope;
    return next();
  };

  return { enabled: true, middleware };
}

module.exports = {
  createSafeA2ABridge,
  buildSignaturePayload
};
