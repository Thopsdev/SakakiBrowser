const crypto = require('crypto');
let blake3Native = null;

try {
  blake3Native = require('@napi-rs/blake-hash').blake3;
} catch {}

function normalizeMethod(method) {
  return (method || 'POST').toUpperCase();
}

function buildSignaturePayload({ method, url, iat, bodyHash }) {
  return `${normalizeMethod(method)}\n${url}\n${iat}\n${bodyHash}`;
}

function stableStringify(value) {
  if (value && typeof value.toJSON === 'function') {
    return stableStringify(value.toJSON());
  }
  if (value === null) return 'null';
  if (value === undefined) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (Buffer.isBuffer(value)) return JSON.stringify(value.toString('base64'));
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`);
    return `{${pairs.join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalizeEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return '';
  const clone = JSON.parse(JSON.stringify(envelope));
  if (clone.sig && typeof clone.sig === 'object') {
    delete clone.sig.value;
    if (Object.keys(clone.sig).length === 0) {
      delete clone.sig;
    }
  }
  return stableStringify(clone);
}

function payloadToBuffer(payload) {
  if (payload === undefined || payload === null) return Buffer.from('');
  if (Buffer.isBuffer(payload)) return payload;
  if (typeof payload === 'string') return Buffer.from(payload);
  return Buffer.from(stableStringify(payload));
}

function computePayloadHash(payload, algorithm = 'sha256') {
  const buf = payloadToBuffer(payload);
  if (algorithm === 'blake3') {
    if (!blake3Native) return null;
    return `blake3:${blake3Native(buf).toString('hex')}`;
  }
  const hex = crypto.createHash('sha256').update(buf).digest('hex');
  return `sha256:${hex}`;
}

function parseHashAlgorithm(value) {
  const raw = String(value || '').toLowerCase();
  if (raw.startsWith('sha256:')) return 'sha256';
  if (raw.startsWith('blake3:')) return 'blake3';
  return null;
}

function normalizeHashString(value) {
  return String(value || '').toLowerCase();
}

function verifyPayloadHash(payload, expected) {
  if (!expected) return { ok: false, reason: 'PAYLOAD_HASH_MISSING' };
  const algorithm = parseHashAlgorithm(expected);
  if (!algorithm) return { ok: false, reason: 'PAYLOAD_HASH_ALG' };
  const computed = computePayloadHash(payload, algorithm);
  if (!computed) return { ok: false, reason: 'PAYLOAD_HASH_ALG_UNSUPPORTED' };
  if (normalizeHashString(computed) !== normalizeHashString(expected)) {
    return { ok: false, reason: 'PAYLOAD_HASH_MISMATCH', computed };
  }
  return { ok: true, computed };
}

async function verifySignature(envelope, config) {
  if (typeof config.verify_signature !== 'function') {
    return { ok: false, reason: 'SIG_VERIFY_UNCONFIGURED' };
  }
  return config.verify_signature(envelope);
}

module.exports = {
  normalizeMethod,
  buildSignaturePayload,
  stableStringify,
  canonicalizeEnvelope,
  computePayloadHash,
  verifyPayloadHash,
  verifySignature
};
