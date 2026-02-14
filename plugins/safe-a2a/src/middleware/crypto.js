const crypto = require('crypto');

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

function computePayloadHash(payload) {
  const buf = payloadToBuffer(payload);
  const hex = crypto.createHash('sha256').update(buf).digest('hex');
  return `sha256:${hex}`;
}

function normalizeHashValue(raw) {
  if (!raw) return '';
  return String(raw).replace(/^sha256:/i, '');
}

function payloadHashMatches(expected, actual) {
  const a = normalizeHashValue(expected);
  const b = normalizeHashValue(actual);
  return !!a && !!b && a === b;
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
  payloadHashMatches,
  verifySignature
};
