function normalizeMethod(method) {
  return (method || 'POST').toUpperCase();
}

function buildSignaturePayload({ method, url, iat, bodyHash }) {
  return `${normalizeMethod(method)}\n${url}\n${iat}\n${bodyHash}`;
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
  verifySignature
};
