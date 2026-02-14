const JWT_RE = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
const PRIVATE_KEY_RE = /BEGIN (RSA|EC|OPENSSH) PRIVATE KEY/;
const API_KEY_RE = /\b(sk-|api[_-]?key|token[_-]?)[A-Za-z0-9_-]{8,}\b/i;
const BASE64_LONG_RE = /[A-Za-z0-9+/=]{32,}/;

function detectSensitive(payload) {
  if (!payload) {
    return { found: false, tags: [], reasons: [] };
  }
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const tags = [];
  const reasons = [];
  let authDetected = false;
  let secretDetected = false;

  if (JWT_RE.test(text)) {
    tags.push('AUTH');
    reasons.push('DLP_JWT');
    authDetected = true;
  }
  if (PRIVATE_KEY_RE.test(text)) {
    tags.push('AUTH');
    reasons.push('DLP_PRIVATE_KEY');
    authDetected = true;
  }
  if (API_KEY_RE.test(text)) {
    tags.push('AUTH');
    reasons.push('DLP_API_KEY');
    authDetected = true;
  }
  if (BASE64_LONG_RE.test(text)) {
    tags.push('POTENTIAL_SECRET');
    reasons.push('DLP_BASE64_LONG');
    secretDetected = true;
  }

  if (authDetected) {
    reasons.push('DLP_DETECTED_AUTH');
  }
  if (secretDetected) {
    reasons.push('DLP_DETECTED_SECRET');
  }

  return {
    found: tags.length > 0,
    tags: Array.from(new Set(tags)),
    reasons: Array.from(new Set(reasons))
  };
}

module.exports = {
  detectSensitive
};
