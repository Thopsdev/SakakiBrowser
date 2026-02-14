const { detectSensitive } = require('./dlp');
const { verifySignature, computePayloadHash, payloadHashMatches } = require('./crypto');
const { buildAuditEvent, emitAudit } = require('./audit');
const { requiresVault, hasVaultRefs } = require('./vault');
const { createNonceStore } = require('./replay');

let defaultNonceStore;

function getEnvelope(ctx) {
  if (ctx.envelope) {
    return ctx.envelope;
  }
  const meta = ctx.metadata || {};
  return meta['sakai:safety-envelope/1'] || meta['sakai:safety-envelope/v1'];
}

function validateBasics(envelope) {
  const required = ['ver', 'iss', 'aud', 'iat', 'exp', 'nonce', 'trace_id', 'purpose', 'classification', 'payload_hash', 'sig'];
  const missing = required.filter((key) => !envelope || !envelope[key]);
  if (missing.length) {
    return { ok: false, reason: 'ENVELOPE_MISSING_FIELDS' };
  }
  if (envelope.ver !== 'sakai:safety-envelope/1') {
    return { ok: false, reason: 'ENVELOPE_VERSION' };
  }
  return { ok: true };
}

function validateTime(envelope, config) {
  const iat = Date.parse(envelope.iat);
  const exp = Date.parse(envelope.exp);
  if (!iat || !exp) {
    return { ok: false, reason: 'ENVELOPE_TIME' };
  }
  if (exp <= iat) {
    return { ok: false, reason: 'ENVELOPE_EXP' };
  }
  const ttlSec = (exp - iat) / 1000;
  if (ttlSec > config.max_ttl_sec) {
    return { ok: false, reason: 'ENVELOPE_TTL' };
  }
  const now = Date.now();
  const skewMs = config.max_clock_skew_sec * 1000;
  if (iat - now > skewMs || now - exp > skewMs) {
    return { ok: false, reason: 'ENVELOPE_CLOCK_SKEW' };
  }
  return { ok: true };
}

async function inboundGuard(ctx, config) {
  const envelope = getEnvelope(ctx);
  const reasons = [];

  const basics = validateBasics(envelope);
  if (!basics.ok) {
    reasons.push(basics.reason);
  }

  const timeCheck = envelope ? validateTime(envelope, config) : { ok: false, reason: 'ENVELOPE_TIME' };
  if (!timeCheck.ok) {
    reasons.push(timeCheck.reason);
  }

  if (config.allowed_purposes.length && envelope && !config.allowed_purposes.includes(envelope.purpose)) {
    reasons.push('PURPOSE_NOT_ALLOWED');
  }

  if (config.receiver_aud && envelope && envelope.aud !== config.receiver_aud) {
    reasons.push('AUD_MISMATCH');
  }

  if (config.require_allowlist) {
    const domains = envelope && envelope.constraints && envelope.constraints.allowed_domains;
    if (!Array.isArray(domains)) {
      reasons.push('ALLOWLIST_MISSING');
    } else if (domains.length === 0) {
      reasons.push('ALLOWLIST_EMPTY');
    }
  }

  const nonceStore = config.nonce_store || (defaultNonceStore || (defaultNonceStore = createNonceStore(config.replay_window_sec)));
  if (envelope) {
    const nonceKey = `${envelope.iss || ''}:${envelope.aud || ''}:${envelope.nonce || ''}`;
    const nonceResult = nonceStore.check(nonceKey, envelope.exp);
    if (!nonceResult.ok) {
      reasons.push(nonceResult.reason);
    }
  }

  const payloadHash = computePayloadHash(ctx.payload);
  if (envelope && envelope.payload_hash && !payloadHashMatches(envelope.payload_hash, payloadHash)) {
    reasons.push('PAYLOAD_HASH_MISMATCH');
  }

  const dlp = detectSensitive(ctx.payload);
  const warnings = [];
  if (dlp.found) {
    if (config.dlp_mode === 'deny') {
      reasons.push('DLP_DENY', ...dlp.reasons);
    } else if (config.dlp_mode === 'warn') {
      warnings.push(...dlp.reasons);
    }
  }

  if (requiresVault(envelope, ctx.payload, config)) {
    if (!hasVaultRefs(envelope)) {
      reasons.push('VAULT_REQUIRED');
    }
  }

  const sigResult = envelope ? await verifySignature(envelope, config) : { ok: false, reason: 'SIG_MISSING' };
  if (!sigResult.ok) {
    reasons.push(sigResult.reason || 'SIG_INVALID');
  }

  const allowed = reasons.length === 0;
  const audit = buildAuditEvent({
    direction: 'inbound',
    decision: allowed ? 'allow' : 'deny',
    reasons,
    envelope,
    payloadHash,
    warnings
  });
  emitAudit(audit, config);

  return { allowed, reasons };
}

module.exports = {
  inboundGuard
};
