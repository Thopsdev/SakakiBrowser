const { detectSensitive } = require('./dlp');
const { verifySignature, verifyPayloadHash } = require('./crypto');
const { buildAuditEvent, emitAudit } = require('./audit');
const { requiresVault, hasVaultRefs } = require('./vault');

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
  return { ok: true };
}

async function outboundGuard(ctx, config) {
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

  if (config.require_allowlist && envelope && envelope.constraints && envelope.constraints.allowed_domains) {
    if (envelope.constraints.allowed_domains.length === 0) {
      reasons.push('ALLOWLIST_EMPTY');
    }
  } else if (config.require_allowlist) {
    reasons.push('ALLOWLIST_MISSING');
  }

  let payloadHash = null;
  if (envelope && envelope.payload_hash) {
    const hashCheck = verifyPayloadHash(ctx.payload, envelope.payload_hash);
    payloadHash = hashCheck.computed || null;
    if (!hashCheck.ok) {
      reasons.push(hashCheck.reason || 'PAYLOAD_HASH_MISMATCH');
    }
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
    direction: 'outbound',
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
  outboundGuard
};
