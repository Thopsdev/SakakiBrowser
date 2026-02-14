function buildAuditEvent({ direction, decision, reasons, envelope, payloadHash, warnings }) {
  return {
    ts: new Date().toISOString(),
    direction,
    decision,
    reason_codes: reasons || [],
    warning_codes: warnings || [],
    trace_id: envelope && envelope.trace_id,
    iss: envelope && envelope.iss,
    aud: envelope && envelope.aud,
    purpose: envelope && envelope.purpose,
    classification: envelope && envelope.classification,
    data_tags: envelope && envelope.data_tags,
    payload_hash: payloadHash || (envelope && envelope.payload_hash),
    envelope_kid: envelope && envelope.sig && envelope.sig.kid
  };
}

function emitAudit(event, config) {
  if (config.audit_mode === 'none') {
    return;
  }
  if (typeof config.audit_sink === 'function') {
    config.audit_sink(event);
    return;
  }
  console.log(JSON.stringify(event));
}

module.exports = {
  buildAuditEvent,
  emitAudit
};
