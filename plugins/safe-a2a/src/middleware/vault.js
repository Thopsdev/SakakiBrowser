function hasVaultRefs(envelope) {
  return Array.isArray(envelope.vault_refs) && envelope.vault_refs.length > 0;
}

function hasPayload(payload) {
  if (payload === undefined || payload === null) {
    return false;
  }
  if (typeof payload === 'string') {
    return payload.length > 0;
  }
  if (Buffer.isBuffer(payload)) {
    return payload.length > 0;
  }
  if (typeof payload === 'object') {
    return Object.keys(payload).length > 0;
  }
  return true;
}

function requiresVault(envelope, payload, config) {
  if (!envelope || envelope.classification !== 'VAULT') {
    return false;
  }
  const mode = config && config.mode;
  if ((mode === 'strict' || mode === 'vault_only') && hasPayload(payload)) {
    return true;
  }
  return false;
}

module.exports = {
  hasVaultRefs,
  requiresVault
};
