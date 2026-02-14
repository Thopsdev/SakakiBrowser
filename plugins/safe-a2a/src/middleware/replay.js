function createNonceStore(windowSec = 600) {
  const seen = new Map();
  return {
    check(nonce, expIso) {
      const now = Date.now();
      for (const [key, exp] of seen.entries()) {
        if (exp <= now) {
          seen.delete(key);
        }
      }
      if (seen.has(nonce)) {
        return { ok: false, reason: 'REPLAY_NONCE' };
      }
      const expMs = expIso ? Date.parse(expIso) : now + windowSec * 1000;
      seen.set(nonce, expMs);
      return { ok: true };
    }
  };
}

module.exports = {
  createNonceStore
};
