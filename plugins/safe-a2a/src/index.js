const { outboundGuard } = require('./middleware/outbound');
const { inboundGuard } = require('./middleware/inbound');

const defaultConfig = {
  mode: 'strict',
  max_ttl_sec: 600,
  max_clock_skew_sec: 30,
  require_allowlist: true,
  allowed_purposes: [],
  trusted_kids: [],
  replay_window_sec: 600,
  dlp_mode: 'deny',
  audit_mode: 'metadata'
};

function createSafeA2A(config = {}) {
  const merged = { ...defaultConfig, ...config };
  return {
    config: merged,
    outbound: (ctx) => outboundGuard(ctx, merged),
    inbound: (ctx) => inboundGuard(ctx, merged)
  };
}

module.exports = {
  createSafeA2A,
  defaultConfig
};
