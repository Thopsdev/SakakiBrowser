const crypto = require('crypto');

class IsolatedStoreClient {
  constructor(options = {}) {
    this.endpoint = options.endpoint || '';
    this.apiKey = options.apiKey || '';
    this.hmacSecret = options.hmacSecret || '';
    this.requireHttps = options.requireHttps !== false;
    this.timeoutMs = Number(options.timeoutMs || 8000);

    this.stats = {
      attempts: 0,
      success: 0,
      failed: 0,
      lastError: null,
      lastSuccessAt: null
    };
  }

  setConfig(options = {}) {
    if (Object.prototype.hasOwnProperty.call(options, 'endpoint')) {
      this.endpoint = String(options.endpoint || '').trim();
    }
    if (Object.prototype.hasOwnProperty.call(options, 'apiKey')) {
      this.apiKey = String(options.apiKey || '').trim();
    }
    if (Object.prototype.hasOwnProperty.call(options, 'hmacSecret')) {
      this.hmacSecret = String(options.hmacSecret || '').trim();
    }
    if (Object.prototype.hasOwnProperty.call(options, 'requireHttps')) {
      this.requireHttps = options.requireHttps !== false;
    }
    if (Object.prototype.hasOwnProperty.call(options, 'timeoutMs')) {
      const value = Number(options.timeoutMs);
      if (Number.isFinite(value) && value > 0) this.timeoutMs = value;
    }
    return this.getConfig();
  }

  isConfigured() {
    return !!this.endpoint;
  }

  getConfig() {
    return {
      endpoint: this.endpoint || null,
      configured: this.isConfigured(),
      requireHttps: this.requireHttps,
      timeoutMs: this.timeoutMs,
      auth: {
        apiKey: !!this.apiKey,
        hmacSecret: !!this.hmacSecret
      },
      stats: { ...this.stats }
    };
  }

  _validateEndpoint() {
    if (!this.endpoint) {
      throw new Error('Isolated store endpoint is not configured');
    }
    let parsed;
    try {
      parsed = new URL(this.endpoint);
    } catch {
      throw new Error('Invalid isolated store endpoint URL');
    }
    if (this.requireHttps && parsed.protocol !== 'https:') {
      throw new Error('Isolated store requires HTTPS endpoint');
    }
    return parsed;
  }

  async store({ name, value, metadata = {} }) {
    this.stats.attempts += 1;
    try {
      this._validateEndpoint();
      if (typeof value !== 'string' || !value.length) {
        throw new Error('Invalid secret payload');
      }

      const timestamp = new Date().toISOString();
      const nonce = crypto.randomBytes(12).toString('hex');
      const payload = {
        name,
        value,
        timestamp,
        nonce,
        metadata
      };
      const body = JSON.stringify(payload);
      const headers = {
        'content-type': 'application/json',
        'x-sakaki-timestamp': timestamp,
        'x-sakaki-nonce': nonce,
        'user-agent': 'SakakiBrowser/isolated-store'
      };

      if (this.apiKey) {
        headers.authorization = `Bearer ${this.apiKey}`;
      }
      if (this.hmacSecret) {
        headers['x-sakaki-signature'] = crypto
          .createHmac('sha256', this.hmacSecret)
          .update(body)
          .digest('hex');
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      let response;
      try {
        response = await fetch(this.endpoint, {
          method: 'POST',
          headers,
          body,
          signal: controller.signal
        });
      } finally {
        clearTimeout(timeout);
      }

      const text = await response.text();
      let parsed;
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = { raw: text };
      }

      if (!response.ok) {
        throw new Error(parsed.error || `HTTP ${response.status}`);
      }

      this.stats.success += 1;
      this.stats.lastSuccessAt = timestamp;
      this.stats.lastError = null;

      return {
        success: true,
        ref: parsed.ref || parsed.id || name || null,
        remote: parsed
      };
    } catch (error) {
      this.stats.failed += 1;
      this.stats.lastError = error.message;
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = { IsolatedStoreClient };
