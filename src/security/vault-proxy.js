/**
 * Vault Proxy
 *
 * Vault executes external API requests on behalf of the client
 * - Secrets never leave the Vault
 * - Adds signature to requests (can be verified by external services)
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');

class VaultProxy {
  constructor(vaultClient, options = {}) {
    this.vaultClient = vaultClient;
    this.name = options.name || 'sakaki-vault';

    // Signing key pair
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.publicKeyId = options.publicKeyId || crypto.randomBytes(8).toString('hex');

    // Allowed domains (empty means allow all)
    this.allowedDomains = new Set(options.allowedDomains || []);

    // Audit log
    this.auditLog = [];

    // Statistics
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      blockedRequests: 0
    };
  }

  /**
   * Generate request signature
   * External services can verify this signature to confirm request came through Vault
   */
  signRequest(method, url, timestamp, body = '') {
    const payload = `${method}\n${url}\n${timestamp}\n${body}`;
    const signature = crypto
      .createHmac('sha256', this.signingKey)
      .update(payload)
      .digest('hex');

    return {
      signature,
      keyId: this.publicKeyId,
      timestamp,
      algorithm: 'hmac-sha256'
    };
  }

  /**
   * Verify signature (used on external service side)
   */
  verifySignature(method, url, timestamp, body, signature, keyId) {
    // Check if timestamp is within 5 minutes
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
      return { valid: false, reason: 'Timestamp too old' };
    }

    // Verify signature
    const expectedSig = this.signRequest(method, url, timestamp, body);
    if (keyId !== this.publicKeyId) {
      return { valid: false, reason: 'Unknown key ID' };
    }

    const valid = crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSig.signature, 'hex')
    );

    return { valid, reason: valid ? null : 'Invalid signature' };
  }

  /**
   * Record audit log
   */
  audit(action, details) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      ...details
    };
    this.auditLog.push(entry);
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Execute external API request as proxy
   *
   * @param {string} secretName - Secret name in Vault
   * @param {object} request - Request configuration
   * @param {string} request.method - HTTP method
   * @param {string} request.url - Target URL
   * @param {object} request.headers - Headers
   * @param {string|object} request.body - Request body
   * @param {string} injectAs - Secret injection method
   *   - "Authorization: Bearer ${secret}" -> Inject into Authorization header
   *   - "X-API-Key: ${secret}" -> Inject into custom header
   *   - "body.api_key" -> Inject into body field
   */
  async proxyRequest(secretName, request, injectAs) {
    this.stats.totalRequests++;

    const { method = 'GET', url, headers = {}, body } = request;

    // URL validation
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      this.stats.failedRequests++;
      return { error: 'Invalid URL' };
    }

    // Domain restriction check
    if (this.allowedDomains.size > 0 && !this.allowedDomains.has(parsedUrl.hostname)) {
      this.stats.blockedRequests++;
      this.audit('BLOCKED', { url, reason: 'Domain not allowed' });
      return { error: `Domain ${parsedUrl.hostname} not allowed` };
    }

    // Get secret from Vault (internal use only, not exposed externally)
    // Here we need to use vaultClient's internal method
    // In actual implementation, send request directly to vault-process

    // Build request with secret injected
    const finalHeaders = { ...headers };
    let finalBody = typeof body === 'object' ? JSON.stringify(body) : body;

    // Add signature
    const timestamp = Date.now().toString();
    const sig = this.signRequest(method, url, timestamp, finalBody || '');

    finalHeaders['X-Vault-Signature'] = sig.signature;
    finalHeaders['X-Vault-KeyId'] = sig.keyId;
    finalHeaders['X-Vault-Timestamp'] = timestamp;
    finalHeaders['X-Vault-Proxy'] = this.name;

    // Secret injection (should be done inside Vault Process)
    // This function defines the interface only

    this.audit('PROXY', {
      method,
      url,
      secretName,
      injectAs,
      success: true
    });

    return {
      success: true,
      message: 'Request would be proxied through vault',
      headers: {
        'X-Vault-Signature': '[signed]',
        'X-Vault-KeyId': sig.keyId,
        'X-Vault-Timestamp': timestamp,
        'X-Vault-Proxy': this.name
      }
    };
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      publicKeyId: this.publicKeyId,
      allowedDomains: Array.from(this.allowedDomains),
      auditLogSize: this.auditLog.length
    };
  }

  /**
   * Get audit log
   */
  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  /**
   * Add allowed domain
   */
  addAllowedDomain(domain) {
    this.allowedDomains.add(domain);
  }

  /**
   * Remove allowed domain
   */
  removeAllowedDomain(domain) {
    this.allowedDomains.delete(domain);
  }
}

/**
 * Verification middleware for external services
 * Only allow requests through Vault
 */
function createVaultVerificationMiddleware(options = {}) {
  const {
    signingKey,        // Signing key shared with Vault
    publicKeyId,       // Allowed key ID
    enforceVaultProxy = false,  // true: Vault required, false: warning only
    allowedProxyNames = []      // Allowed proxy names
  } = options;

  return (req, res, next) => {
    const signature = req.headers['x-vault-signature'];
    const keyId = req.headers['x-vault-keyid'];
    const timestamp = req.headers['x-vault-timestamp'];
    const proxyName = req.headers['x-vault-proxy'];

    // No Vault signature present
    if (!signature || !keyId || !timestamp) {
      if (enforceVaultProxy) {
        return res.status(403).json({
          error: 'Vault proxy required',
          message: 'This endpoint only accepts requests through Sakaki Vault proxy',
          hint: 'Use POST /vault/proxy to make requests'
        });
      } else {
        // Warning only, allow through
        req.vaultVerified = false;
        req.vaultWarning = 'Request not from Vault proxy';
        return next();
      }
    }

    // Proxy name check
    if (allowedProxyNames.length > 0 && !allowedProxyNames.includes(proxyName)) {
      if (enforceVaultProxy) {
        return res.status(403).json({
          error: 'Unknown vault proxy',
          proxyName
        });
      }
    }

    // Timestamp verification (replay attack prevention)
    const now = Date.now();
    const requestTime = parseInt(timestamp);
    if (Math.abs(now - requestTime) > 5 * 60 * 1000) {
      return res.status(403).json({
        error: 'Request expired',
        message: 'Timestamp too old'
      });
    }

    // Signature verification
    const body = JSON.stringify(req.body) || '';
    const url = req.originalUrl || req.url;
    const payload = `${req.method}\n${url}\n${timestamp}\n${body}`;

    const expectedSignature = crypto
      .createHmac('sha256', signingKey)
      .update(payload)
      .digest('hex');

    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
      );

      if (!valid) {
        return res.status(403).json({
          error: 'Invalid signature',
          message: 'Vault signature verification failed'
        });
      }
    } catch (e) {
      return res.status(403).json({
        error: 'Signature verification error'
      });
    }

    // Verification successful
    req.vaultVerified = true;
    req.vaultProxy = proxyName;
    req.vaultKeyId = keyId;

    next();
  };
}

/**
 * External service configuration helper
 * Easy toggle for enforceVaultProxy ON/OFF
 */
class VaultEnforcementConfig {
  constructor() {
    this.enforceVaultProxy = false;
    this.allowedProxyNames = [];
    this.signingKeys = new Map(); // keyId -> signingKey
  }

  // Set Vault required mode
  setEnforceVaultProxy(enabled) {
    this.enforceVaultProxy = enabled;
    return { enforceVaultProxy: this.enforceVaultProxy };
  }

  // Register signing key
  registerSigningKey(keyId, signingKey) {
    this.signingKeys.set(keyId, signingKey);
  }

  // Add proxy name to allowed list
  addAllowedProxy(proxyName) {
    if (!this.allowedProxyNames.includes(proxyName)) {
      this.allowedProxyNames.push(proxyName);
    }
  }

  // Get configuration
  getConfig() {
    return {
      enforceVaultProxy: this.enforceVaultProxy,
      allowedProxyNames: this.allowedProxyNames,
      registeredKeyIds: Array.from(this.signingKeys.keys())
    };
  }

  // Create middleware
  createMiddleware(keyId) {
    const signingKey = this.signingKeys.get(keyId);
    if (!signingKey) {
      throw new Error(`Unknown key ID: ${keyId}`);
    }

    return createVaultVerificationMiddleware({
      signingKey,
      publicKeyId: keyId,
      enforceVaultProxy: this.enforceVaultProxy,
      allowedProxyNames: this.allowedProxyNames
    });
  }
}

module.exports = {
  VaultProxy,
  createVaultVerificationMiddleware,
  VaultEnforcementConfig
};
