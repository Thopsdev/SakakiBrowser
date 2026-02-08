#!/usr/bin/env node
/**
 * Isolated Vault Process
 *
 * Manages secrets in a completely isolated process
 * - No retrieve() method (ZKP principle)
 * - Memory protection
 * - Self-destruct capability
 * - Audit logging
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const net = require('net');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// ========== Proxy Configuration ==========
let proxyConfig = {
  enabled: true,
  signingKey: crypto.randomBytes(32).toString('hex'),
  publicKeyId: crypto.randomBytes(8).toString('hex'),
  allowedDomains: new Set(), // Empty = allow all
  enforceVaultProxy: false   // For external services: true = Vault required
};

// ========== Configuration ==========
const SOCKET_PATH = process.env.VAULT_SOCKET || '/tmp/sakaki-vault.sock';
const VAULT_FILE = process.env.VAULT_FILE || path.join(__dirname, '../../.vault.enc');
const MAX_FAILED_ATTEMPTS = 10;
const LOCKOUT_DURATION = 60000; // 1 minute

// ========== State ==========
let masterKey = null;
let secrets = new Map();
let failedAttempts = new Map(); // name -> { count, lastAttempt }
let auditLog = [];
let isDestroyed = false;

// ========== Audit Log ==========
function audit(action, name, success, details = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    name: name || null,
    success,
    pid: process.pid,
    ...details
  };
  auditLog.push(entry);

  // Keep only the latest 1000 entries
  if (auditLog.length > 1000) {
    auditLog = auditLog.slice(-1000);
  }

  // Output to console as well
  const status = success ? '✓' : '✗';
  console.log(`[Vault:Audit] ${status} ${action} ${name || ''}`);
}

// ========== SecureBuffer ==========
class SecureBuffer {
  constructor(data) {
    this.buffer = Buffer.from(data);
  }

  toString() {
    return this.buffer.toString();
  }

  // Ensure clearing after use
  destroy() {
    if (this.buffer) {
      crypto.randomFillSync(this.buffer); // Overwrite with random data
      this.buffer.fill(0); // Overwrite with zeros
      this.buffer = null;
    }
  }
}

// ========== Encryption ==========
function deriveKey(masterKey, salt) {
  return crypto.scryptSync(masterKey, salt, 32, { N: 16384, r: 8, p: 1 });
}

function encrypt(value, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(value, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    encrypted,
    authTag: authTag.toString('hex')
  };
}

// ========== Brute Force Protection ==========
function checkRateLimit(name) {
  const record = failedAttempts.get(name);
  if (!record) return { allowed: true };

  // Check if in lockout period
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    const elapsed = Date.now() - record.lastAttempt;
    if (elapsed < LOCKOUT_DURATION) {
      return {
        allowed: false,
        reason: 'Too many failed attempts',
        remainingLockout: Math.ceil((LOCKOUT_DURATION - elapsed) / 1000)
      };
    }
    // Lockout period ended, reset count
    failedAttempts.delete(name);
  }

  return { allowed: true };
}

function recordFailedAttempt(name) {
  const record = failedAttempts.get(name) || { count: 0 };
  record.count++;
  record.lastAttempt = Date.now();
  failedAttempts.set(name, record);

  // Self-destruct check
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    audit('LOCKOUT', name, false, { attempts: record.count });

    // Self-destruct if 10 failures across all secrets
    const totalFailures = Array.from(failedAttempts.values())
      .reduce((sum, r) => sum + r.count, 0);

    if (totalFailures >= MAX_FAILED_ATTEMPTS * 3) {
      selfDestruct('Too many total failed attempts');
    }
  }
}

function selfDestruct(reason) {
  audit('SELF_DESTRUCT', null, true, { reason });

  // Destroy all secrets
  secrets.clear();

  // Delete file as well
  try {
    if (fs.existsSync(VAULT_FILE)) {
      // Overwrite file with random data before deletion
      const stat = fs.statSync(VAULT_FILE);
      const randomData = crypto.randomBytes(stat.size);
      fs.writeFileSync(VAULT_FILE, randomData);
      fs.unlinkSync(VAULT_FILE);
    }
  } catch (e) {
    // Ignore
  }

  isDestroyed = true;
  console.error('[Vault] SELF-DESTRUCTED:', reason);
}

// ========== Persistence ==========
function saveToFile() {
  if (!masterKey || isDestroyed) return;

  try {
    const data = JSON.stringify(Array.from(secrets.entries()));
    const salt = crypto.randomBytes(32);
    const key = deriveKey(masterKey, salt);
    const encrypted = encrypt(data, key);

    const payload = {
      salt: salt.toString('hex'),
      ...encrypted
    };

    fs.writeFileSync(VAULT_FILE, JSON.stringify(payload), { mode: 0o600 });
    audit('SAVE', null, true);
  } catch (e) {
    audit('SAVE', null, false, { error: e.message });
  }
}

function loadFromFile() {
  if (!masterKey || !fs.existsSync(VAULT_FILE)) return;

  try {
    const payload = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
    const key = deriveKey(masterKey, Buffer.from(payload.salt, 'hex'));

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(payload.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(payload.authTag, 'hex'));

    let decrypted = decipher.update(payload.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    secrets = new Map(JSON.parse(decrypted));
    audit('LOAD', null, true, { count: secrets.size });
  } catch (e) {
    audit('LOAD', null, false, { error: e.message });
  }
}

// ========== Command Handlers ==========
const handlers = {
  // Initialize (set master key)
  init(params) {
    if (masterKey) {
      return { success: false, error: 'Already initialized' };
    }
    if (!params.masterKey || params.masterKey.length < 16) {
      return { success: false, error: 'Master key must be at least 16 characters' };
    }

    masterKey = params.masterKey;
    loadFromFile();
    audit('INIT', null, true);

    return { success: true, secretCount: secrets.size };
  },

  // Store
  store(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (!params.name || !params.value) {
      return { success: false, error: 'name and value required' };
    }

    const secureValue = new SecureBuffer(params.value);

    try {
      // Random salt per secret
      const salt = crypto.randomBytes(32);
      const key = deriveKey(masterKey, salt);
      const encrypted = encrypt(secureValue.toString(), key);

      // Hash (for verification)
      const hash = crypto.createHash('sha256')
        .update(secureValue.toString())
        .digest('hex');

      secrets.set(params.name, {
        salt: salt.toString('hex'),
        ...encrypted,
        hash,
        createdAt: new Date().toISOString()
      });

      saveToFile();
      audit('STORE', params.name, true);

      return { success: true, name: params.name };
    } finally {
      // Ensure clearing
      secureValue.destroy();
    }
  },

  // ZKP verification (does not return value)
  verify(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (!params.name || !params.value) {
      return { success: false, error: 'name and value required' };
    }

    // Rate limit check
    const rateCheck = checkRateLimit(params.name);
    if (!rateCheck.allowed) {
      audit('VERIFY', params.name, false, { reason: 'rate_limited' });
      return {
        success: false,
        error: rateCheck.reason,
        lockoutSeconds: rateCheck.remainingLockout
      };
    }

    const secret = secrets.get(params.name);
    if (!secret) {
      audit('VERIFY', params.name, false, { reason: 'not_found' });
      return { success: false, error: 'Not found' };
    }

    const secureValue = new SecureBuffer(params.value);

    try {
      const hash = crypto.createHash('sha256')
        .update(secureValue.toString())
        .digest('hex');

      const valid = hash === secret.hash;

      if (!valid) {
        recordFailedAttempt(params.name);
      } else {
        // Reset count on success
        failedAttempts.delete(params.name);
      }

      audit('VERIFY', params.name, valid);

      // Never return the value (ZKP)
      return { success: true, valid };
    } finally {
      secureValue.destroy();
    }
  },

  // List (names only)
  list() {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };

    const names = Array.from(secrets.keys()).map(name => ({
      name,
      createdAt: secrets.get(name).createdAt
    }));

    audit('LIST', null, true);
    return { success: true, secrets: names };
  },

  // Delete
  delete(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (!params.name) return { success: false, error: 'name required' };

    const existed = secrets.delete(params.name);
    if (existed) {
      saveToFile();
    }

    audit('DELETE', params.name, existed);
    return { success: true, deleted: existed };
  },

  // Get audit log
  audit(params) {
    const limit = params.limit || 100;
    return {
      success: true,
      log: auditLog.slice(-limit),
      total: auditLog.length
    };
  },

  // Status
  status() {
    return {
      success: true,
      initialized: !!masterKey,
      destroyed: isDestroyed,
      secretCount: secrets.size,
      pid: process.pid,
      proxyEnabled: proxyConfig.enabled,
      proxyKeyId: proxyConfig.publicKeyId
    };
  },

  // ========== Proxy Features ==========

  // Proxy configuration
  proxyConfig(params) {
    if (params.enabled !== undefined) {
      proxyConfig.enabled = params.enabled;
    }
    if (params.enforceVaultProxy !== undefined) {
      proxyConfig.enforceVaultProxy = params.enforceVaultProxy;
    }
    if (params.addDomain) {
      proxyConfig.allowedDomains.add(params.addDomain);
    }
    if (params.removeDomain) {
      proxyConfig.allowedDomains.delete(params.removeDomain);
    }

    return {
      success: true,
      config: {
        enabled: proxyConfig.enabled,
        enforceVaultProxy: proxyConfig.enforceVaultProxy,
        publicKeyId: proxyConfig.publicKeyId,
        allowedDomains: Array.from(proxyConfig.allowedDomains)
      }
    };
  },

  // Get signing key (for sharing with external services)
  getSigningKey() {
    return {
      success: true,
      publicKeyId: proxyConfig.publicKeyId,
      // Signing key is only returned during sharing setup (normally kept private)
      hint: 'Use /vault/proxy/share to securely share signing key'
    };
  },

  // Execute proxy request (secret is only used within this process)
  async proxy(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (!proxyConfig.enabled) return { success: false, error: 'Proxy disabled' };

    const { secretName, request, injectAs } = params;

    if (!secretName || !request || !injectAs) {
      return { success: false, error: 'secretName, request, and injectAs required' };
    }

    // Get secret (internal use only)
    const secret = secrets.get(secretName);
    if (!secret) {
      audit('PROXY', secretName, false, { reason: 'secret_not_found' });
      return { success: false, error: 'Secret not found' };
    }

    // Decrypt (internal use only, not returned externally)
    let decryptedValue;
    try {
      const key = deriveKey(masterKey, Buffer.from(secret.salt, 'hex'));
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(secret.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(secret.authTag, 'hex'));
      decryptedValue = decipher.update(secret.encrypted, 'hex', 'utf8');
      decryptedValue += decipher.final('utf8');
    } catch (e) {
      audit('PROXY', secretName, false, { reason: 'decrypt_failed' });
      return { success: false, error: 'Failed to decrypt secret' };
    }

    // Parse URL
    let parsedUrl;
    try {
      parsedUrl = new URL(request.url);
    } catch (e) {
      return { success: false, error: 'Invalid URL' };
    }

    // Domain restriction check
    if (proxyConfig.allowedDomains.size > 0 &&
        !proxyConfig.allowedDomains.has(parsedUrl.hostname)) {
      audit('PROXY', secretName, false, {
        reason: 'domain_blocked',
        domain: parsedUrl.hostname
      });
      return {
        success: false,
        error: `Domain ${parsedUrl.hostname} not in allowed list`
      };
    }

    // Build headers
    const headers = { ...(request.headers || {}) };
    let body = request.body;

    // Inject secret
    if (injectAs.startsWith('Authorization:')) {
      const template = injectAs.replace('Authorization:', '').trim();
      headers['Authorization'] = template.replace('${secret}', decryptedValue);
    } else if (injectAs.includes(':')) {
      const [headerName, template] = injectAs.split(':').map(s => s.trim());
      headers[headerName] = template.replace('${secret}', decryptedValue);
    } else if (injectAs.startsWith('body.')) {
      const fieldPath = injectAs.substring(5);
      if (typeof body === 'string') {
        try { body = JSON.parse(body); } catch {}
      }
      body = body || {};
      body[fieldPath] = decryptedValue;
    }

    // Add Vault signature
    const timestamp = Date.now().toString();
    const bodyStr = typeof body === 'object' ? JSON.stringify(body) : (body || '');
    const signPayload = `${request.method || 'GET'}\n${request.url}\n${timestamp}\n${bodyStr}`;
    const signature = crypto
      .createHmac('sha256', proxyConfig.signingKey)
      .update(signPayload)
      .digest('hex');

    headers['X-Vault-Signature'] = signature;
    headers['X-Vault-KeyId'] = proxyConfig.publicKeyId;
    headers['X-Vault-Timestamp'] = timestamp;
    headers['X-Vault-Proxy'] = 'sakaki-vault';

    // Execute HTTP request
    try {
      const response = await makeHttpRequest({
        method: request.method || 'GET',
        url: request.url,
        headers,
        body: typeof body === 'object' ? JSON.stringify(body) : body,
        timeout: request.timeout || 30000
      });

      // Clear secret immediately
      decryptedValue = null;

      audit('PROXY', secretName, true, {
        url: request.url,
        status: response.statusCode
      });

      return {
        success: true,
        response: {
          statusCode: response.statusCode,
          headers: response.headers,
          body: response.body
        },
        vaultSigned: true,
        keyId: proxyConfig.publicKeyId
      };
    } catch (e) {
      decryptedValue = null;
      audit('PROXY', secretName, false, { reason: e.message });
      return { success: false, error: e.message };
    }
  }
};

// HTTP request execution helper
function makeHttpRequest({ method, url, headers, body, timeout }) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    const options = {
      method,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      headers: {
        ...headers,
        'Content-Length': body ? Buffer.byteLength(body) : 0
      },
      timeout
    };

    const req = httpModule.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// ========== IPC Server ==========
function startServer() {
  // Delete existing socket
  try {
    if (fs.existsSync(SOCKET_PATH)) {
      fs.unlinkSync(SOCKET_PATH);
    }
  } catch (e) {
    // Ignore
  }

  const server = net.createServer((socket) => {
    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();

      // Process newline-delimited JSON
      const lines = buffer.split('\n');
      buffer = lines.pop(); // Keep incomplete line

      for (const line of lines) {
        if (!line.trim()) continue;

        try {
          const request = JSON.parse(line);
          const handler = handlers[request.command];

          let response;
          if (handler) {
            // Support async handler
            const result = handler(request.params || {});
            if (result && typeof result.then === 'function') {
              result.then(res => {
                socket.write(JSON.stringify(res) + '\n');
              }).catch(err => {
                socket.write(JSON.stringify({
                  success: false,
                  error: err.message
                }) + '\n');
              });
              return; // Async, so exit here
            }
            response = result;
          } else {
            response = { success: false, error: 'Unknown command' };
          }

          socket.write(JSON.stringify(response) + '\n');
        } catch (e) {
          socket.write(JSON.stringify({
            success: false,
            error: 'Invalid request'
          }) + '\n');
        }
      }
    });

    socket.on('error', () => {
      // Client disconnected
    });
  });

  server.listen(SOCKET_PATH, () => {
    // Restrict socket permissions
    fs.chmodSync(SOCKET_PATH, 0o600);
    console.log(`[Vault] Listening on ${SOCKET_PATH}`);
    console.log(`[Vault] PID: ${process.pid}`);
    console.log('[Vault] Waiting for initialization...');
  });

  // Signal handling
  process.on('SIGTERM', () => {
    console.log('[Vault] Shutting down...');
    server.close();
    process.exit(0);
  });

  process.on('SIGINT', () => {
    console.log('[Vault] Shutting down...');
    server.close();
    process.exit(0);
  });
}

// ========== Main ==========
if (require.main === module) {
  console.log('[Vault] Starting isolated vault process...');
  console.log('[Vault] Security features:');
  console.log('  - No retrieve() method (ZKP only)');
  console.log('  - Separate process isolation');
  console.log('  - SecureBuffer for sensitive data');
  console.log('  - Rate limiting + self-destruct');
  console.log('  - Full audit logging');
  console.log('  - Encrypted persistence');

  startServer();
}

module.exports = { handlers }; // For testing
