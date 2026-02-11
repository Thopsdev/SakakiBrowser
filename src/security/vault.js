/**
 * Legacy in-process vault (not the isolated Vault process)
 *
 * Used for local protection/detection helpers. The main server uses
 * src/security/vault-process.js for isolated secret handling.
 */

const crypto = require('crypto');

// Protection target patterns
const SENSITIVE_PATTERNS = [
  { name: 'API Key', pattern: /api[_-]?key/i },
  { name: 'Secret', pattern: /secret/i },
  { name: 'Password', pattern: /password|passwd|pwd/i },
  { name: 'Token', pattern: /token|bearer/i },
  { name: 'Private Key', pattern: /private[_-]?key|-----BEGIN/i },
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/i },
  { name: 'Credit Card', pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/ },
];

// Vault (encrypted storage)
class SecureVault {
  constructor(masterKey) {
    this.key = crypto.scryptSync(masterKey || 'default', 'salt', 32);
    this.secrets = new Map();
  }

  // Store secret (encrypted)
  store(name, value) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    this.secrets.set(name, {
      iv: iv.toString('hex'),
      encrypted,
      authTag: authTag.toString('hex'),
      hash: crypto.createHash('sha256').update(value).digest('hex')
    });

    return { stored: true, name };
  }

  // Retrieve secret (decrypt)
  retrieve(name) {
    const secret = this.secrets.get(name);
    if (!secret) return null;

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(secret.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(secret.authTag, 'hex'));

    let decrypted = decipher.update(secret.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // ZKP-like verification: prove match without revealing value
  verify(name, value) {
    const secret = this.secrets.get(name);
    if (!secret) return { valid: false, reason: 'not found' };

    const hash = crypto.createHash('sha256').update(value).digest('hex');
    return {
      valid: hash === secret.hash,
      // Value itself is not returned (Zero Knowledge)
    };
  }
}

// Sensitive data detection for forms/requests
function detectSensitiveData(content) {
  const warnings = [];

  if (typeof content === 'object') {
    content = JSON.stringify(content);
  }

  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    if (pattern.test(content)) {
      warnings.push({
        type: name,
        severity: 'high',
        message: `Potential ${name} detected in content`
      });
    }
  }

  return warnings;
}

// Pre-submission form check
function checkFormSubmission(formData, targetUrl) {
  const warnings = detectSensitiveData(formData);

  // Submission to HTTP is dangerous
  if (targetUrl && targetUrl.startsWith('http://')) {
    warnings.push({
      type: 'Insecure Transport',
      severity: 'critical',
      message: 'Submitting to non-HTTPS endpoint'
    });
  }

  return {
    safe: warnings.length === 0,
    warnings,
    requiresApproval: warnings.some(w => w.severity === 'critical')
  };
}

module.exports = {
  SecureVault,
  detectSensitiveData,
  checkFormSubmission,
  SENSITIVE_PATTERNS
};
