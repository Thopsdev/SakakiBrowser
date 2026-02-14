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
  { name: 'JWT', pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/ },
];

const HIGH_ENTROPY_MIN_LEN = 32;
const HIGH_ENTROPY_MAX_LEN = 4096;
const HIGH_ENTROPY_THRESHOLD = 3.8;
const HIGH_ENTROPY_BASE64_THRESHOLD = 3.6;
const HIGH_ENTROPY_TOKEN_REGEX = /[-A-Za-z0-9+/_=]{32,}/g;

function shannonEntropy(input) {
  const str = String(input);
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function countCharClasses(str) {
  let lower = 0;
  let upper = 0;
  let digit = 0;
  let symbol = 0;
  for (const ch of str) {
    if (ch >= 'a' && ch <= 'z') lower = 1;
    else if (ch >= 'A' && ch <= 'Z') upper = 1;
    else if (ch >= '0' && ch <= '9') digit = 1;
    else symbol = 1;
  }
  return lower + upper + digit + symbol;
}

function looksLikeBase64(token) {
  if (token.length < HIGH_ENTROPY_MIN_LEN) return false;
  if (token.length > HIGH_ENTROPY_MAX_LEN) return false;
  if (/[^A-Za-z0-9+/_=-]/.test(token)) return false;
  const hasPadding = token.includes('=');
  const base64ish = hasPadding && token.length % 4 === 0;
  const base64urlish = /[-_]/.test(token);
  return base64ish || base64urlish;
}

function isLikelyHighEntropySecret(token) {
  if (!token) return false;
  if (token.length < HIGH_ENTROPY_MIN_LEN) return false;
  if (token.length > HIGH_ENTROPY_MAX_LEN) return false;
  if (/^https?:\/\//i.test(token)) return false;
  const entropy = shannonEntropy(token);
  const classCount = countCharClasses(token);
  if (looksLikeBase64(token) && entropy >= HIGH_ENTROPY_BASE64_THRESHOLD) return true;
  if (entropy >= HIGH_ENTROPY_THRESHOLD && classCount >= 3) return true;
  return false;
}

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
  const text = String(content || '');

  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    if (pattern.test(text)) {
      warnings.push({
        type: name,
        severity: 'high',
        message: `Potential ${name} detected in content`
      });
    }
  }

  if (warnings.length === 0) {
    const candidates = text.match(HIGH_ENTROPY_TOKEN_REGEX) || [];
    for (const token of candidates) {
      if (isLikelyHighEntropySecret(token)) {
        warnings.push({
          type: 'High Entropy Secret',
          severity: 'high',
          message: 'Potential high-entropy secret detected in content'
        });
        break;
      }
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
