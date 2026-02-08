/**
 * Secret Detector
 *
 * Automatically detects and protects sensitive data
 * - Pattern-based detection (API keys, tokens, etc.)
 * - Field name detection (password, secret, etc.)
 * - PII detection (credit cards, emails in sensitive context)
 */

const crypto = require('crypto');

// Built-in patterns for known secret formats
const BUILTIN_PATTERNS = [
  // OpenAI
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/, severity: 'critical' },
  { name: 'OpenAI Project Key', pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/, severity: 'critical' },

  // GitHub
  { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub App Token', pattern: /ghu_[a-zA-Z0-9]{36,}/, severity: 'critical' },
  { name: 'GitHub Refresh Token', pattern: /ghr_[a-zA-Z0-9]{36,}/, severity: 'critical' },

  // AWS
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /[a-zA-Z0-9/+=]{40}/, context: 'aws', severity: 'critical' },

  // Google
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/, severity: 'critical' },

  // Stripe
  { name: 'Stripe Secret Key', pattern: /sk_live_[a-zA-Z0-9]{24,}/, severity: 'critical' },
  { name: 'Stripe Test Key', pattern: /sk_test_[a-zA-Z0-9]{24,}/, severity: 'high' },

  // Slack
  { name: 'Slack Token', pattern: /xox[baprs]-[a-zA-Z0-9-]+/, severity: 'critical' },

  // Discord
  { name: 'Discord Token', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/, severity: 'critical' },

  // Generic
  { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/, severity: 'high' },
  { name: 'JWT', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, severity: 'high' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, severity: 'critical' },

  // PII
  { name: 'Credit Card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/, severity: 'critical' },
];

// Sensitive field names (case insensitive)
const SENSITIVE_FIELDS = [
  'password', 'passwd', 'pwd', 'pass',
  'secret', 'api_key', 'apikey', 'api-key',
  'token', 'auth_token', 'access_token', 'refresh_token',
  'private_key', 'privatekey', 'private-key',
  'credential', 'credentials',
  'bearer', 'authorization',
  'ssn', 'social_security',
  'credit_card', 'creditcard', 'card_number',
];

class SecretDetector {
  constructor(options = {}) {
    this.patterns = [...BUILTIN_PATTERNS];
    this.sensitiveFields = [...SENSITIVE_FIELDS];
    this.customPatterns = [];
    this.enabled = true;

    // Statistics
    this.stats = {
      scanned: 0,
      detected: 0,
      protected: 0,
      byType: {}
    };

    // Vault reference for auto-storing
    this.vaultClient = options.vaultClient || null;

    // Detection log
    this.detectionLog = [];
  }

  /**
   * Add custom pattern
   */
  addPattern(name, pattern, severity = 'high') {
    const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern;
    this.customPatterns.push({ name, pattern: regex, severity, custom: true });
    return this;
  }

  /**
   * Add sensitive field name
   */
  addSensitiveField(fieldName) {
    this.sensitiveFields.push(fieldName.toLowerCase());
    return this;
  }

  /**
   * Remove pattern by name
   */
  removePattern(name) {
    this.customPatterns = this.customPatterns.filter(p => p.name !== name);
    return this;
  }

  /**
   * Scan string for secrets
   */
  scanString(input, context = {}) {
    if (!this.enabled || !input || typeof input !== 'string') {
      return { clean: true, findings: [] };
    }

    this.stats.scanned++;
    const findings = [];
    const allPatterns = [...this.patterns, ...this.customPatterns];

    for (const { name, pattern, severity, context: patternContext } of allPatterns) {
      // Skip context-specific patterns if context doesn't match
      if (patternContext && context.type !== patternContext) continue;

      const matches = input.match(new RegExp(pattern, 'g'));
      if (matches) {
        for (const match of matches) {
          findings.push({
            type: name,
            value: match,
            severity,
            position: input.indexOf(match),
            length: match.length
          });
        }
      }
    }

    if (findings.length > 0) {
      this.stats.detected += findings.length;
      findings.forEach(f => {
        this.stats.byType[f.type] = (this.stats.byType[f.type] || 0) + 1;
      });
    }

    return {
      clean: findings.length === 0,
      findings
    };
  }

  /**
   * Scan object (JSON response, form data, etc.)
   */
  scanObject(obj, path = '') {
    if (!this.enabled || !obj) {
      return { clean: true, findings: [], protected: {} };
    }

    const findings = [];
    const protectedObj = Array.isArray(obj) ? [] : {};

    const processValue = (key, value, currentPath) => {
      const fullPath = currentPath ? `${currentPath}.${key}` : key;
      const keyLower = String(key).toLowerCase();

      // Check if field name is sensitive
      const isSensitiveField = this.sensitiveFields.some(f => keyLower.includes(f));

      if (typeof value === 'string') {
        // Scan the value
        const scan = this.scanString(value);

        if (scan.findings.length > 0 || isSensitiveField) {
          // Found secret or sensitive field
          const finding = {
            path: fullPath,
            type: scan.findings[0]?.type || 'Sensitive Field',
            severity: scan.findings[0]?.severity || 'high',
            fieldName: key,
            valueLength: value.length,
            isSensitiveField
          };
          findings.push(finding);

          // Return placeholder
          return `[PROTECTED:${this._generateRef(fullPath)}]`;
        }
        return value;

      } else if (typeof value === 'object' && value !== null) {
        // Recurse
        const nested = this.scanObject(value, fullPath);
        findings.push(...nested.findings);
        return nested.protected;

      } else {
        return value;
      }
    };

    if (Array.isArray(obj)) {
      obj.forEach((item, index) => {
        protectedObj[index] = processValue(index, item, path);
      });
    } else {
      for (const [key, value] of Object.entries(obj)) {
        protectedObj[key] = processValue(key, value, path);
      }
    }

    return {
      clean: findings.length === 0,
      findings,
      protected: protectedObj
    };
  }

  /**
   * Generate reference ID for protected value
   */
  _generateRef(path) {
    const hash = crypto.createHash('sha256')
      .update(path + Date.now())
      .digest('hex')
      .slice(0, 12);
    return `ref-${hash}`;
  }

  /**
   * Protect response (scan and replace secrets)
   */
  protectResponse(response) {
    if (!this.enabled) {
      return { original: response, protected: response, findings: [] };
    }

    let parsed = response;
    let isJson = false;

    // Try to parse JSON
    if (typeof response === 'string') {
      try {
        parsed = JSON.parse(response);
        isJson = true;
      } catch {
        // Not JSON, scan as string
        const scan = this.scanString(response);
        if (scan.findings.length > 0) {
          let sanitized = response;
          for (const finding of scan.findings) {
            sanitized = sanitized.replace(finding.value, `[PROTECTED:${finding.type}]`);
          }
          return { original: response, protected: sanitized, findings: scan.findings };
        }
        return { original: response, protected: response, findings: [] };
      }
    }

    // Scan object
    const result = this.scanObject(parsed);

    return {
      original: response,
      protected: isJson ? JSON.stringify(result.protected) : result.protected,
      findings: result.findings
    };
  }

  /**
   * Auto-vault detected secrets
   */
  async autoVault(findings, originalData) {
    if (!this.vaultClient || findings.length === 0) {
      return { stored: 0, refs: {} };
    }

    const refs = {};
    let stored = 0;

    for (const finding of findings) {
      try {
        // Extract actual value from original data
        let value;
        if (finding.path) {
          value = this._getValueByPath(originalData, finding.path);
        } else if (finding.value) {
          value = finding.value;
        }

        if (value) {
          const secretName = `auto-${finding.type.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`;
          await this.vaultClient.store(secretName, value);
          refs[finding.path || finding.type] = secretName;
          stored++;
          this.stats.protected++;

          this._logDetection('auto-vault', finding, secretName);
        }
      } catch (e) {
        console.error('[SecretDetector] Auto-vault failed:', e.message);
      }
    }

    return { stored, refs };
  }

  /**
   * Get value by path from object
   */
  _getValueByPath(obj, path) {
    return path.split('.').reduce((o, k) => o?.[k], obj);
  }

  /**
   * Log detection
   */
  _logDetection(action, finding, extra = null) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      type: finding.type,
      severity: finding.severity,
      path: finding.path,
      extra
    };
    this.detectionLog.push(entry);

    // Keep last 500 entries
    if (this.detectionLog.length > 500) {
      this.detectionLog = this.detectionLog.slice(-500);
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      patterns: this.patterns.length + this.customPatterns.length,
      customPatterns: this.customPatterns.length,
      sensitiveFields: this.sensitiveFields.length
    };
  }

  /**
   * Get detection log
   */
  getLog(limit = 100) {
    return this.detectionLog.slice(-limit);
  }

  /**
   * Get configuration
   */
  getConfig() {
    return {
      enabled: this.enabled,
      builtinPatterns: this.patterns.map(p => ({ name: p.name, severity: p.severity })),
      customPatterns: this.customPatterns.map(p => ({ name: p.name, severity: p.severity })),
      sensitiveFields: this.sensitiveFields
    };
  }

  /**
   * Enable/disable detection
   */
  setEnabled(enabled) {
    this.enabled = enabled;
    return this;
  }
}

// Singleton instance
const secretDetector = new SecretDetector();

module.exports = { SecretDetector, secretDetector };
