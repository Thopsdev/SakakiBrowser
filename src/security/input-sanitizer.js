/**
 * Input Sanitizer
 *
 * Prompt injection countermeasures
 * - URL spoofing attacks (ChatGPT Atlas Browser vulnerability)
 * - Hidden instruction detection
 * - Data and instruction separation
 */

// Dangerous patterns
const INJECTION_PATTERNS = [
  // Instructions disguised as URLs
  /https?:\/\/[^\s]*\+follow\+/i,
  /https?:\/\/[^\s]*\+ignore\+/i,
  /https?:\/\/[^\s]*\+visit\+/i,
  /https?:\/\/[^\s]*\+execute\+/i,
  /https?:\/\/[^\s]*\+delete\+/i,
  /https?:\/\/[^\s]*\+send\+/i,

  // Instruction keywords (dangerous in URL context)
  /instruction[s]?\s*:/i,
  /command[s]?\s*:/i,
  /ignore\s+(previous|above|all)/i,
  /forget\s+(previous|above|all)/i,
  /disregard\s+(previous|above|all)/i,

  // System prompt override attempts
  /system\s*prompt/i,
  /you\s+are\s+(now|a)/i,
  /act\s+as\s+(if|a)/i,
  /pretend\s+(to\s+be|you)/i,

  // Dangerous action instructions
  /delete\s+(all|my|the)\s+files/i,
  /send\s+(to|this|my)/i,
  /upload\s+(to|this|my)/i,
  /transfer\s+(to|funds|money)/i,
  /execute\s+(this|the|command)/i,
];

// Strict URL validation
function isStrictlyValidUrl(input) {
  // Immediately reject those containing spaces or plus signs
  if (/[\s+]/.test(input.replace(/\+/g, ' ').trim())) {
    // + within URL should be encoded
    const decoded = decodeURIComponent(input.replace(/\+/g, '%2B'));
    if (decoded !== input) {
      return { valid: false, reason: 'Unencoded special characters' };
    }
  }

  try {
    const url = new URL(input);

    // Protocol check
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, reason: 'Invalid protocol' };
    }

    // Hostname check
    if (!url.hostname || url.hostname.length < 3) {
      return { valid: false, reason: 'Invalid hostname' };
    }

    // Check for dangerous patterns in path
    const fullPath = url.pathname + url.search + url.hash;
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(fullPath)) {
        return {
          valid: false,
          reason: 'Suspicious pattern in URL path',
          pattern: pattern.toString()
        };
      }
    }

    return { valid: true, url: url.href };

  } catch (e) {
    return { valid: false, reason: 'URL parse failed: ' + e.message };
  }
}

// Input sanitization
function sanitizeInput(input, context = 'url') {
  const result = {
    original: input,
    sanitized: input,
    warnings: [],
    blocked: false
  };

  // 1. Injection pattern detection
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(input)) {
      result.warnings.push({
        type: 'injection_pattern',
        pattern: pattern.toString(),
        severity: 'high'
      });
    }
  }

  // 2. URL context case
  if (context === 'url') {
    const urlCheck = isStrictlyValidUrl(input);
    if (!urlCheck.valid) {
      result.warnings.push({
        type: 'invalid_url',
        reason: urlCheck.reason,
        severity: 'critical'
      });
      // Invalid URL is not interpreted as prompt -> block
      result.blocked = true;
      result.blockReason = 'Invalid URL - will not interpret as prompt';
    }
  }

  // 3. Hidden Unicode detection
  const invisibleChars = input.match(/[\u200B-\u200F\u2028-\u202F\uFEFF]/g);
  if (invisibleChars) {
    result.warnings.push({
      type: 'invisible_characters',
      count: invisibleChars.length,
      severity: 'medium'
    });
    // Remove
    result.sanitized = input.replace(/[\u200B-\u200F\u2028-\u202F\uFEFF]/g, '');
  }

  // 4. Control character detection
  const controlChars = input.match(/[\x00-\x1F\x7F]/g);
  if (controlChars) {
    result.warnings.push({
      type: 'control_characters',
      count: controlChars.length,
      severity: 'medium'
    });
    result.sanitized = result.sanitized.replace(/[\x00-\x1F\x7F]/g, '');
  }

  // 5. Block if serious warnings present
  if (result.warnings.some(w => w.severity === 'high' || w.severity === 'critical')) {
    result.blocked = true;
    if (!result.blockReason) {
      result.blockReason = 'Suspicious input detected';
    }
  }

  return result;
}

// Detect instruction extraction from page content
function detectPageInjection(content) {
  const findings = [];

  // Patterns for hidden text detection (CSS concealment)
  const hiddenPatterns = [
    /display\s*:\s*none[^}]*>[^<]*(?:instruction|command|ignore|forget)/gi,
    /visibility\s*:\s*hidden[^}]*>[^<]*(?:instruction|command|ignore|forget)/gi,
    /font-size\s*:\s*0[^}]*>[^<]*(?:instruction|command|ignore|forget)/gi,
    /opacity\s*:\s*0[^}]*>[^<]*(?:instruction|command|ignore|forget)/gi,
  ];

  for (const pattern of hiddenPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push({
        type: 'hidden_instruction',
        matches: matches.slice(0, 3), // Only first 3
        severity: 'critical'
      });
    }
  }

  // Instructions in meta tags
  const metaInstructions = content.match(/<meta[^>]*content\s*=\s*["'][^"']*(?:instruction|command|ignore)[^"']*["'][^>]*>/gi);
  if (metaInstructions) {
    findings.push({
      type: 'meta_injection',
      count: metaInstructions.length,
      severity: 'high'
    });
  }

  // Instructions in comments
  const commentInstructions = content.match(/<!--[^>]*(?:instruction|command|ignore|system\s*prompt)[^>]*-->/gi);
  if (commentInstructions) {
    findings.push({
      type: 'comment_injection',
      count: commentInstructions.length,
      severity: 'medium'
    });
  }

  return {
    safe: findings.length === 0,
    findings
  };
}

// API request body sanitization
function sanitizeRequestBody(body) {
  if (typeof body === 'string') {
    return sanitizeInput(body, 'text');
  }

  if (typeof body === 'object' && body !== null) {
    const result = { sanitized: {}, warnings: [] };

    for (const [key, value] of Object.entries(body)) {
      if (typeof value === 'string') {
        const check = sanitizeInput(value, key === 'url' ? 'url' : 'text');
        result.sanitized[key] = check.sanitized;
        result.warnings.push(...check.warnings.map(w => ({ ...w, field: key })));
      } else {
        result.sanitized[key] = value;
      }
    }

    return result;
  }

  return { sanitized: body, warnings: [] };
}

module.exports = {
  isStrictlyValidUrl,
  sanitizeInput,
  detectPageInjection,
  sanitizeRequestBody,
  INJECTION_PATTERNS
};
