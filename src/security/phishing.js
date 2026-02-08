/**
 * Phishing Detection
 *
 * Detection of phishing sites
 */

const crypto = require('crypto');

// Known phishing patterns
const PHISHING_PATTERNS = {
  // URL patterns
  urlPatterns: [
    /login.*\.(tk|ml|ga|cf|gq)$/i,           // Free TLD + login
    /paypal.*(?!paypal\.com)/i,               // PayPal impersonation
    /google.*(?!google\.com|googleapis)/i,    // Google impersonation
    /microsoft.*(?!microsoft\.com)/i,         // Microsoft impersonation
    /apple.*(?!apple\.com)/i,                 // Apple impersonation
    /amazon.*(?!amazon\.com|amazonaws)/i,     // Amazon impersonation
    /bank.*\.(tk|ml|ga|cf|gq|xyz)$/i,        // Bank impersonation
    /-login\./i,                              // xxx-login.example.com
    /\d{1,3}-\d{1,3}-\d{1,3}/,               // IP-like subdomain
  ],

  // DOM patterns (login form characteristics)
  domPatterns: [
    { selector: 'input[type="password"]', weight: 2 },
    { selector: 'form[action*="login"]', weight: 3 },
    { selector: 'form[action*="signin"]', weight: 3 },
    { selector: 'input[name*="card"]', weight: 4 },
    { selector: 'input[name*="cvv"]', weight: 5 },
    { selector: 'input[name*="ssn"]', weight: 5 },
  ],

  // Text patterns
  textPatterns: [
    { pattern: /verify your account/i, weight: 2 },
    { pattern: /confirm your identity/i, weight: 2 },
    { pattern: /suspended.*account/i, weight: 3 },
    { pattern: /unusual activity/i, weight: 2 },
    { pattern: /update.*payment/i, weight: 3 },
    { pattern: /expire.*24 hours/i, weight: 3 },
    { pattern: /click here immediately/i, weight: 2 },
  ]
};

// Legitimate domains list (whitelist)
const LEGITIMATE_DOMAINS = new Set([
  'google.com', 'accounts.google.com',
  'microsoft.com', 'login.microsoftonline.com',
  'apple.com', 'appleid.apple.com',
  'amazon.com', 'amazon.co.jp',
  'paypal.com',
  'github.com',
  'facebook.com',
  'twitter.com', 'x.com',
]);

// URL analysis
function analyzeUrl(url) {
  const result = {
    url,
    score: 0,
    warnings: [],
    isPhishing: false
  };

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Whitelist check
    for (const legit of LEGITIMATE_DOMAINS) {
      if (hostname === legit || hostname.endsWith('.' + legit)) {
        result.legitimate = true;
        return result;
      }
    }

    // URL pattern check
    for (const pattern of PHISHING_PATTERNS.urlPatterns) {
      if (pattern.test(url)) {
        result.score += 3;
        result.warnings.push({
          type: 'url_pattern',
          pattern: pattern.toString(),
          message: 'Suspicious URL pattern detected'
        });
      }
    }

    // Subdomain count check
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
      result.score += 1;
      result.warnings.push({
        type: 'excessive_subdomains',
        message: `Unusual subdomain depth: ${subdomains}`
      });
    }

    // Overly long hostname
    if (hostname.length > 50) {
      result.score += 2;
      result.warnings.push({
        type: 'long_hostname',
        message: 'Unusually long hostname'
      });
    }

  } catch (e) {
    result.warnings.push({ type: 'invalid_url', message: e.message });
  }

  result.isPhishing = result.score >= 5;
  return result;
}

// Page content analysis
async function analyzePage(page) {
  const result = {
    score: 0,
    warnings: [],
    isPhishing: false
  };

  try {
    // DOM pattern check
    for (const { selector, weight } of PHISHING_PATTERNS.domPatterns) {
      const count = await page.$$eval(selector, els => els.length).catch(() => 0);
      if (count > 0) {
        result.score += weight;
        result.warnings.push({
          type: 'dom_pattern',
          selector,
          count,
          message: `Found ${count} element(s) matching ${selector}`
        });
      }
    }

    // Text pattern check
    const bodyText = await page.evaluate(() => document.body?.innerText || '').catch(() => '');
    for (const { pattern, weight } of PHISHING_PATTERNS.textPatterns) {
      if (pattern.test(bodyText)) {
        result.score += weight;
        result.warnings.push({
          type: 'text_pattern',
          pattern: pattern.toString(),
          message: 'Suspicious text pattern detected'
        });
      }
    }

    // Form submission target check
    const formActions = await page.$$eval('form', forms =>
      forms.map(f => f.action).filter(Boolean)
    ).catch(() => []);

    for (const action of formActions) {
      if (action.startsWith('http://')) {
        result.score += 4;
        result.warnings.push({
          type: 'insecure_form',
          action,
          message: 'Form submits to HTTP (not HTTPS)'
        });
      }
    }

  } catch (e) {
    result.warnings.push({ type: 'analysis_error', message: e.message });
  }

  result.isPhishing = result.score >= 6;
  return result;
}

// Overall judgment
async function checkPhishing(url, page = null) {
  const urlResult = analyzeUrl(url);

  if (urlResult.legitimate) {
    return {
      safe: true,
      reason: 'Legitimate domain',
      score: 0,
      warnings: []
    };
  }

  let pageResult = { score: 0, warnings: [] };
  if (page) {
    pageResult = await analyzePage(page);
  }

  const totalScore = urlResult.score + pageResult.score;
  const allWarnings = [...urlResult.warnings, ...pageResult.warnings];

  return {
    safe: totalScore < 5,
    isPhishing: totalScore >= 8,
    isSuspicious: totalScore >= 5 && totalScore < 8,
    score: totalScore,
    warnings: allWarnings,
    recommendation: totalScore >= 8
      ? 'BLOCK - High confidence phishing'
      : totalScore >= 5
        ? 'WARN - Suspicious, proceed with caution'
        : 'ALLOW - No significant indicators'
  };
}

module.exports = {
  analyzeUrl,
  analyzePage,
  checkPhishing,
  PHISHING_PATTERNS,
  LEGITIMATE_DOMAINS
};
