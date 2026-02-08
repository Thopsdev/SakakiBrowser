/**
 * Security Guardian
 *
 * Monitors agent behavior and blocks/warns dangerous operations
 */

const antivirus = require('./antivirus');
const vault = require('./vault');
const threatIntel = require('./threat-intel');

// Operation log
const auditLog = [];

// Risk levels
const RISK_LEVELS = {
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

// Log operation
function logAction(action, details, risk = RISK_LEVELS.LOW) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    details,
    risk,
    blocked: false
  };
  auditLog.push(entry);

  if (risk === RISK_LEVELS.HIGH || risk === RISK_LEVELS.CRITICAL) {
    console.warn(`[Guardian] ⚠️  ${risk.toUpperCase()}: ${action}`, details);
  }

  return entry;
}

// Pre-navigation check
async function beforeNavigate(url) {
  const checks = {
    url,
    allowed: true,
    warnings: [],
    risk: RISK_LEVELS.SAFE
  };

  // HTTP warning
  if (url.startsWith('http://')) {
    checks.warnings.push('Non-HTTPS connection');
    checks.risk = RISK_LEVELS.MEDIUM;
  }

  // Known dangerous domain check (TODO: external list integration)
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
  if (suspiciousTLDs.some(tld => url.includes(tld))) {
    checks.warnings.push('Suspicious TLD detected');
    checks.risk = RISK_LEVELS.HIGH;
  }

  // VirusTotal URL scan
  const scanResult = await antivirus.scanURL(url);
  if (scanResult && scanResult.threatsFound > 0) {
    checks.warnings.push('URL flagged by antivirus');
    checks.risk = RISK_LEVELS.CRITICAL;
    checks.allowed = false;
  }

  // External threat DB check (URLhaus, PhishTank, etc.)
  // Skip known safe domains (optimization)
  const safeDomains = ['localhost', '127.0.0.1', 'example.com', 'google.com', 'github.com'];
  const hostname = new URL(url).hostname;
  const skipThreatIntel = safeDomains.some(d => hostname === d || hostname.endsWith('.' + d));

  if (!skipThreatIntel) {
    try {
      const tiResult = await threatIntel.checkUrl(url, { timeout: 500 });
      checks.threatIntel = tiResult;
      if (tiResult.malicious) {
        checks.warnings.push('URL flagged by threat intelligence: ' +
          tiResult.threats.map(t => t.provider).join(', '));
        checks.risk = RISK_LEVELS.CRITICAL;
        checks.allowed = false;
      }
    } catch (e) {
      // Threat DB connection error is warning only (don't block)
    }
  }

  logAction('navigate', { url }, checks.risk);
  return checks;
}

// Pre-download check
async function beforeDownload(url, filename) {
  const checks = {
    url,
    filename,
    allowed: true,
    warnings: [],
    risk: RISK_LEVELS.LOW
  };

  // Dangerous extensions
  const dangerousExt = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.scr'];
  const ext = filename.toLowerCase().slice(filename.lastIndexOf('.'));

  if (dangerousExt.includes(ext)) {
    checks.warnings.push(`Dangerous file type: ${ext}`);
    checks.risk = RISK_LEVELS.HIGH;
    checks.requiresScan = true;
  }

  logAction('download', { url, filename }, checks.risk);
  return checks;
}

// Post-download scan
async function afterDownload(filePath) {
  const scanResult = await antivirus.scanFile(filePath);

  if (!scanResult.safe) {
    logAction('malware_detected', {
      file: filePath,
      threats: scanResult.threats
    }, RISK_LEVELS.CRITICAL);

    return {
      safe: false,
      action: 'quarantine',
      threats: scanResult.threats
    };
  }

  return { safe: true };
}

// Pre-form submission check
function beforeFormSubmit(formData, targetUrl) {
  const vaultCheck = vault.checkFormSubmission(formData, targetUrl);

  if (!vaultCheck.safe) {
    logAction('sensitive_data_submit', {
      target: targetUrl,
      warnings: vaultCheck.warnings
    }, RISK_LEVELS.HIGH);
  }

  return vaultCheck;
}

// Get audit log
function getAuditLog(limit = 100) {
  return auditLog.slice(-limit);
}

// Statistics
function getStats() {
  const stats = {
    total: auditLog.length,
    byRisk: {},
    blocked: 0
  };

  for (const entry of auditLog) {
    stats.byRisk[entry.risk] = (stats.byRisk[entry.risk] || 0) + 1;
    if (entry.blocked) stats.blocked++;
  }

  return stats;
}

module.exports = {
  RISK_LEVELS,
  beforeNavigate,
  beforeDownload,
  afterDownload,
  beforeFormSubmit,
  logAction,
  getAuditLog,
  getStats
};
