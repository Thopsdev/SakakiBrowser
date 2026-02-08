/**
 * Sakaki Browser - Security-aware browser automation
 *
 * AI agent browser automation with security at its core
 * + ZKP Vault with process isolation
 * + Antivirus integration
 * + Phishing detection + Rate limiting + Resource monitoring
 */

const puppeteer = require('puppeteer');
const express = require('express');
const antivirus = require('./security/antivirus');
const vault = require('./security/vault');
const { vaultClient, detectSensitiveData } = require('./security/vault-client');
const guardian = require('./security/guardian');
const phishing = require('./security/phishing');
const { rateLimiter } = require('./security/rate-limiter');
const resourceMonitor = require('./security/resource-monitor');
const inputSanitizer = require('./security/input-sanitizer');
const threatIntel = require('./security/threat-intel');
const imageScanner = require('./security/image-scanner');
const { ZKPProvider, createZKPMiddleware } = require('./plugins/zkp-provider');
const { VaultProxy, createVaultVerificationMiddleware, VaultEnforcementConfig } = require('./security/vault-proxy');
const { fastBrowser } = require('./browser/fast-browser');
const { wsProxy } = require('./realtime/websocket-proxy');
const { webhookReceiver } = require('./realtime/webhook-receiver');
const fastHash = require('./security/fast-hash');
const { secretDetector } = require('./security/secret-detector');
const { semanticFinder } = require('./browser/semantic-finder');

// Vault verification settings for external services
const vaultEnforcement = new VaultEnforcementConfig();

const app = express();
app.use(express.json());

let browser = null;
let vaultInitialized = false;

// ZKP Provider (for service providers)
const zkpProvider = new ZKPProvider({ name: 'sakaki-main' });

// Browser initialization
async function initBrowser() {
  browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  console.log('[Sakaki-Browser] Browser initialized');
}

// Comprehensive security check
async function fullSecurityCheck(url, page = null) {
  const results = {
    allowed: true,
    warnings: [],
    checks: {},
    risk: 'safe'
  };

  // 0. Input sanitization (URL spoofing attack countermeasure)
  const sanitizeCheck = inputSanitizer.sanitizeInput(url, 'url');
  results.checks.sanitizer = sanitizeCheck;
  if (sanitizeCheck.blocked) {
    results.allowed = false;
    results.warnings.push(...sanitizeCheck.warnings.map(w => w.message || w.reason));
  }

  // 1. Guardian check (TLD, HTTP, etc.)
  const guardianCheck = await guardian.beforeNavigate(url);
  results.checks.guardian = guardianCheck;
  if (!guardianCheck.allowed) {
    results.allowed = false;
  }
  if (guardianCheck.risk && guardianCheck.risk !== 'safe') {
    results.risk = guardianCheck.risk;
  }
  results.warnings.push(...guardianCheck.warnings);

  // 2. Phishing check
  const phishingCheck = await phishing.checkPhishing(url, page);
  results.checks.phishing = phishingCheck;
  if (phishingCheck.isPhishing) {
    results.allowed = false;
    results.warnings.push('Phishing site detected');
  }
  results.warnings.push(...phishingCheck.warnings.map(w => w.message));

  // 3. Rate limit check
  const rateCheck = rateLimiter.canRequest(url);
  results.checks.rateLimit = rateCheck;
  if (!rateCheck.allowed) {
    results.allowed = false;
    results.warnings.push(rateCheck.reason);
  }

  return results;
}

// Page operation API (with full security check)
// Current page state for sequential operations
let currentPage = null;
let currentMonitor = null;

app.post('/navigate', async (req, res) => {
  const { url, skipSecurityCheck } = req.body;

  // Security check
  let securityCheck = null;
  if (!skipSecurityCheck) {
    securityCheck = await fullSecurityCheck(url);
    if (!securityCheck.allowed) {
      return res.json({
        blocked: true,
        reason: 'Security check failed',
        warnings: securityCheck.warnings,
        risk: securityCheck.risk,
        checks: securityCheck.checks
      });
    }
    if (securityCheck.warnings.length > 0) {
      console.warn('[Navigate] Warnings:', securityCheck.warnings);
    }
  }

  try {
    // Close previous page if exists
    if (currentPage) {
      try {
        await currentPage.close();
        rateLimiter.pageClosed();
        if (currentMonitor) currentMonitor.stop();
      } catch {}
    }

    rateLimiter.recordRequest(url);
    rateLimiter.pageOpened();

    currentPage = await browser.newPage();

    // Start resource monitoring
    currentMonitor = await resourceMonitor.monitorPage(currentPage);

    await currentPage.goto(url, { waitUntil: 'networkidle2' });

    // Phishing check after page load
    const phishingCheck = await phishing.checkPhishing(url, currentPage);
    if (phishingCheck.isPhishing) {
      await currentPage.close();
      currentPage = null;
      rateLimiter.pageClosed();
      currentMonitor.stop();
      currentMonitor = null;
      return res.json({
        blocked: true,
        reason: 'Phishing detected after page load',
        phishingScore: phishingCheck.score,
        warnings: phishingCheck.warnings
      });
    }

    const title = await currentPage.title();
    const metrics = currentMonitor.getMetrics();

    // Keep page open for subsequent operations

    // Aggregate all warnings
    const allWarnings = [
      ...(securityCheck?.warnings || []),
      ...phishingCheck.warnings.map(w => w.message || w)
    ].filter(Boolean);

    guardian.logAction('navigate', { url }, securityCheck?.risk || 'safe', false);

    res.json({
      success: true,
      title,
      url,
      metrics,
      phishingScore: phishingCheck.score,
      risk: securityCheck?.risk || 'safe',
      warnings: allWarnings.length > 0 ? allWarnings : undefined
    });
  } catch (err) {
    if (currentPage) {
      try { await currentPage.close(); } catch {}
      currentPage = null;
    }
    rateLimiter.pageClosed();
    res.json({
      error: err.message,
      risk: securityCheck?.risk || 'unknown',
      warnings: securityCheck?.warnings || []
    });
  }
});

// Close current page
app.post('/close', async (req, res) => {
  if (currentPage) {
    try {
      await currentPage.close();
      currentPage = null;
      rateLimiter.pageClosed();
      if (currentMonitor) {
        currentMonitor.stop();
        currentMonitor = null;
      }
      res.json({ success: true });
    } catch (err) {
      res.json({ error: err.message });
    }
  } else {
    res.json({ success: true, message: 'No page open' });
  }
});

// Screenshot
app.post('/screenshot', async (req, res) => {
  const { url, path: outputPath } = req.body;

  // If URL provided, navigate first; otherwise use current page
  if (url) {
    const check = await fullSecurityCheck(url);
    if (!check.allowed) {
      return res.json({ blocked: true, warnings: check.warnings });
    }

    try {
      rateLimiter.recordRequest(url);
      rateLimiter.pageOpened();

      const page = await browser.newPage();
      await page.goto(url, { waitUntil: 'networkidle2' });
      const screenshot = await page.screenshot({ encoding: 'base64', path: outputPath });
      await page.close();
      rateLimiter.pageClosed();

      res.json({ success: true, screenshot: outputPath ? undefined : screenshot, path: outputPath });
      return;
    } catch (err) {
      rateLimiter.pageClosed();
      res.json({ error: err.message });
      return;
    }
  }

  // Use current page
  if (!currentPage) {
    return res.json({ error: 'No page open. Call /navigate first or provide a URL' });
  }

  try {
    if (outputPath) {
      // Save to file
      await currentPage.screenshot({ path: outputPath });
      guardian.logAction('screenshot', { path: outputPath }, 'safe', false);
      res.json({ success: true, path: outputPath });
    } else {
      // Return base64
      const screenshot = await currentPage.screenshot({ encoding: 'base64' });
      guardian.logAction('screenshot', {}, 'safe', false);
      res.json({ success: true, screenshot });
    }
  } catch (err) {
    res.json({ error: err.message });
  }
});

// Click element
app.post('/click', async (req, res) => {
  const { selector } = req.body;
  if (!selector) {
    return res.json({ error: 'selector required' });
  }

  if (!currentPage) {
    return res.json({ error: 'No page open. Call /navigate first' });
  }

  try {
    // Try semantic search first, fall back to CSS selector
    let clicked = false;
    try {
      const found = await semanticFinder.find(currentPage, selector);
      if (found && found.element) {
        await found.element.click();
        clicked = true;
      }
    } catch {
      // Fall back to CSS selector
    }

    if (!clicked) {
      await currentPage.click(selector);
    }

    guardian.logAction('click', { selector }, 'safe', false);
    res.json({ success: true, selector });
  } catch (err) {
    guardian.logAction('click', { selector }, 'error', false);
    res.json({ error: err.message });
  }
});

// Type text into element
app.post('/type', async (req, res) => {
  const { selector, text } = req.body;
  if (!selector || text === undefined) {
    return res.json({ error: 'selector and text required' });
  }

  if (!currentPage) {
    return res.json({ error: 'No page open. Call /navigate first' });
  }

  try {
    // Try semantic search first
    let typed = false;
    try {
      const found = await semanticFinder.find(currentPage, selector);
      if (found && found.element) {
        await found.element.type(text);
        typed = true;
      }
    } catch {
      // Fall back to CSS selector
    }

    if (!typed) {
      await currentPage.type(selector, text);
    }

    guardian.logAction('type', { selector, length: text.length }, 'safe', false);
    res.json({ success: true, selector });
  } catch (err) {
    guardian.logAction('type', { selector }, 'error', false);
    res.json({ error: err.message });
  }
});

// Type secret from vault (value never exposed to caller)
app.post('/type-secret', async (req, res) => {
  const { selector, secretName } = req.body;
  if (!selector || !secretName) {
    return res.json({ error: 'selector and secretName required' });
  }

  if (!currentPage) {
    return res.json({ error: 'No page open. Call /navigate first' });
  }

  try {
    // Get secret value from vault process (internal only)
    const secretResult = await vaultClient.send('getForInternal', { name: secretName });
    if (!secretResult.success) {
      return res.json({ error: secretResult.error || 'Secret not found or vault not initialized' });
    }

    // Type the secret
    let typed = false;
    try {
      const found = await semanticFinder.find(currentPage, selector);
      if (found && found.element) {
        await found.element.type(secretResult.value);
        typed = true;
      }
    } catch {
      // Fall back to CSS selector
    }

    if (!typed) {
      await currentPage.type(selector, secretResult.value);
    }

    // Clear secret from memory
    secretResult.value = null;

    guardian.logAction('type-secret', { selector, secretName }, 'safe', false);
    res.json({ success: true, selector, secretName });
  } catch (err) {
    guardian.logAction('type-secret', { selector, secretName }, 'error', false);
    res.json({ error: err.message });
  }
});

// Form submission (with sensitive data check)
app.post('/submit-form', async (req, res) => {
  const { url, formData, selector } = req.body;

  // Full security check
  const secCheck = await fullSecurityCheck(url);
  if (!secCheck.allowed) {
    return res.json({
      blocked: true,
      reason: 'Security check failed',
      warnings: secCheck.warnings
    });
  }

  // Sensitive data check
  const vaultCheck = guardian.beforeFormSubmit(formData, url);
  if (vaultCheck.requiresApproval) {
    return res.json({
      blocked: true,
      reason: 'Sensitive data detected - requires approval',
      warnings: vaultCheck.warnings
    });
  }

  try {
    rateLimiter.recordRequest(url);
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });

    // Fill form fields
    for (const [field, value] of Object.entries(formData)) {
      await page.type(`[name="${field}"]`, value);
    }

    // Submit
    if (selector) {
      await page.click(selector);
      await page.waitForNavigation({ waitUntil: 'networkidle2' });
    }

    await page.close();

    res.json({
      success: true,
      warnings: vaultCheck.warnings
    });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// Phishing check API
app.post('/check-phishing', async (req, res) => {
  const { url } = req.body;
  const result = await phishing.checkPhishing(url);
  res.json(result);
});

// Security check only (no navigation, fast)
app.post('/security-check', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.json({ error: 'url required' });
  }

  const startTime = Date.now();
  const result = await fullSecurityCheck(url);

  res.json({
    ...result,
    elapsed: Date.now() - startTime
  });
});

// Vault: Initialize
app.post('/vault/init', async (req, res) => {
  const { masterKey } = req.body;
  if (!masterKey) {
    return res.json({ error: 'masterKey required (min 16 chars)' });
  }
  try {
    const result = await vaultClient.init(masterKey);
    if (result.success) {
      vaultInitialized = true;
    }
    res.json(result);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Vault: Store secret (encrypted in isolated process)
app.post('/vault/store', async (req, res) => {
  const { name, value } = req.body;
  if (!name || !value) {
    return res.json({ error: 'name and value required' });
  }
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized. Call /vault/init first' });
  }
  const result = await vaultClient.store(name, value);
  res.json(result);
});

// Vault: ZKP verification (confirm match without revealing value)
app.post('/vault/verify', async (req, res) => {
  const { name, value } = req.body;
  if (!name || !value) {
    return res.json({ error: 'name and value required' });
  }
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const result = await vaultClient.verify(name, value);
  res.json(result);
});

// Vault: List (names only, values not returned)
app.get('/vault/list', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const result = await vaultClient.list();
  res.json(result);
});

// Vault: Delete
app.delete('/vault/:name', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const result = await vaultClient.delete(req.params.name);
  res.json(result);
});

// Vault: Audit log
app.get('/vault/audit', async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const result = await vaultClient.getAuditLog(limit);
  res.json(result);
});

// Vault: Status
app.get('/vault/status', async (req, res) => {
  const result = await vaultClient.getStatus();
  res.json(result);
});

// ========== Vault Proxy (external API calls without exposing secrets) ==========

// Proxy configuration
app.get('/vault/proxy/config', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const result = await vaultClient.send('proxyConfig', {});
  res.json(result);
});

app.post('/vault/proxy/config', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const { enabled, enforceVaultProxy, addDomain, removeDomain } = req.body;
  const result = await vaultClient.send('proxyConfig', {
    enabled,
    enforceVaultProxy,
    addDomain,
    removeDomain
  });
  res.json(result);
});

// Execute proxy request
app.post('/vault/proxy', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }

  const { secretName, request, injectAs } = req.body;

  if (!secretName || !request || !injectAs) {
    return res.json({
      error: 'Required: secretName, request, injectAs',
      example: {
        secretName: 'OPENAI_KEY',
        request: {
          method: 'POST',
          url: 'https://api.openai.com/v1/chat/completions',
          headers: { 'Content-Type': 'application/json' },
          body: { model: 'gpt-4', messages: [] }
        },
        injectAs: 'Authorization: Bearer ${secret}'
      }
    });
  }

  const result = await vaultClient.send('proxy', {
    secretName,
    request,
    injectAs
  });

  // Auto-protect secrets in response
  if (result.success && result.response?.body) {
    const protection = secretDetector.protectResponse(result.response.body);
    if (protection.findings.length > 0) {
      result.response.body = protection.protected;
      result.secretsDetected = protection.findings.map(f => ({
        type: f.type,
        severity: f.severity,
        path: f.path
      }));
      guardian.logAction('secret-detected', {
        count: protection.findings.length,
        types: protection.findings.map(f => f.type)
      }, 'warning', false);
    }
  }

  res.json(result);
});

// Signing key info (for external service integration)
app.get('/vault/proxy/signing-key', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }
  const result = await vaultClient.send('getSigningKey', {});
  res.json(result);
});

// ========== External services: Vault-only mode enforcement ==========

// enforceVaultProxy setting (used by external services)
app.get('/service/vault-enforcement', (req, res) => {
  res.json(vaultEnforcement.getConfig());
});

app.post('/service/vault-enforcement', (req, res) => {
  const { enforceVaultProxy } = req.body;
  if (typeof enforceVaultProxy === 'boolean') {
    vaultEnforcement.setEnforceVaultProxy(enforceVaultProxy);
  }
  res.json(vaultEnforcement.getConfig());
});

// Sample: Endpoint requiring Vault proxy
// External services can implement this pattern
app.post('/service/protected-api',
  // This middleware verifies Vault signature
  (req, res, next) => {
    const enforced = vaultEnforcement.getConfig().enforceVaultProxy;
    const signature = req.headers['x-vault-signature'];

    if (enforced && !signature) {
      return res.status(403).json({
        error: 'Vault proxy required',
        message: 'This endpoint only accepts requests through Sakaki Vault proxy',
        hint: 'Use POST /vault/proxy to make requests',
        enforceVaultProxy: true
      });
    }

    // Verify signature if present (simplified version)
    if (signature) {
      req.vaultVerified = true;
      req.vaultKeyId = req.headers['x-vault-keyid'];
    } else {
      req.vaultVerified = false;
    }

    next();
  },
  (req, res) => {
    res.json({
      success: true,
      message: 'Protected API accessed',
      vaultVerified: req.vaultVerified,
      vaultKeyId: req.vaultKeyId || null
    });
  }
);

// ========== ZKP Provider (for service providers) ==========

// ZKP: Configuration (vaultOnly mode toggle)
app.get('/zkp/config', (req, res) => {
  res.json(zkpProvider.getConfig());
});

app.post('/zkp/config', (req, res) => {
  const { vaultOnly } = req.body;
  if (typeof vaultOnly === 'boolean') {
    zkpProvider.setVaultOnly(vaultOnly);
  }
  res.json(zkpProvider.getConfig());
});

// ZKP: API key registration (rejected in vaultOnly mode)
app.post('/zkp/register', (req, res) => {
  const { keyId, apiKey, metadata } = req.body;
  if (!keyId || !apiKey) {
    return res.json({ error: 'keyId and apiKey required' });
  }
  const result = zkpProvider.registerKey(keyId, apiKey, metadata);
  res.json(result);
});

// ZKP: Register API key via Vault
app.post('/zkp/register-from-vault', async (req, res) => {
  const { keyId, vaultSecretName, metadata } = req.body;
  if (!keyId || !vaultSecretName) {
    return res.json({ error: 'keyId and vaultSecretName required' });
  }

  // Configure Vault client
  if (!zkpProvider.config.vaultClient) {
    zkpProvider.setVaultClient(vaultClient);
  }

  const result = await zkpProvider.registerFromVault(keyId, vaultSecretName, metadata);
  res.json(result);
});

// ZKP: Issue challenge
app.post('/zkp/challenge', (req, res) => {
  const { keyId } = req.body;
  if (!keyId) {
    return res.json({ error: 'keyId required' });
  }
  const result = zkpProvider.createChallenge(keyId);
  res.json(result);
});

// ZKP: Verify challenge response
app.post('/zkp/verify', (req, res) => {
  const { sessionId, response } = req.body;
  if (!sessionId || !response) {
    return res.json({ error: 'sessionId and response required' });
  }
  const result = zkpProvider.verifyResponse(sessionId, response);
  res.json(result);
});

// ZKP: Vault verification (verify directly with value)
app.post('/zkp/verify-with-vault', async (req, res) => {
  const { keyId, value } = req.body;
  if (!keyId || !value) {
    return res.json({ error: 'keyId and value required' });
  }

  if (!zkpProvider.config.vaultClient) {
    zkpProvider.setVaultClient(vaultClient);
  }

  const result = await zkpProvider.verifyWithVault(keyId, value);
  res.json(result);
});

// ZKP: List registered keys
app.get('/zkp/keys', (req, res) => {
  res.json({ keys: zkpProvider.listKeys() });
});

// ZKP: Delete key
app.delete('/zkp/keys/:keyId', (req, res) => {
  const result = zkpProvider.removeKey(req.params.keyId);
  res.json(result);
});

// ZKP: Statistics
app.get('/zkp/stats', (req, res) => {
  res.json(zkpProvider.getStats());
});

// File scan
app.post('/scan/file', async (req, res) => {
  const { path } = req.body;
  const result = await antivirus.scanFile(path);
  res.json(result);
});

// Content scan
app.post('/scan/content', async (req, res) => {
  const { content, filename } = req.body;
  const result = await antivirus.scanContent(content, filename);
  res.json(result);
});

// Sensitive data detection
app.post('/detect-sensitive', (req, res) => {
  const { content } = req.body;
  const warnings = detectSensitiveData(content);
  res.json({ warnings, hasSensitiveData: warnings.length > 0 });
});

// Audit log
app.get('/audit-log', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  res.json(guardian.getAuditLog(limit));
});

// Security statistics
app.get('/security-stats', (req, res) => {
  res.json({
    guardian: guardian.getStats(),
    rateLimit: rateLimiter.getStats(),
    resources: resourceMonitor.getStats(),
    threatIntel: threatIntel.getStats(),
    threatIntelCache: threatIntel.getCacheStats()
  });
});

// Direct threat DB check
app.post('/threat-check', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.json({ error: 'url required' });
  }
  const result = await threatIntel.checkUrl(url);
  res.json(result);
});

// Image scan (hidden text detection)
app.post('/scan/image', async (req, res) => {
  const { image } = req.body; // Base64 image
  if (!image) {
    return res.json({ error: 'image (base64) required' });
  }
  try {
    const result = await imageScanner.scanBase64Image(image);
    res.json(result);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Image scan warning info
app.get('/scan/image/warning', (req, res) => {
  res.json(imageScanner.getScreenshotWarning());
});

// Resource alerts
app.get('/resource-alerts', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  res.json(resourceMonitor.getAlerts(limit));
});

// ========== Secret Detector ==========

// Get secret detector config
app.get('/secrets/config', (req, res) => {
  res.json(secretDetector.getConfig());
});

// Add custom pattern
app.post('/secrets/pattern', (req, res) => {
  const { name, pattern, severity } = req.body;
  if (!name || !pattern) {
    return res.json({ error: 'name and pattern required' });
  }
  try {
    secretDetector.addPattern(name, pattern, severity || 'high');
    res.json({ success: true, name, pattern });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Remove custom pattern
app.delete('/secrets/pattern/:name', (req, res) => {
  secretDetector.removePattern(req.params.name);
  res.json({ success: true });
});

// Add sensitive field
app.post('/secrets/field', (req, res) => {
  const { field } = req.body;
  if (!field) {
    return res.json({ error: 'field required' });
  }
  secretDetector.addSensitiveField(field);
  res.json({ success: true, field });
});

// Get detection stats
app.get('/secrets/stats', (req, res) => {
  res.json(secretDetector.getStats());
});

// Get detection log
app.get('/secrets/log', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  res.json(secretDetector.getLog(limit));
});

// Test detection (without storing)
app.post('/secrets/test', (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.json({ error: 'data required' });
  }
  const result = typeof data === 'string'
    ? secretDetector.scanString(data)
    : secretDetector.scanObject(data);
  res.json(result);
});

// Enable/disable detection
app.post('/secrets/enabled', (req, res) => {
  const { enabled } = req.body;
  secretDetector.setEnabled(enabled !== false);
  res.json({ success: true, enabled: secretDetector.enabled });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    browser: !!browser,
    security: {
      clamav: antivirus.SCANNERS.clamav.available,
      virustotal: !!antivirus.SCANNERS.virustotal.apiKey,
      resourceMonitoring: resourceMonitor.getStats().isMonitoring,
      rateLimiter: 'active'
    }
  });
});

// Dashboard (simple HTML)
app.get('/dashboard', (req, res) => {
  const guardianStats = guardian.getStats();
  const rateStats = rateLimiter.getStats();
  const resourceStats = resourceMonitor.getStats();

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Sakaki Browser Dashboard</title>
  <style>
    body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }
    .card { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }
    .stat { display: inline-block; margin: 10px 20px; }
    .value { font-size: 2em; color: #0f0; }
    .warn { color: #ff0; }
    .danger { color: #f00; }
    h1 { color: #e94560; }
    h2 { color: #0f3460; background: #e94560; padding: 5px 10px; display: inline-block; }
  </style>
</head>
<body>
  <h1>Sakaki Browser Security Dashboard</h1>

  <div class="card">
    <h2>Guardian Stats</h2>
    <div class="stat">
      <div class="value">${guardianStats.total}</div>
      <div>Total Actions</div>
    </div>
    <div class="stat">
      <div class="value ${guardianStats.blocked > 0 ? 'warn' : ''}">${guardianStats.blocked}</div>
      <div>Blocked</div>
    </div>
  </div>

  <div class="card">
    <h2>Rate Limiter</h2>
    <div class="stat">
      <div class="value">${rateStats.activePages}</div>
      <div>Active Pages</div>
    </div>
    <div class="stat">
      <div class="value">${Object.keys(rateStats.domains).length}</div>
      <div>Domains Tracked</div>
    </div>
  </div>

  <div class="card">
    <h2>Resource Monitor</h2>
    <div class="stat">
      <div class="value">${resourceStats.avgCpuUsage}%</div>
      <div>Avg CPU</div>
    </div>
    <div class="stat">
      <div class="value">${resourceStats.currentMemory?.heapUsedMB || 0}MB</div>
      <div>Heap Used</div>
    </div>
    <div class="stat">
      <div class="value ${resourceStats.alertsCount > 0 ? 'danger' : ''}">${resourceStats.alertsCount}</div>
      <div>Alerts</div>
    </div>
  </div>

  <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>
  `);
});

// Vault UI
app.get('/vault', async (req, res) => {
  const status = await vaultClient.getStatus();
  const secrets = status.initialized ? (await vaultClient.list()).secrets || [] : [];

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Sakaki Vault</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; max-width: 800px; margin: 0 auto; }
    .card { background: #161b22; padding: 20px; margin: 15px 0; border-radius: 8px; border: 1px solid #30363d; }
    h1 { color: #58a6ff; }
    h2 { color: #8b949e; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
    input { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 10px; border-radius: 4px; width: 100%; box-sizing: border-box; margin: 5px 0; }
    input:focus { border-color: #58a6ff; outline: none; }
    button { background: #238636; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px 5px 5px 0; }
    button:hover { background: #2ea043; }
    button.danger { background: #da3633; }
    button.danger:hover { background: #f85149; }
    button.secondary { background: #30363d; }
    .secret-item { display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid #30363d; }
    .secret-item:last-child { border-bottom: none; }
    .secret-name { font-weight: bold; color: #58a6ff; }
    .secret-date { color: #8b949e; font-size: 12px; }
    .status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
    .status.ok { background: #238636; }
    .status.warn { background: #9e6a03; }
    .status.error { background: #da3633; }
    .result { margin-top: 10px; padding: 10px; border-radius: 4px; }
    .result.success { background: #238636; }
    .result.fail { background: #da3633; }
    .features { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
    .feature { background: #0d1117; padding: 10px; border-radius: 4px; font-size: 12px; }
    .feature .icon { margin-right: 5px; }
    #result { display: none; }
  </style>
</head>
<body>
  <h1>🔐 Sakaki Vault</h1>

  <div class="card">
    <h2>Status</h2>
    <p>
      Process:
      <span class="status ${status.success ? 'ok' : 'error'}">
        ${status.success ? 'Running (PID: ' + status.pid + ')' : 'Not Running'}
      </span>
    </p>
    <p>
      Initialized:
      <span class="status ${status.initialized ? 'ok' : 'warn'}">
        ${status.initialized ? 'Yes' : 'No'}
      </span>
      ${status.destroyed ? '<span class="status error">DESTROYED</span>' : ''}
    </p>
    <p>Secrets stored: ${status.secretCount || 0}</p>
  </div>

  <div class="card">
    <h2>Security Features</h2>
    <div class="features">
      <div class="feature"><span class="icon">🚫</span> No retrieve() - ZKP only</div>
      <div class="feature"><span class="icon">🔒</span> Separate process isolation</div>
      <div class="feature"><span class="icon">🧹</span> SecureBuffer auto-wipe</div>
      <div class="feature"><span class="icon">💣</span> Self-destruct on attack</div>
      <div class="feature"><span class="icon">📝</span> Full audit logging</div>
      <div class="feature"><span class="icon">💾</span> Encrypted persistence</div>
    </div>
  </div>

  ${!status.initialized ? `
  <div class="card">
    <h2>Initialize Vault</h2>
    <form id="initForm">
      <input type="password" id="masterKey" placeholder="Master Key (min 16 characters)" minlength="16" required>
      <button type="submit">Initialize</button>
    </form>
  </div>
  ` : `
  <div class="card">
    <h2>Stored Secrets</h2>
    ${secrets.length === 0 ? '<p style="color: #8b949e;">No secrets stored</p>' : `
    <div>
      ${secrets.map(s => `
        <div class="secret-item">
          <div>
            <span class="secret-name">${s.name}</span>
            <div class="secret-date">Created: ${new Date(s.createdAt).toLocaleString()}</div>
          </div>
          <div>
            <button class="secondary" onclick="showVerify('${s.name}')">Verify</button>
            <button class="danger" onclick="deleteSecret('${s.name}')">Delete</button>
          </div>
        </div>
      `).join('')}
    </div>
    `}
  </div>

  <div class="card">
    <h2>Store New Secret</h2>
    <form id="storeForm">
      <input type="text" id="storeName" placeholder="Secret name" required>
      <input type="password" id="storeValue" placeholder="Secret value (never visible after save)" required>
      <button type="submit">Store</button>
    </form>
  </div>

  <div class="card">
    <h2>Verify Secret (ZKP)</h2>
    <form id="verifyForm">
      <input type="text" id="verifyName" placeholder="Secret name" required>
      <input type="password" id="verifyValue" placeholder="Value to verify" required>
      <button type="submit">Verify</button>
    </form>
    <div id="result"></div>
  </div>
  `}

  <div class="card">
    <h2>Audit Log</h2>
    <button onclick="showAudit()">View Recent Actions</button>
    <pre id="auditLog" style="display: none; overflow-x: auto; font-size: 11px; max-height: 300px;"></pre>
  </div>

  <p style="text-align: center; color: #8b949e; margin-top: 30px;">
    <a href="/dashboard" style="color: #58a6ff;">← Back to Dashboard</a>
  </p>

  <script>
    const resultDiv = document.getElementById('result');

    function showResult(success, message) {
      resultDiv.style.display = 'block';
      resultDiv.className = 'result ' + (success ? 'success' : 'fail');
      resultDiv.textContent = message;
    }

    document.getElementById('initForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const masterKey = document.getElementById('masterKey').value;
      const res = await fetch('/vault/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterKey })
      });
      const data = await res.json();
      if (data.success) {
        location.reload();
      } else {
        alert('Error: ' + data.error);
      }
    });

    document.getElementById('storeForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('storeName').value;
      const value = document.getElementById('storeValue').value;
      const res = await fetch('/vault/store', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, value })
      });
      const data = await res.json();
      if (data.success) {
        location.reload();
      } else {
        alert('Error: ' + data.error);
      }
    });

    document.getElementById('verifyForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('verifyName').value;
      const value = document.getElementById('verifyValue').value;
      const res = await fetch('/vault/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, value })
      });
      const data = await res.json();
      if (data.success) {
        showResult(data.valid, data.valid ? '✓ Match confirmed (ZKP verified)' : '✗ No match');
      } else {
        showResult(false, 'Error: ' + data.error);
      }
    });

    function showVerify(name) {
      document.getElementById('verifyName').value = name;
      document.getElementById('verifyValue').focus();
    }

    async function deleteSecret(name) {
      if (!confirm('Delete secret "' + name + '"?')) return;
      const res = await fetch('/vault/' + encodeURIComponent(name), { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        location.reload();
      } else {
        alert('Error: ' + data.error);
      }
    }

    async function showAudit() {
      const logPre = document.getElementById('auditLog');
      if (logPre.style.display === 'none') {
        const res = await fetch('/vault/audit?limit=50');
        const data = await res.json();
        logPre.textContent = data.log?.map(e =>
          e.timestamp + ' ' + (e.success ? '✓' : '✗') + ' ' + e.action + ' ' + (e.name || '')
        ).join('\\n') || 'No logs';
        logPre.style.display = 'block';
      } else {
        logPre.style.display = 'none';
      }
    }
  </script>
</body>
</html>
  `);
});

// ========== Fast Hash API (BLAKE3/SHA256 auto-selection) ==========

// Hash info
app.get('/hash/info', (req, res) => {
  res.json(fastHash.getInfo());
});

// Hash calculation
app.post('/hash', (req, res) => {
  const { data, algorithm } = req.body;
  if (!data) return res.json({ error: 'data required' });

  const result = fastHash.hash(data, { algorithm });
  res.json(result);
});

// Benchmark
app.get('/hash/benchmark', (req, res) => {
  const size = parseInt(req.query.size) || 1024 * 1024;
  const iterations = parseInt(req.query.iterations) || 100;

  const result = fastHash.benchmark(size, iterations);
  res.json(result);
});

// ========== Realtime API (WebSocket/Webhook) ==========

// WebSocket: Connect
app.post('/realtime/ws/connect', async (req, res) => {
  const { url, headers } = req.body;
  if (!url) return res.json({ error: 'url required' });

  try {
    const result = await wsProxy.connect(url, { headers });
    res.json(result);
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// WebSocket: Send message
app.post('/realtime/ws/send', (req, res) => {
  const { connectionId, message } = req.body;
  if (!connectionId || message === undefined) {
    return res.json({ error: 'connectionId and message required' });
  }

  const result = wsProxy.send(connectionId, message);
  res.json(result);
});

// WebSocket: Disconnect
app.post('/realtime/ws/close', (req, res) => {
  const { connectionId } = req.body;
  if (!connectionId) return res.json({ error: 'connectionId required' });

  const result = wsProxy.close(connectionId);
  res.json(result);
});

// WebSocket: List connections
app.get('/realtime/ws/connections', (req, res) => {
  res.json({ connections: wsProxy.listConnections() });
});

// WebSocket: Statistics
app.get('/realtime/ws/stats', (req, res) => {
  res.json(wsProxy.getStats());
});

// Webhook: Register endpoint
app.post('/realtime/webhook/register', (req, res) => {
  const { endpointId, secret, signatureHeader, vaultSecretName } = req.body;
  if (!endpointId) return res.json({ error: 'endpointId required' });

  const result = webhookReceiver.registerEndpoint(endpointId, {
    secret,
    signatureHeader,
    vaultSecretName
  });

  res.json(result);
});

// Webhook: Delete endpoint
app.delete('/realtime/webhook/:endpointId', (req, res) => {
  const result = webhookReceiver.unregisterEndpoint(req.params.endpointId);
  res.json(result);
});

// Webhook: Receive endpoint (receives notifications from external services)
app.post('/realtime/webhook/:endpointId', async (req, res) => {
  const result = await webhookReceiver.receive(
    req.params.endpointId,
    req.headers,
    req.body
  );

  if (result.success) {
    res.status(200).json(result);
  } else {
    res.status(400).json(result);
  }
});

// Webhook: Get events
app.get('/realtime/webhook/events', (req, res) => {
  const { endpointId, since, limit } = req.query;
  const events = webhookReceiver.getEvents({
    endpointId,
    since: since ? parseInt(since) : undefined,
    limit: limit ? parseInt(limit) : 50
  });
  res.json({ events });
});

// Webhook: List endpoints
app.get('/realtime/webhook/endpoints', (req, res) => {
  res.json({ endpoints: webhookReceiver.listEndpoints() });
});

// Webhook: Statistics
app.get('/realtime/webhook/stats', (req, res) => {
  res.json(webhookReceiver.getStats());
});

// ========== Fast Browser API (high-speed, stable browser operations) ==========

// FastBrowser initialization
let fastBrowserInitialized = false;

app.post('/fast/init', async (req, res) => {
  try {
    await fastBrowser.init();
    fastBrowserInitialized = true;
    res.json({ success: true, message: 'FastBrowser initialized' });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// Open page
app.post('/fast/open', async (req, res) => {
  if (!fastBrowserInitialized) {
    await fastBrowser.init();
    fastBrowserInitialized = true;
  }

  const { url } = req.body;
  if (!url) return res.json({ error: 'url required' });

  const result = await fastBrowser.open(url);
  if (result.success) {
    // Generate and manage page ID
    const pageId = Date.now().toString(36);
    fastBrowser._activePages = fastBrowser._activePages || new Map();
    fastBrowser._activePages.set(pageId, { page: result.page, release: result.release });

    res.json({
      success: true,
      pageId,
      loadTime: result.loadTime
    });
  } else {
    res.json(result);
  }
});

// Semantic click
app.post('/fast/click', async (req, res) => {
  const { pageId, target, waitForNavigation } = req.body;
  if (!pageId || !target) return res.json({ error: 'pageId and target required' });

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  const result = await fastBrowser.click(pageData.page, target, { waitForNavigation });
  res.json(result);
});

// Semantic input
app.post('/fast/type', async (req, res) => {
  const { pageId, target, text } = req.body;
  if (!pageId || !target || text === undefined) {
    return res.json({ error: 'pageId, target, and text required' });
  }

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  const result = await fastBrowser.type(pageData.page, target, text);
  res.json(result);
});

// Get text
app.post('/fast/get-text', async (req, res) => {
  const { pageId, target } = req.body;
  if (!pageId || !target) return res.json({ error: 'pageId and target required' });

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  const result = await fastBrowser.getText(pageData.page, target);
  res.json(result);
});

// Get DOM (simplified HTML)
app.post('/fast/dom', async (req, res) => {
  const { pageId, full } = req.body;
  if (!pageId) return res.json({ error: 'pageId required' });

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  const result = await fastBrowser.getDOM(pageData.page, { full });
  res.json(result);
});

// Screenshot
app.post('/fast/screenshot', async (req, res) => {
  const { pageId, fullPage } = req.body;
  if (!pageId) return res.json({ error: 'pageId required' });

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  const result = await fastBrowser.screenshot(pageData.page, { fullPage });
  res.json(result);
});

// Close page
app.post('/fast/close', async (req, res) => {
  const { pageId } = req.body;
  if (!pageId) return res.json({ error: 'pageId required' });

  const pageData = fastBrowser._activePages?.get(pageId);
  if (!pageData) return res.json({ error: 'Page not found' });

  await pageData.release();
  fastBrowser._activePages.delete(pageId);

  res.json({ success: true });
});

// One-shot login
app.post('/fast/login', async (req, res) => {
  if (!fastBrowserInitialized) {
    await fastBrowser.init();
    fastBrowserInitialized = true;
  }

  const { url, email, username, password } = req.body;
  if (!url || !password) return res.json({ error: 'url and password required' });

  const result = await fastBrowser.login(url, { email, username, password });

  if (result.success && result.release) {
    const pageId = Date.now().toString(36);
    fastBrowser._activePages = fastBrowser._activePages || new Map();
    fastBrowser._activePages.set(pageId, { page: null, release: result.release });

    result.pageId = pageId;
    delete result.release;
  }

  res.json(result);
});

// Statistics
app.get('/fast/stats', (req, res) => {
  res.json(fastBrowser.getStats());
});

const PORT = process.env.PORT || 18800;

async function main() {
  // Initialize security modules
  await antivirus.init();
  resourceMonitor.startMonitoring(5000);
  console.log('[Sakaki-Browser] Security modules initialized');

  await initBrowser();
  app.listen(PORT, () => {
    console.log(`[Sakaki-Browser] Listening on port ${PORT}`);
    console.log(`[Sakaki-Browser] Dashboard: http://localhost:${PORT}/dashboard`);
    console.log('[Sakaki-Browser] Guardian + Phishing + RateLimiter + ResourceMonitor active');
  });
}

main().catch(console.error);
