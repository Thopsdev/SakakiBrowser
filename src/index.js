/**
 * Sakaki Browser - Security-aware browser automation
 *
 * AI agent browser automation with security at its core
 * + ZKP Vault with process isolation
 * + Antivirus integration
 * + Phishing detection + Rate limiting + Resource monitoring
 */

const express = require('express');
const crypto = require('crypto');
const net = require('net');
const http = require('http');
const WebSocket = require('ws');
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
const { resolveBackendConfig, launchBrowser, normalizeWaitUntil } = require('./browser/backend');
const { attachRequestInterception } = require('./browser/request-interceptor');
const { wsProxy } = require('./realtime/websocket-proxy');
const { webhookReceiver } = require('./realtime/webhook-receiver');
const { notificationCenter } = require('./realtime/notification-center');
const fastHash = require('./security/fast-hash');
const { secretDetector } = require('./security/secret-detector');
const { semanticFinder } = require('./browser/semantic-finder');
const { createSafeA2ABridge } = require('./plugins/safe-a2a-bridge');

// Vault verification settings for external services
const vaultEnforcement = new VaultEnforcementConfig();

const app = express();
const MAX_JSON_SIZE = process.env.SAKAKI_JSON_LIMIT || '1mb';
app.use(express.json({ limit: MAX_JSON_SIZE }));

const BIND = process.env.SAKAKI_BIND || process.env.HOST || '127.0.0.1';
const ADMIN_TOKEN = process.env.SAKAKI_ADMIN_TOKEN || '';
const ALLOW_INSECURE_VAULT = process.env.SAKAKI_ALLOW_INSECURE_VAULT === '1';
const SECURE_ALLOWED_DOMAINS = (process.env.SAKAKI_SECURE_ALLOWED_DOMAINS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const SECURE_ALLOW_SUBDOMAINS = process.env.SAKAKI_SECURE_ALLOW_SUBDOMAINS === '1';
const SECURE_ALLOW_HTTP = process.env.SAKAKI_SECURE_ALLOW_HTTP === '1';
const SECURE_ALLOW_SENSITIVE = process.env.SAKAKI_SECURE_ALLOW_SENSITIVE === '1';
const SECURE_ALLOW_PRIVATE = process.env.SAKAKI_SECURE_ALLOW_PRIVATE === '1';
const VAULT_BROWSER_ALLOW_PRIVATE = process.env.SAKAKI_VAULT_BROWSER_ALLOW_PRIVATE === '1';
const VAULT_BROWSER_ALLOW_SENSITIVE = process.env.SAKAKI_VAULT_BROWSER_ALLOW_SENSITIVE === '1';
const VAULT_BROWSER_MAX_ACTIONS = parseInt(
  process.env.SAKAKI_VAULT_BROWSER_MAX_ACTIONS || '50',
  10
);
const REMOTE_VIEW_ENABLED = process.env.SAKAKI_REMOTE_VIEW === '1';
const REMOTE_VIEW_MAX_SESSIONS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_MAX_SESSIONS || '3',
  10
);
const REMOTE_VIEW_TTL_MS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_TTL_MS || '900000',
  10
);
const REMOTE_VIEW_MAX_TTL_MS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_MAX_TTL_MS || String(REMOTE_VIEW_TTL_MS * 2),
  10
);
const REMOTE_VIEW_IDLE_TIMEOUT_MS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_IDLE_TIMEOUT_MS || '120000',
  10
);
const REMOTE_VIEW_ACTIVITY_EXTEND_MS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_ACTIVITY_EXTEND_MS || String(REMOTE_VIEW_TTL_MS),
  10
);
const REMOTE_VIEW_DEFAULT_FPS = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_FPS || '5',
  10
);
const REMOTE_VIEW_DEFAULT_QUALITY = parseInt(
  process.env.SAKAKI_REMOTE_VIEW_QUALITY || '60',
  10
);
const REMOTE_VIEW_ALLOW_TEXT = process.env.SAKAKI_REMOTE_VIEW_ALLOW_TEXT === '1';
const REMOTE_VIEW_ALLOW_SCROLL = process.env.SAKAKI_REMOTE_VIEW_ALLOW_SCROLL !== '0';
const REMOTE_VIEW_BLOCK_SENSITIVE = process.env.SAKAKI_REMOTE_VIEW_BLOCK_SENSITIVE !== '0';
const CHALLENGE_AUTO_REMOTE = process.env.SAKAKI_CHALLENGE_AUTO_REMOTE !== '0';
const CHALLENGE_NOTIFY_COOLDOWN_MS = parseInt(
  process.env.SAKAKI_CHALLENGE_NOTIFY_COOLDOWN_MS || '60000',
  10
);
const CHALLENGE_TEXT_LIMIT = parseInt(
  process.env.SAKAKI_CHALLENGE_TEXT_LIMIT || '2000',
  10
);
const CHALLENGE_MIN_SCORE = parseInt(
  process.env.SAKAKI_CHALLENGE_MIN_SCORE || '2',
  10
);
const CHALLENGE_DOMAIN_IGNORE = (process.env.SAKAKI_CHALLENGE_DOMAIN_IGNORE || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const CHALLENGE_DOMAIN_FORCE = (process.env.SAKAKI_CHALLENGE_DOMAIN_FORCE || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const HEADLESS_MODE = parseHeadlessMode(
  process.env.SAKAKI_HEADLESS_MODE || process.env.SAKAKI_HEADLESS
);
const PUPPETEER_EXTRA_ARGS = parseListValue(
  process.env.SAKAKI_PUPPETEER_ARGS || process.env.SAKAKI_CHROME_ARGS || ''
);
const PUPPETEER_FORCE_SINGLE_PROCESS = process.env.SAKAKI_PUPPETEER_FORCE_SINGLE_PROCESS === '1';
const SKIP_BROWSER_INIT = process.env.SAKAKI_SKIP_BROWSER_INIT === '1';

let BACKEND_CONFIG;
try {
  BACKEND_CONFIG = resolveBackendConfig('main');
} catch (e) {
  console.error(`[Sakaki-Browser] ${e.message}`);
  process.exit(1);
}
const BROWSER_BACKEND = BACKEND_CONFIG.backend;
const WAIT_UNTIL_NETWORK_IDLE = normalizeWaitUntil('networkidle2', BROWSER_BACKEND);

notificationCenter.configureFromEnv(process.env);

const safeA2ABridge = createSafeA2ABridge(process.env, { onBlock: recordA2ABlock });
if (safeA2ABridge.enabled) {
  app.use(safeA2ABridge.middleware);
}

function isLocalRequest(req) {
  const addr = req.socket?.remoteAddress || '';
  return (
    addr === '127.0.0.1' ||
    addr === '::1' ||
    addr.startsWith('::ffff:127.0.0.1')
  );
}

function normalizeHost(hostname) {
  return (hostname || '').toLowerCase().replace(/\.$/, '');
}

function parseListValue(raw) {
  if (!raw) return [];
  const sep = raw.includes(';') ? ';' : ',';
  return raw.split(sep).map(s => s.trim()).filter(Boolean);
}

function parseHeadlessMode(raw) {
  if (raw === undefined || raw === null || raw === '') return true;
  const v = String(raw).toLowerCase().trim();
  if (v === 'false' || v === '0' || v === 'off' || v === 'no') return false;
  if (v === 'new') return 'new';
  return true;
}

function parseRegexList(value) {
  if (!value) return [];
  const trimmed = String(value).trim();
  let list = [];
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) list = parsed;
    } catch {}
  }
  if (!list.length) {
    const sep = trimmed.includes(';') ? ';' : ',';
    list = trimmed.split(sep).map(s => s.trim()).filter(Boolean);
  }
  return list.map((pattern) => {
    const m = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    try {
      if (m) return new RegExp(m[1], m[2] || 'i');
      return new RegExp(pattern, 'i');
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function domainMatches(hostname, list) {
  const host = normalizeHost(hostname);
  if (!host) return false;
  return list.some((d) => host === d || host.endsWith('.' + d));
}

const a2aMetrics = {
  total: 0,
  blocked: 0,
  byReason: {},
  byTool: {},
  byPurpose: {},
  byDomain: {}
};

function incMetric(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

function recordA2ABlock({ req, reason, reasons, tool, host, context }) {
  a2aMetrics.total += 1;
  a2aMetrics.blocked += 1;

  const envelope = req?.a2aEnvelope;
  const reasonList = Array.isArray(reasons) && reasons.length ? reasons : (reason ? [reason] : []);
  reasonList.forEach((r) => incMetric(a2aMetrics.byReason, r));

  incMetric(a2aMetrics.byTool, tool);
  incMetric(a2aMetrics.byDomain, host);
  if (envelope?.purpose) incMetric(a2aMetrics.byPurpose, envelope.purpose);

  guardian.logAction('a2a_block', {
    reasons: reasonList,
    tool,
    host,
    context,
    trace_id: envelope?.trace_id || null,
    purpose: envelope?.purpose || null,
    classification: envelope?.classification || null,
    data_tags: envelope?.data_tags || null,
    iss: envelope?.iss || null,
    aud: envelope?.aud || null
  }, guardian.RISK_LEVELS.HIGH, true);
}

function getA2AStats() {
  return {
    ...a2aMetrics,
    byReason: { ...a2aMetrics.byReason },
    byTool: { ...a2aMetrics.byTool },
    byPurpose: { ...a2aMetrics.byPurpose },
    byDomain: { ...a2aMetrics.byDomain }
  };
}

function getA2AAllowedDomains(req) {
  const list = req?.a2aEnvelope?.constraints?.allowed_domains;
  if (!Array.isArray(list)) return null;
  return list.map(normalizeHost).filter(Boolean);
}

function enforceA2ATool(req, res, toolName) {
  const envelope = req?.a2aEnvelope;
  if (!envelope) return true;
  const constraints = envelope.constraints || {};
  const disallowed = Array.isArray(constraints.disallowed_actions) ? constraints.disallowed_actions : [];
  if (disallowed.includes(toolName)) {
    recordA2ABlock({ req, reason: 'A2A_TOOL_DISALLOWED', tool: toolName, context: 'tool' });
    res.status(403).json({
      error: 'A2A tool blocked',
      reason: 'A2A_TOOL_DISALLOWED',
      tool: toolName,
      disallowed_actions: disallowed
    });
    return false;
  }
  const allowed = Array.isArray(constraints.allowed_tools) ? constraints.allowed_tools : null;
  if (allowed && allowed.length > 0 && !allowed.includes(toolName)) {
    recordA2ABlock({ req, reason: 'A2A_TOOL_NOT_ALLOWED', tool: toolName, context: 'tool' });
    res.status(403).json({
      error: 'A2A tool blocked',
      reason: 'A2A_TOOL_NOT_ALLOWED',
      tool: toolName,
      allowed_tools: allowed
    });
    return false;
  }
  return true;
}

function enforceA2ADomain(req, res, url, context) {
  const envelope = req?.a2aEnvelope;
  if (!envelope) return true;
  const allowed = getA2AAllowedDomains(req);
  if (!allowed || allowed.length === 0) {
    recordA2ABlock({ req, reason: 'A2A_ALLOWLIST_MISSING', context });
    res.status(403).json({
      error: 'A2A allowlist required',
      reason: 'A2A_ALLOWLIST_MISSING',
      context
    });
    return false;
  }
  if (!url) return true;
  let host;
  try {
    host = new URL(url).hostname;
  } catch {
    recordA2ABlock({ req, reason: 'A2A_URL_INVALID', context });
    res.status(400).json({
      error: 'Invalid URL',
      reason: 'A2A_URL_INVALID',
      context
    });
    return false;
  }
  if (!domainMatches(host, allowed)) {
    recordA2ABlock({ req, reason: 'A2A_DOMAIN_NOT_ALLOWED', host, context });
    res.status(403).json({
      error: 'A2A domain blocked',
      reason: 'A2A_DOMAIN_NOT_ALLOWED',
      host,
      allowed_domains: allowed,
      context
    });
    return false;
  }
  return true;
}

function enforceA2ADomainList(req, res, domains, context) {
  const envelope = req?.a2aEnvelope;
  if (!envelope) return true;
  const allowed = getA2AAllowedDomains(req);
  if (!allowed || allowed.length === 0) {
    recordA2ABlock({ req, reason: 'A2A_ALLOWLIST_MISSING', context });
    res.status(403).json({
      error: 'A2A allowlist required',
      reason: 'A2A_ALLOWLIST_MISSING',
      context
    });
    return false;
  }
  const normalized = (domains || []).map(normalizeHost).filter(Boolean);
  const invalid = normalized.filter((d) => !domainMatches(d, allowed));
  if (invalid.length > 0) {
    recordA2ABlock({ req, reason: 'A2A_DOMAIN_NOT_ALLOWED', host: invalid[0], context });
    res.status(403).json({
      error: 'A2A domain blocked',
      reason: 'A2A_DOMAIN_NOT_ALLOWED',
      invalid_domains: invalid,
      allowed_domains: allowed,
      context
    });
    return false;
  }
  return true;
}

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const host = ip.toLowerCase();
  if (host === '::1') return true;
  if (host.startsWith('fe80:')) return true;
  if (host.startsWith('fc') || host.startsWith('fd')) return true;
  if (host.startsWith('::ffff:')) {
    const v4 = host.replace('::ffff:', '');
    return isPrivateIPv4(v4);
  }
  return false;
}

function isPrivateHost(hostname) {
  const host = normalizeHost(hostname);
  const version = net.isIP(host);
  if (version === 4) return isPrivateIPv4(host);
  if (version === 6) return isPrivateIPv6(host);
  return false;
}

function isHostAllowedForList(hostname, allowedDomains, allowSubdomains) {
  const host = normalizeHost(hostname);
  if (!allowedDomains.length) return false;
  if (allowedDomains.includes(host)) return true;
  if (!allowSubdomains) return false;
  return allowedDomains.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function isHostAllowed(hostname) {
  return isHostAllowedForList(hostname, SECURE_ALLOWED_DOMAINS, SECURE_ALLOW_SUBDOMAINS);
}

function checkSecureUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return { ok: false, error: 'Invalid URL' };
  }
  if (!SECURE_ALLOW_HTTP && parsed.protocol !== 'https:') {
    return { ok: false, error: 'HTTPS required in secure lane' };
  }
  if (!SECURE_ALLOW_PRIVATE && (isPrivateHost(parsed.hostname) || parsed.hostname.endsWith('.local'))) {
    return { ok: false, error: 'Private/local targets are blocked in secure lane' };
  }
  if (!isHostAllowed(parsed.hostname)) {
    return { ok: false, error: 'Domain not allowed in secure lane' };
  }
  return { ok: true, parsed };
}

function checkAllowedUrl(url, allowedDomains, allowSubdomains, allowHttp) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return { ok: false, error: 'Invalid URL' };
  }
  if (!allowHttp && parsed.protocol !== 'https:') {
    return { ok: false, error: 'HTTPS required' };
  }
  if (isPrivateHost(parsed.hostname) || parsed.hostname.endsWith('.local')) {
    return { ok: false, error: 'Private/local targets are blocked' };
  }
  if (!isHostAllowedForList(parsed.hostname, allowedDomains, allowSubdomains)) {
    return { ok: false, error: 'Domain not allowed' };
  }
  return { ok: true, parsed };
}

function validateBrowserActions(actions, allowSensitive) {
  if (!Array.isArray(actions) || actions.length === 0) {
    return { ok: false, error: 'actions array required' };
  }
  if (actions.length > VAULT_BROWSER_MAX_ACTIONS) {
    return { ok: false, error: `actions exceeds max (${VAULT_BROWSER_MAX_ACTIONS})` };
  }
  if (allowSensitive) {
    return { ok: true };
  }

  for (const action of actions) {
    if (!action || typeof action !== 'object') continue;
    if (action.type === 'type' && typeof action.text === 'string') {
      const warnings = detectSensitiveData(action.text);
      if (warnings.length > 0) {
        return {
          ok: false,
          error: 'Sensitive input blocked for vault browser',
          warnings
        };
      }
    }
  }

  return { ok: true };
}

function requireRemoteViewEnabled(req, res, next) {
  if (!REMOTE_VIEW_ENABLED) {
    return res.status(404).json({ error: 'Remote view disabled' });
  }
  return next();
}

function extractAdminToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  if (auth.startsWith('Token ')) return auth.slice(6).trim();
  return (
    req.headers['x-api-key'] ||
    req.headers['x-admin-token'] ||
    ''
  ).toString().trim();
}

function isAdminRequest(req) {
  if (ADMIN_TOKEN) {
    const token = extractAdminToken(req);
    return token === ADMIN_TOKEN;
  }
  if (ALLOW_INSECURE_VAULT || isLocalRequest(req)) {
    return true;
  }
  return false;
}

function requireVaultAdmin(req, res, next) {
  if (isAdminRequest(req)) return next();
  return res.status(403).json({ error: 'Vault admin token required for non-local access' });
}

let browser = null;
let vaultInitialized = false;

// Protect Vault endpoints by default
app.use('/vault', requireVaultAdmin);

// ZKP Provider (for service providers)
const zkpProvider = new ZKPProvider({ name: 'sakaki-main' });

// Protect all ZKP endpoints by default
app.use('/zkp', requireVaultAdmin);

// Protect secure lane endpoints
app.use('/secure', requireVaultAdmin);

// Browser initialization
async function initBrowser() {
  const baseArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-crashpad',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    ...PUPPETEER_EXTRA_ARGS
  ];
  const fallbackArgs = [...baseArgs, '--no-zygote', '--single-process'];
  const launch = (args) => launchBrowser(BACKEND_CONFIG, {
    headless: HEADLESS_MODE,
    args
  });
  if (PUPPETEER_FORCE_SINGLE_PROCESS) {
    browser = await launch(fallbackArgs);
  } else {
    browser = await launch(baseArgs).catch(() => launch(fallbackArgs));
  }
  const label = `${BACKEND_CONFIG.backend}/${BACKEND_CONFIG.browserType}`;
  const extra = BACKEND_CONFIG.executablePath ? ` (${BACKEND_CONFIG.executablePath})` : '';
  console.log(`[Sakaki-Browser] Browser initialized: ${label}${extra}`);
}

// Comprehensive security check
async function fullSecurityCheck(url, page = null) {
  const results = {
    allowed: true,
    warnings: [],
    checks: {},
    risk: 'safe'
  };

  // 0. Input sanitization (URL spoofing countermeasure)
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
let securePage = null;
let secureMonitor = null;

const remoteSessions = new Map(); // sessionId -> session

function getLanePage(lane) {
  if (lane === 'secure') return securePage;
  if (lane === 'public') return currentPage;
  return null;
}

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

async function getViewportSize(page) {
  try {
    const vp = typeof page.viewport === 'function'
      ? page.viewport()
      : (typeof page.viewportSize === 'function' ? page.viewportSize() : null);
    if (vp && vp.width && vp.height) {
      return { width: vp.width, height: vp.height };
    }
    return await page.evaluate(() => ({
      width: window.innerWidth,
      height: window.innerHeight
    }));
  } catch {
    return { width: 0, height: 0 };
  }
}

async function screenshotBase64(page, options = {}) {
  if (!page || typeof page.screenshot !== 'function') return null;
  const opts = { ...options, encoding: 'base64' };
  try {
    return await page.screenshot(opts);
  } catch {
    const { encoding, ...rest } = opts;
    const buffer = await page.screenshot(rest);
    return buffer ? buffer.toString('base64') : null;
  }
}

function signRemotePayload(key, payload) {
  const signature = crypto.createHmac('sha256', key).update(payload).digest('hex');
  return { signature, algorithm: 'sha256-hmac' };
}

function verifyRemotePayload(key, payload, signature) {
  const expected = crypto.createHmac('sha256', key).update(payload).digest('hex');
  return expected === signature;
}

function sanitizeRemoteText(text) {
  if (!REMOTE_VIEW_BLOCK_SENSITIVE) return { ok: true };
  const warnings = detectSensitiveData(text);
  if (warnings.length > 0) {
    return { ok: false, warnings };
  }
  return { ok: true };
}

const challengeCooldown = new WeakMap();
const challengeResolvedCooldown = new WeakMap();
const challengeState = new WeakMap();

const CHALLENGE_URL_PATTERNS = [
  /captcha/i,
  /challenge/i,
  /verify/i,
  /verification/i,
  /two[-_]?factor/i,
  /\\b2fa\\b/i,
  /\\bmfa\\b/i,
  /\\botp\\b/i,
  /turnstile/i,
  /cloudflare/i,
  /arkoselabs/i
];
const CHALLENGE_URL_EXTRA = parseRegexList(process.env.SAKAKI_CHALLENGE_URL_REGEX);

const CHALLENGE_TEXT_PATTERNS = [
  /verify (you are|you're) human/i,
  /i am not a robot/i,
  /security check/i,
  /verification code/i,
  /one[- ]time code/i,
  /authentication code/i,
  /enter.*code/i,
  /two[- ]factor/i,
  /multi[- ]factor/i,
  /captcha/i,
  /robot check/i
];
const CHALLENGE_TEXT_EXTRA = parseRegexList(process.env.SAKAKI_CHALLENGE_TEXT_REGEX);

const CHALLENGE_SELECTORS = [
  'iframe[src*="recaptcha"]',
  'iframe[src*="hcaptcha"]',
  'iframe[src*="turnstile"]',
  'iframe[src*="arkoselabs"]',
  'div.g-recaptcha',
  'div.h-captcha',
  'input[name*="captcha"]',
  '[id*="captcha"]'
];
const CHALLENGE_SELECTOR_EXTRA = (() => {
  const raw = process.env.SAKAKI_CHALLENGE_SELECTOR || '';
  if (!raw) return [];
  const sep = raw.includes(';') ? ';' : ',';
  return raw.split(sep).map(s => s.trim()).filter(Boolean);
})();

function shouldNotifyChallenge(page) {
  if (!page) return true;
  const now = Date.now();
  const last = challengeCooldown.get(page);
  if (last && (now - last) < CHALLENGE_NOTIFY_COOLDOWN_MS) {
    return false;
  }
  challengeCooldown.set(page, now);
  return true;
}

function shouldNotifyResolved(page) {
  if (!page) return true;
  const now = Date.now();
  const last = challengeResolvedCooldown.get(page);
  if (last && (now - last) < CHALLENGE_NOTIFY_COOLDOWN_MS) {
    return false;
  }
  challengeResolvedCooldown.set(page, now);
  return true;
}

function getChallengeState(page) {
  if (!page) return { active: false };
  let state = challengeState.get(page);
  if (!state) {
    state = { active: false, kind: null, evidence: [], url: null };
    challengeState.set(page, state);
  }
  return state;
}

function shouldNotifySession(session, key) {
  const now = Date.now();
  const last = session[key] || 0;
  if (now - last < CHALLENGE_NOTIFY_COOLDOWN_MS) return false;
  session[key] = now;
  return true;
}

async function handleVaultChallengeResult(session, result, lane) {
  if (!result || !result.success) return;
  if (!result.detected) {
    if (session.challengeActive) {
      session.challengeActive = false;
      if (shouldNotifySession(session, 'lastChallengeResolvedAt')) {
        notificationCenter.notify({
          type: 'challenge_resolved',
          severity: 'info',
          message: `Challenge resolved (${session.challengeKind || 'unknown'})`,
          data: {
            lane,
            url: session.challengeUrl || null,
            kind: session.challengeKind,
            evidence: session.challengeEvidence || []
          }
        });
      }
      if (session.autoStopOnResolve) {
        closeRemoteSession(session.id, 'challenge_resolved');
      }
    }
    return;
  }

  session.challengeActive = true;
  session.challengeKind = result.kind;
  session.challengeEvidence = result.evidence || [];
  session.challengeUrl = result.url || null;

  if (shouldNotifySession(session, 'lastChallengeNotifyAt')) {
    const view = buildRemoteViewInfo(session);
    notificationCenter.notify({
      type: 'challenge_required',
      severity: 'warn',
      message: `Challenge detected (${result.kind})`,
      data: {
        lane,
        url: session.challengeUrl,
        kind: result.kind,
        score: result.score,
        threshold: result.threshold,
        evidence: result.evidence || [],
        viewUrl: view?.viewUrl || null
      }
    });
  }
}

async function maybeCheckChallengeForPage(session, page, lane) {
  const now = Date.now();
  if (now - (session.lastChallengeCheckAt || 0) < 1000) return;
  session.lastChallengeCheckAt = now;
  await handleChallenge({ lane, page, url: page.url() });
}

function findRemoteSessionForPage(page) {
  if (!page) return null;
  for (const session of remoteSessions.values()) {
    if (session.page === page) return session;
  }
  return null;
}

function buildRemoteViewInfo(session) {
  if (!session) return null;
  return {
    sessionId: session.id,
    viewUrl: `/remote/view/${session.id}?token=${session.token}`,
    expiresAt: session.expiresAt
  };
}

function touchRemoteSession(session) {
  const now = Date.now();
  session.lastActivityAt = now;
  if (REMOTE_VIEW_ACTIVITY_EXTEND_MS > 0) {
    const next = now + REMOTE_VIEW_ACTIVITY_EXTEND_MS;
    session.expiresAt = Math.min(session.maxExpiresAt, next);
  }
}

function startRemoteSession({
  lane,
  page,
  vaultSessionId,
  lastSize,
  allowInput,
  allowText,
  allowScroll,
  fps,
  quality,
  autoStopOnResolve
}) {
  if (remoteSessions.size >= REMOTE_VIEW_MAX_SESSIONS) {
    return { success: false, error: 'Too many remote sessions' };
  }

  const sessionId = randomId(12);
  const token = randomId(16);
  const key = Buffer.from(token, 'hex');
  const now = Date.now();
  const maxTtl = Number.isFinite(REMOTE_VIEW_MAX_TTL_MS) && REMOTE_VIEW_MAX_TTL_MS > 0
    ? REMOTE_VIEW_MAX_TTL_MS
    : REMOTE_VIEW_TTL_MS;

  const session = {
    id: sessionId,
    token,
    key,
    lane,
    page: page || null,
    vaultSessionId: vaultSessionId || null,
    fps: Math.min(Math.max(parseInt(fps, 10) || REMOTE_VIEW_DEFAULT_FPS, 1), 15),
    quality: Math.min(Math.max(parseInt(quality, 10) || REMOTE_VIEW_DEFAULT_QUALITY, 30), 90),
    allowInput: !!allowInput,
    allowText: !!allowText,
    allowScroll: !!allowScroll,
    createdAt: now,
    expiresAt: now + REMOTE_VIEW_TTL_MS,
    maxExpiresAt: now + maxTtl,
    clients: new Set(),
    lastFrameHash: null,
    lastSize: lastSize || { width: 0, height: 0 },
    lastCounter: 0,
    lastCommandCounter: 0,
    lastActivityAt: now,
    lastChallengeCheckAt: 0,
    challengeActive: false,
    challengeKind: null,
    challengeEvidence: [],
    challengeUrl: null,
    lastChallengeNotifyAt: 0,
    lastChallengeResolvedAt: 0,
    autoStopOnResolve: !!autoStopOnResolve
  };

  remoteSessions.set(sessionId, session);

  session.timer = setInterval(async () => {
    const now = Date.now();
    if (now > session.expiresAt) {
      closeRemoteSession(sessionId, 'expired');
      return;
    }
    if (REMOTE_VIEW_IDLE_TIMEOUT_MS > 0 && (now - (session.lastActivityAt || 0)) > REMOTE_VIEW_IDLE_TIMEOUT_MS) {
      closeRemoteSession(sessionId, 'idle_timeout');
      return;
    }

    if (session.clients.size > 0) {
      touchRemoteSession(session);
    }

    try {
      let screenshot;
      let size = session.lastSize;
      let hash;

      if (session.lane === 'vault') {
        if (!session.vaultSessionId) {
          closeRemoteSession(sessionId, 'vault_missing');
          return;
        }
        const frame = await vaultClient.send('browserRemoteFrame', {
          sessionId: session.vaultSessionId,
          quality: session.quality,
          force: session.lastFrameHash === null
        });
        if (!frame.success) {
          closeRemoteSession(sessionId, 'vault_error');
          return;
        }
        if (!frame.changed) {
          return;
        }
        screenshot = Buffer.from(frame.data, 'base64');
        size = frame.size || size;
        hash = frame.hash || fastHash.hash(screenshot).hash;
        session.lastSize = size;
      } else {
        if (!session.page || session.page.isClosed()) {
          closeRemoteSession(sessionId, 'page_closed');
          return;
        }
        screenshot = await session.page.screenshot({
          type: 'jpeg',
          quality: session.quality
        });
        hash = fastHash.hash(screenshot).hash;
        size = await getViewportSize(session.page);
        session.lastSize = size;
      }

      if (hash === session.lastFrameHash) {
        return;
      }
      session.lastFrameHash = hash;

      const counter = ++session.lastCounter;
      const ts = Date.now();
      const payload = Buffer.concat([
        Buffer.from(`${counter}|${ts}|`),
        screenshot
      ]);
      const signed = signRemotePayload(session.key, payload);

      const frameMsg = JSON.stringify({
        type: 'frame',
        counter,
        ts,
        width: size.width,
        height: size.height,
        hash,
        alg: signed.algorithm,
        sig: signed.signature,
        data: screenshot.toString('base64')
      });

      for (const ws of session.clients) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(frameMsg);
        }
      }
    } catch (err) {
      // Ignore transient errors
    }
  }, Math.max(1000 / session.fps, 50));

  return {
    success: true,
    sessionId,
    viewUrl: `/remote/view/${sessionId}?token=${token}`,
    expiresAt: session.expiresAt
  };
}

async function detectChallenge(page) {
  if (!page || page.isClosed()) return { detected: false };
  const evidence = [];
  let url = '';
  let title = '';

  try { url = page.url(); } catch {}
  try { title = await page.title(); } catch {}

  const urlLower = (url || '').toLowerCase();
  const titleLower = (title || '').toLowerCase();
  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {}

  if (hostname && domainMatches(hostname, CHALLENGE_DOMAIN_IGNORE)) {
    return { detected: false, skipped: 'domain_ignore', url, title };
  }
  if (hostname && domainMatches(hostname, CHALLENGE_DOMAIN_FORCE)) {
    return {
      detected: true,
      kind: 'challenge',
      score: CHALLENGE_MIN_SCORE,
      threshold: CHALLENGE_MIN_SCORE,
      url,
      title,
      evidence: [`domain:${hostname}`]
    };
  }

  for (const pattern of CHALLENGE_URL_PATTERNS.concat(CHALLENGE_URL_EXTRA)) {
    if (pattern.test(urlLower)) {
      evidence.push(`url:${pattern}`);
      break;
    }
  }

  for (const pattern of CHALLENGE_URL_PATTERNS.concat(CHALLENGE_URL_EXTRA)) {
    if (pattern.test(titleLower)) {
      evidence.push(`title:${pattern}`);
      break;
    }
  }

  for (const sel of CHALLENGE_SELECTORS.concat(CHALLENGE_SELECTOR_EXTRA)) {
    try {
      const el = await page.$(sel);
      if (el) {
        evidence.push(`selector:${sel}`);
        break;
      }
    } catch {}
  }

  if (CHALLENGE_TEXT_LIMIT > 0) {
    try {
      const text = await page.evaluate((limit) => {
        const body = document.body;
        const t = body ? body.innerText || '' : '';
        return t.slice(0, limit);
      }, CHALLENGE_TEXT_LIMIT);

      for (const pattern of CHALLENGE_TEXT_PATTERNS.concat(CHALLENGE_TEXT_EXTRA)) {
        if (pattern.test(text)) {
          evidence.push(`text:${pattern}`);
          break;
        }
      }
    } catch {}
  }

  if (evidence.length === 0) {
    return { detected: false };
  }

  let score = 0;
  for (const ev of evidence) {
    if (ev.startsWith('selector:')) score += 3;
    else if (ev.startsWith('url:')) score += 2;
    else if (ev.startsWith('title:')) score += 1;
    else if (ev.startsWith('text:')) score += 2;
  }

  if (score < CHALLENGE_MIN_SCORE) {
    return {
      detected: false,
      score,
      threshold: CHALLENGE_MIN_SCORE,
      evidence,
      url,
      title
    };
  }

  const evidenceStr = evidence.join(' ');
  let kind = 'challenge';
  if (/captcha|recaptcha|hcaptcha|turnstile|arkoselabs/i.test(evidenceStr)) {
    kind = 'captcha';
  } else if (/two[-_]?factor|\\b2fa\\b|\\bmfa\\b|\\botp\\b|verification code|one[- ]time/i.test(evidenceStr)) {
    kind = 'mfa';
  }

  return {
    detected: true,
    kind,
    score,
    threshold: CHALLENGE_MIN_SCORE,
    url,
    title,
    evidence
  };
}

async function handleChallenge({ lane, page, url }) {
  const state = getChallengeState(page);
  const challenge = await detectChallenge(page);
  if (!challenge.detected) {
    if (state.active) {
      state.active = false;
      const existing = findRemoteSessionForPage(page);
      if (existing && existing.autoStopOnResolve) {
        closeRemoteSession(existing.id, 'challenge_resolved');
      }
      if (shouldNotifyResolved(page)) {
        notificationCenter.notify({
          type: 'challenge_resolved',
          severity: 'info',
          message: `Challenge resolved (${state.kind || 'unknown'})`,
          data: {
            lane,
            url: state.url || url || null,
            kind: state.kind,
            evidence: state.evidence || []
          }
        });
      }
    }
    return null;
  }

  state.active = true;
  state.kind = challenge.kind;
  state.evidence = challenge.evidence;
  state.url = challenge.url || url || null;

  let remoteView = null;
  if (REMOTE_VIEW_ENABLED && CHALLENGE_AUTO_REMOTE) {
    const existing = findRemoteSessionForPage(page);
    if (existing) {
      remoteView = buildRemoteViewInfo(existing);
    } else {
      const allowText = challenge.kind === 'mfa';
      const started = startRemoteSession({
        lane,
        page,
        allowInput: true,
        allowText,
        allowScroll: true,
        autoStopOnResolve: true
      });
      remoteView = started.success ? {
        sessionId: started.sessionId,
        viewUrl: started.viewUrl,
        expiresAt: started.expiresAt
      } : { error: started.error };
    }
  }

  let eventId = null;
  if (shouldNotifyChallenge(page)) {
    const event = notificationCenter.notify({
      type: 'challenge_required',
      severity: 'warn',
      message: `Challenge detected (${challenge.kind})`,
      data: {
        lane,
        url: url || challenge.url,
        kind: challenge.kind,
        score: challenge.score,
        threshold: challenge.threshold,
        evidence: challenge.evidence,
        viewUrl: remoteView?.viewUrl || null
      }
    });
    eventId = event.id;
  }

  return {
    blocked: true,
    reason: 'challenge_required',
    challenge: {
      kind: challenge.kind,
      score: challenge.score,
      threshold: challenge.threshold,
      evidence: challenge.evidence,
      url: url || challenge.url
    },
    remoteView,
    eventId
  };
}

function notifyApprovalRequired({ lane, reason, url, warnings, fields, selector }) {
  try {
    notificationCenter.notify({
      type: 'approval_required',
      severity: 'warn',
      message: reason || 'Human approval required',
      data: {
        lane: lane || 'default',
        url: url || null,
        selector: selector || null,
        fields: fields || null,
        warnings: warnings || []
      }
    });
  } catch {}
}

function closeRemoteSession(sessionId, reason) {
  const session = remoteSessions.get(sessionId);
  if (!session) return;
  if (session.timer) clearInterval(session.timer);
  session.timer = null;
  session.closed = true;
  session.closeReason = reason || 'closed';
  if (session.lane === 'vault' && session.vaultSessionId) {
    vaultClient.send('browserRemoteStop', { sessionId: session.vaultSessionId }).catch(() => {});
  }
  for (const ws of session.clients) {
    try { ws.close(); } catch {}
  }
  remoteSessions.delete(sessionId);
}

function ensureSecureLaneEnabled(res) {
  if (!SECURE_ALLOWED_DOMAINS.length) {
    res.json({
      error: 'Secure lane disabled',
      message: 'Set SAKAKI_SECURE_ALLOWED_DOMAINS to enable secure browsing',
      hint: 'Example: SAKAKI_SECURE_ALLOWED_DOMAINS=example.com,login.example.com'
    });
    return false;
  }
  return true;
}

function ensureSecurePage(res) {
  if (!securePage) {
    res.json({ error: 'No secure page open. Call /secure/navigate first' });
    return null;
  }
  return securePage;
}

function allowOpaqueUrl(url) {
  return (
    url.startsWith('data:') ||
    url.startsWith('blob:') ||
    url === 'about:blank'
  );
}

function checkSecureRequestUrl(url) {
  if (allowOpaqueUrl(url)) return { ok: true };
  return checkSecureUrl(url);
}

async function createSecurePage() {
  const page = await browser.newPage();
  await attachRequestInterception(page, (req) => {
    const url = req.url();
    const guard = checkSecureRequestUrl(url);
    if (!guard.ok) {
      return req.abort();
    }
    return req.continue();
  }, BROWSER_BACKEND);
  return page;
}

app.post('/navigate', async (req, res) => {
  const { url, skipSecurityCheck } = req.body;
  if (!enforceA2ATool(req, res, 'navigate')) return;
  if (!enforceA2ADomain(req, res, url, 'navigate')) return;

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

    await currentPage.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });

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

    const challenge = await handleChallenge({
      lane: 'public',
      page: currentPage,
      url
    });
    if (challenge && challenge.blocked) {
      return res.json(challenge);
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
  if (!enforceA2ATool(req, res, 'screenshot')) return;
  if (url && !enforceA2ADomain(req, res, url, 'screenshot')) return;

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
      await page.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });
      const screenshot = await screenshotBase64(page, { path: outputPath });
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
    if (!enforceA2ADomain(req, res, currentPage.url(), 'screenshot')) return;
    if (outputPath) {
      // Save to file
      await currentPage.screenshot({ path: outputPath });
      guardian.logAction('screenshot', { path: outputPath }, 'safe', false);
      res.json({ success: true, path: outputPath });
    } else {
      // Return base64
      const screenshot = await screenshotBase64(currentPage);
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
  if (!enforceA2ATool(req, res, 'type')) return;
  if (!enforceA2ADomain(req, res, currentPage.url(), 'type')) return;
  if (!enforceA2ATool(req, res, 'click')) return;
  if (!enforceA2ADomain(req, res, currentPage.url(), 'click')) return;

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

    try {
      await currentPage.waitForTimeout(600);
    } catch {}

    const challenge = await handleChallenge({
      lane: 'public',
      page: currentPage,
      url: currentPage.url()
    });
    if (challenge && challenge.blocked) {
      return res.json(challenge);
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

// Type secret from vault (disabled for safety)
app.post('/type-secret', (req, res) => {
  res.status(410).json({
    error: 'Endpoint disabled',
    message: '/type-secret has been disabled to avoid exposing secrets outside the Vault process.',
    hint: 'Use /vault/proxy for API calls or design a vault-side browser control flow.'
  });
});

// Form submission (with sensitive data check)
app.post('/submit-form', async (req, res) => {
  const { url, formData, selector } = req.body;
  if (!enforceA2ATool(req, res, 'submit_form')) return;
  if (!enforceA2ADomain(req, res, url, 'submit_form')) return;

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
    notifyApprovalRequired({
      lane: 'default',
      reason: 'Sensitive data detected - requires approval',
      url,
      warnings: vaultCheck.warnings,
      fields: Object.keys(formData || {})
    });
    return res.json({
      blocked: true,
      reason: 'Sensitive data detected - requires approval',
      warnings: vaultCheck.warnings
    });
  }

  try {
    rateLimiter.recordRequest(url);
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });

    // Fill form fields
    for (const [field, value] of Object.entries(formData)) {
      await page.type(`[name="${field}"]`, value);
    }

    // Submit
    if (selector) {
      await page.click(selector);
      await page.waitForNavigation({ waitUntil: WAIT_UNTIL_NETWORK_IDLE });
    }

    const challenge = await handleChallenge({
      lane: 'public',
      page,
      url: page.url()
    });
    if (challenge && challenge.blocked) {
      if (currentPage) {
        try { await currentPage.close(); } catch {}
        currentPage = null;
        rateLimiter.pageClosed();
        if (currentMonitor) currentMonitor.stop();
        currentMonitor = null;
      }
      currentPage = page;
      currentMonitor = await resourceMonitor.monitorPage(currentPage);
      rateLimiter.pageOpened();
      return res.json(challenge);
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

// ========== Secure lane (restricted browsing for sensitive workflows) ==========
app.post('/secure/navigate', async (req, res) => {
  if (!ensureSecureLaneEnabled(res)) return;
  const { url } = req.body;
  if (!url) return res.json({ error: 'url required' });
  if (!enforceA2ATool(req, res, 'secure_navigate')) return;
  if (!enforceA2ADomain(req, res, url, 'secure_navigate')) return;

  const guard = checkSecureUrl(url);
  if (!guard.ok) {
    return res.json({ blocked: true, reason: guard.error });
  }

  const securityCheck = await fullSecurityCheck(url);
  if (!securityCheck.allowed) {
    return res.json({
      blocked: true,
      reason: 'Security check failed',
      warnings: securityCheck.warnings,
      risk: securityCheck.risk,
      checks: securityCheck.checks
    });
  }

  try {
    if (securePage) {
      try {
        await securePage.close();
        rateLimiter.pageClosed();
        if (secureMonitor) secureMonitor.stop();
      } catch {}
    }

    rateLimiter.recordRequest(url);
    rateLimiter.pageOpened();

    securePage = await createSecurePage();
    secureMonitor = await resourceMonitor.monitorPage(securePage);

    await securePage.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });

    const phishingCheck = await phishing.checkPhishing(url, securePage);
    if (phishingCheck.isPhishing) {
      await securePage.close();
      securePage = null;
      rateLimiter.pageClosed();
      secureMonitor.stop();
      secureMonitor = null;
      return res.json({
        blocked: true,
        reason: 'Phishing detected after page load',
        phishingScore: phishingCheck.score,
        warnings: phishingCheck.warnings
      });
    }

    const challenge = await handleChallenge({
      lane: 'secure',
      page: securePage,
      url
    });
    if (challenge && challenge.blocked) {
      return res.json(challenge);
    }

    const title = await securePage.title();
    const metrics = secureMonitor.getMetrics();

    const allWarnings = [
      ...(securityCheck.warnings || []),
      ...phishingCheck.warnings.map(w => w.message || w)
    ].filter(Boolean);

    guardian.logAction('secure-navigate', { url }, securityCheck.risk || 'safe', false);

    res.json({
      success: true,
      title,
      url,
      metrics,
      phishingScore: phishingCheck.score,
      risk: securityCheck.risk || 'safe',
      warnings: allWarnings.length > 0 ? allWarnings : undefined
    });
  } catch (err) {
    if (securePage) {
      try { await securePage.close(); } catch {}
      securePage = null;
    }
    rateLimiter.pageClosed();
    res.json({
      error: err.message,
      risk: securityCheck.risk || 'unknown',
      warnings: securityCheck.warnings || []
    });
  }
});

app.post('/secure/close', async (req, res) => {
  if (securePage) {
    try {
      await securePage.close();
      securePage = null;
      rateLimiter.pageClosed();
      if (secureMonitor) {
        secureMonitor.stop();
        secureMonitor = null;
      }
      res.json({ success: true });
    } catch (err) {
      res.json({ error: err.message });
    }
  } else {
    res.json({ success: true, message: 'No secure page open' });
  }
});

app.post('/secure/screenshot', async (req, res) => {
  if (!ensureSecureLaneEnabled(res)) return;
  const { url, path: outputPath } = req.body;
  if (!enforceA2ATool(req, res, 'secure_screenshot')) return;
  if (url && !enforceA2ADomain(req, res, url, 'secure_screenshot')) return;

  if (url) {
    const guard = checkSecureUrl(url);
    if (!guard.ok) return res.json({ blocked: true, reason: guard.error });

    try {
      rateLimiter.recordRequest(url);
      rateLimiter.pageOpened();

      const page = await createSecurePage();
      await page.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });
      const screenshot = await screenshotBase64(page, { path: outputPath });
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

  const page = ensureSecurePage(res);
  if (!page) return;

  try {
    if (!enforceA2ADomain(req, res, page.url(), 'secure_screenshot')) return;
    if (outputPath) {
      await page.screenshot({ path: outputPath });
      guardian.logAction('secure-screenshot', { path: outputPath }, 'safe', false);
      res.json({ success: true, path: outputPath });
    } else {
      const screenshot = await screenshotBase64(page);
      guardian.logAction('secure-screenshot', {}, 'safe', false);
      res.json({ success: true, screenshot });
    }
  } catch (err) {
    res.json({ error: err.message });
  }
});

app.post('/secure/click', async (req, res) => {
  const { selector } = req.body;
  if (!selector) return res.json({ error: 'selector required' });

  const page = ensureSecurePage(res);
  if (!page) return;
  if (!enforceA2ATool(req, res, 'secure_click')) return;
  if (!enforceA2ADomain(req, res, page.url(), 'secure_click')) return;

  const guard = checkSecureRequestUrl(page.url());
  if (!guard.ok) {
    return res.json({ blocked: true, reason: guard.error });
  }

  try {
    let clicked = false;
    try {
      const found = await semanticFinder.find(page, selector);
      if (found && found.element) {
        await found.element.click();
        clicked = true;
      }
    } catch {}

    if (!clicked) {
      await page.click(selector);
    }

    try {
      await page.waitForTimeout(600);
    } catch {}

    const challenge = await handleChallenge({
      lane: 'secure',
      page,
      url: page.url()
    });
    if (challenge && challenge.blocked) {
      return res.json(challenge);
    }

    guardian.logAction('secure-click', { selector }, 'safe', false);
    res.json({ success: true, selector });
  } catch (err) {
    guardian.logAction('secure-click', { selector }, 'error', false);
    res.json({ error: err.message });
  }
});

app.post('/secure/type', async (req, res) => {
  const { selector, text } = req.body;
  if (!selector || text === undefined) {
    return res.json({ error: 'selector and text required' });
  }

  if (!SECURE_ALLOW_SENSITIVE) {
    const warnings = detectSensitiveData(text);
    if (warnings.length > 0) {
      notifyApprovalRequired({
        lane: 'secure',
        reason: 'Sensitive input blocked in secure lane',
        warnings,
        selector
      });
      return res.json({
        blocked: true,
        reason: 'Sensitive input blocked in secure lane',
        warnings
      });
    }
  }

  const page = ensureSecurePage(res);
  if (!page) return;
  if (!enforceA2ATool(req, res, 'secure_type')) return;
  if (!enforceA2ADomain(req, res, page.url(), 'secure_type')) return;

  const guard = checkSecureRequestUrl(page.url());
  if (!guard.ok) {
    return res.json({ blocked: true, reason: guard.error });
  }

  try {
    let typed = false;
    try {
      const found = await semanticFinder.find(page, selector);
      if (found && found.element) {
        await found.element.type(text);
        typed = true;
      }
    } catch {}

    if (!typed) {
      await page.type(selector, text);
    }

    guardian.logAction('secure-type', { selector, length: text.length }, 'safe', false);
    res.json({ success: true, selector });
  } catch (err) {
    guardian.logAction('secure-type', { selector }, 'error', false);
    res.json({ error: err.message });
  }
});

app.post('/secure/submit-form', async (req, res) => {
  if (!ensureSecureLaneEnabled(res)) return;
  const { url, formData, selector } = req.body;
  if (!url || !formData) return res.json({ error: 'url and formData required' });
  if (!enforceA2ATool(req, res, 'secure_submit_form')) return;
  if (!enforceA2ADomain(req, res, url, 'secure_submit_form')) return;

  const guard = checkSecureUrl(url);
  if (!guard.ok) return res.json({ blocked: true, reason: guard.error });

  const secCheck = await fullSecurityCheck(url);
  if (!secCheck.allowed) {
    return res.json({
      blocked: true,
      reason: 'Security check failed',
      warnings: secCheck.warnings
    });
  }

  const vaultCheck = guardian.beforeFormSubmit(formData, url);
  if (vaultCheck.requiresApproval && !SECURE_ALLOW_SENSITIVE) {
    notifyApprovalRequired({
      lane: 'secure',
      reason: 'Sensitive data detected - secure lane blocks this by default',
      url,
      warnings: vaultCheck.warnings,
      fields: Object.keys(formData || {})
    });
    return res.json({
      blocked: true,
      reason: 'Sensitive data detected - secure lane blocks this by default',
      warnings: vaultCheck.warnings
    });
  }

  try {
    rateLimiter.recordRequest(url);
    rateLimiter.pageOpened();

    const page = await createSecurePage();
    await page.goto(url, { waitUntil: WAIT_UNTIL_NETWORK_IDLE });

    for (const [field, value] of Object.entries(formData)) {
      await page.type(`[name="${field}"]`, value);
    }

    if (selector) {
      await page.click(selector);
      await page.waitForNavigation({ waitUntil: WAIT_UNTIL_NETWORK_IDLE });
    }

    const challenge = await handleChallenge({
      lane: 'secure',
      page,
      url: page.url()
    });
    if (challenge && challenge.blocked) {
      if (securePage) {
        try { await securePage.close(); } catch {}
        securePage = null;
        rateLimiter.pageClosed();
      if (secureMonitor) secureMonitor.stop();
        secureMonitor = null;
      }
      securePage = page;
      secureMonitor = await resourceMonitor.monitorPage(securePage);
      return res.json(challenge);
    }

    await page.close();
    rateLimiter.pageClosed();

    res.json({ success: true, warnings: vaultCheck.warnings });
  } catch (err) {
    rateLimiter.pageClosed();
    res.json({ error: err.message });
  }
});

// ========== Remote View ==========
app.post('/remote/start', requireVaultAdmin, requireRemoteViewEnabled, async (req, res) => {
  const {
    lane = 'secure',
    fps = REMOTE_VIEW_DEFAULT_FPS,
    quality = REMOTE_VIEW_DEFAULT_QUALITY,
    allowInput = false,
    allowText = REMOTE_VIEW_ALLOW_TEXT,
    allowScroll = REMOTE_VIEW_ALLOW_SCROLL,
    startUrl,
    allowedDomains,
    allowSubdomains,
    allowHttp,
    allowPrivate
  } = req.body || {};

  if (!enforceA2ATool(req, res, 'remote_start')) return;

  if (remoteSessions.size >= REMOTE_VIEW_MAX_SESSIONS) {
    return res.status(429).json({ error: 'Too many remote sessions' });
  }

  let page = null;
  let vaultSessionId = null;
  let lastSize = { width: 0, height: 0 };

  if (lane === 'vault') {
    if (!vaultInitialized) {
      return res.json({ error: 'Vault not initialized. Call /vault/init first' });
    }
    const effectiveAllowed = Array.isArray(allowedDomains) && allowedDomains.length
      ? allowedDomains
      : SECURE_ALLOWED_DOMAINS;
    if (!effectiveAllowed.length) {
      return res.json({
        error: 'allowedDomains required',
        hint: 'Set SAKAKI_SECURE_ALLOWED_DOMAINS or pass allowedDomains'
      });
    }
    if (startUrl) {
      if (!enforceA2ADomain(req, res, startUrl, 'remote_start')) return;
      const guard = checkAllowedUrl(
        startUrl,
        effectiveAllowed.map(s => s.toLowerCase()),
        !!allowSubdomains || SECURE_ALLOW_SUBDOMAINS,
        !!allowHttp || SECURE_ALLOW_HTTP
      );
      if (!guard.ok) {
        return res.json({ blocked: true, reason: guard.error });
      }
    }
    if (!enforceA2ADomainList(req, res, effectiveAllowed, 'remote_start')) return;
    try {
      const vaultStart = await vaultClient.send('browserRemoteStart', {
        startUrl,
        allowedDomains: effectiveAllowed,
        allowSubdomains: !!allowSubdomains || SECURE_ALLOW_SUBDOMAINS,
        allowHttp: !!allowHttp || SECURE_ALLOW_HTTP,
        allowPrivate: !!allowPrivate || VAULT_BROWSER_ALLOW_PRIVATE,
        allowInput: !!allowInput,
        allowText: !!allowText,
        allowScroll: !!allowScroll
      });
      if (!vaultStart.success) {
        return res.json(vaultStart);
      }
      vaultSessionId = vaultStart.sessionId;
      lastSize = vaultStart.size || lastSize;
    } catch (e) {
      return res.json({ success: false, error: e.message });
    }
  } else {
    page = getLanePage(lane);
    if (!page) {
      return res.json({ error: `No ${lane} page open` });
    }
    if (!enforceA2ADomain(req, res, page.url(), 'remote_start')) return;
  }

  const started = startRemoteSession({
    lane,
    page,
    vaultSessionId,
    lastSize,
    allowInput,
    allowText,
    allowScroll,
    fps,
    quality
  });

  if (!started.success) {
    const status = started.error === 'Too many remote sessions' ? 429 : 400;
    return res.status(status).json(started);
  }

  res.json(started);
});

app.post('/remote/stop', requireVaultAdmin, requireRemoteViewEnabled, async (req, res) => {
  const { sessionId } = req.body || {};
  if (!sessionId) return res.json({ error: 'sessionId required' });
  if (!enforceA2ATool(req, res, 'remote_stop')) return;
  closeRemoteSession(sessionId, 'stopped');
  res.json({ success: true });
});

app.get('/remote/view/:id', requireRemoteViewEnabled, (req, res) => {
  const session = remoteSessions.get(req.params.id);
  if (!session) return res.status(404).send('Not found');
  const token = req.query.token;
  if (!token || token !== session.token) {
    if (!isAdminRequest(req)) {
      return res.status(403).send('Forbidden');
    }
  }

  const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sakaki Remote View</title>
    <style>
      :root { color-scheme: dark; }
      body { margin:0; background:#111; color:#fff; font-family: -apple-system, system-ui, sans-serif; }
      #wrap { display:flex; flex-direction:column; height:100vh; }
      #top { padding:8px 12px; font-size:12px; background:#181818; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
      #meta { display:flex; gap:6px; flex-wrap:wrap; }
      .badge { padding:2px 6px; border-radius:999px; background:#222; color:#bbb; font-size:11px; }
      .badge.on { background:#1f3f2a; color:#9ae6b4; }
      .badge.warn { background:#3f2a1f; color:#f6ad55; }
      #canvas { flex:1; width:100%; height:100%; touch-action: none; }
      #status { opacity:0.7; }
      #overlay { position:fixed; inset:0; display:none; align-items:center; justify-content:center; background:rgba(0,0,0,0.6); color:#fff; font-size:16px; }
    </style>
  </head>
  <body>
    <div id="wrap">
      <div id="top">
        Sakaki Remote View <span id="status">connecting...</span>
        <div id="meta">
          <span id="laneBadge" class="badge">lane: ${session.lane}</span>
          <span id="inputBadge" class="badge">input: off</span>
          <span id="textBadge" class="badge">text: off</span>
          <span id="scrollBadge" class="badge">scroll: off</span>
        </div>
      </div>
      <canvas id="canvas"></canvas>
    </div>
    <div id="overlay">Session closed</div>
    <script>
      const sessionId = ${JSON.stringify(session.id)};
      const token = ${JSON.stringify(session.token)};
      const wsUrl = ((location.protocol === 'https:') ? 'wss://' : 'ws://') + location.host + '/remote/ws?session=' + sessionId + '&token=' + token;
      const ws = new WebSocket(wsUrl);
      const canvas = document.getElementById('canvas');
      const ctx = canvas.getContext('2d');
      const status = document.getElementById('status');
      const overlay = document.getElementById('overlay');
      const laneBadge = document.getElementById('laneBadge');
      const inputBadge = document.getElementById('inputBadge');
      const textBadge = document.getElementById('textBadge');
      const scrollBadge = document.getElementById('scrollBadge');
      const encoder = new TextEncoder();
      const tokenBytes = Uint8Array.from(token.match(/.{2}/g).map(b => parseInt(b, 16)));
      const hmacKeyPromise = crypto.subtle.importKey(
        'raw',
        tokenBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
      );
      let lastSize = { width: 0, height: 0 };
      let lastCounter = 0;
      let cmdCounter = 0;
      let allowInput = ${session.allowInput ? 'true' : 'false'};
      let allowText = ${session.allowText ? 'true' : 'false'};
      let allowScroll = ${session.allowScroll ? 'true' : 'false'};

      async function hmacHexBytes(bytes) {
        const key = await hmacKeyPromise;
        const sig = await crypto.subtle.sign('HMAC', key, bytes);
        return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      function payloadString(counter, ts, cmd, x, y, deltaY, key, text) {
        return [counter, ts, cmd || '', x ?? '', y ?? '', deltaY ?? '', key ?? '', text ?? ''].join('|');
      }

      function resizeCanvas(w, h) {
        canvas.width = w;
        canvas.height = h;
        canvas.style.width = '100%';
        canvas.style.height = '100%';
      }

      function setBadge(el, enabled) {
        el.classList.toggle('on', !!enabled);
        el.classList.toggle('warn', !enabled);
      }

      function updateBadges() {
        setBadge(inputBadge, allowInput);
        setBadge(textBadge, allowText);
        setBadge(scrollBadge, allowScroll);
        inputBadge.textContent = 'input: ' + (allowInput ? 'on' : 'off');
        textBadge.textContent = 'text: ' + (allowText ? 'on' : 'off');
        scrollBadge.textContent = 'scroll: ' + (allowScroll ? 'on' : 'off');
      }

      ws.onopen = () => {
        status.textContent = 'connected';
        overlay.style.display = 'none';
      };
      ws.onclose = () => {
        status.textContent = 'closed';
        overlay.style.display = 'flex';
      };
      ws.onerror = () => {
        status.textContent = 'error';
      };

      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'hello') {
          allowInput = !!msg.allowInput;
          allowText = !!msg.allowText;
          allowScroll = !!msg.allowScroll;
          updateBadges();
          return;
        }
        if (msg.type !== 'frame') return;
        lastCounter = msg.counter;
        if (msg.width && msg.height && (msg.width !== lastSize.width || msg.height !== lastSize.height)) {
          lastSize = { width: msg.width, height: msg.height };
          resizeCanvas(msg.width, msg.height);
        }
        const binary = Uint8Array.from(atob(msg.data), c => c.charCodeAt(0));
        const header = encoder.encode(String(msg.counter) + '|' + String(msg.ts) + '|');
        const payload = new Uint8Array(header.length + binary.length);
        payload.set(header, 0);
        payload.set(binary, header.length);
        hmacHexBytes(payload).then((sig) => {
          if (sig !== msg.sig) return;
          const img = new Image();
          img.onload = () => {
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          };
          img.src = 'data:image/jpeg;base64,' + msg.data;
        }).catch(() => {});
      };

      async function sendCommand(payload) {
        if (ws.readyState !== WebSocket.OPEN) return;
        const ts = Date.now();
        const counter = ++cmdCounter;
        const p = payloadString(
          counter,
          ts,
          payload.cmd,
          payload.x,
          payload.y,
          payload.deltaY,
          payload.key,
          payload.text
        );
        const sig = await hmacHexBytes(encoder.encode(p));
        ws.send(JSON.stringify({ type: 'cmd', ts, counter, sig, ...payload }));
      }

      function positionToRatio(ev) {
        const rect = canvas.getBoundingClientRect();
        const x = (ev.clientX - rect.left) / rect.width;
        const y = (ev.clientY - rect.top) / rect.height;
        return { x: Math.min(Math.max(x, 0), 1), y: Math.min(Math.max(y, 0), 1) };
      }

      canvas.addEventListener('click', (ev) => {
        if (!allowInput) return;
        const { x, y } = positionToRatio(ev);
        sendCommand({ cmd: 'click', x, y });
      });

      canvas.addEventListener('wheel', (ev) => {
        if (!allowInput || !allowScroll) return;
        sendCommand({ cmd: 'scroll', deltaY: ev.deltaY });
      });

      window.addEventListener('keydown', (ev) => {
        if (!allowInput || !allowText) return;
        if (ev.key.length === 1 || ev.key === 'Enter' || ev.key === 'Backspace') {
          sendCommand({ cmd: 'key', key: ev.key });
        }
      });

      updateBadges();
    </script>
  </body>
</html>`;

  res.type('html').send(html);
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

  if (!enforceA2ATool(req, res, 'vault_proxy')) return;
  if (!enforceA2ADomain(req, res, request.url, 'vault_proxy')) return;

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

// Vault Browser: Execute actions inside Vault process
app.post('/vault/browser/execute', async (req, res) => {
  if (!vaultInitialized) {
    return res.json({ error: 'Vault not initialized' });
  }

  const {
    actions,
    allowedDomains,
    allowSubdomains,
    allowHttp,
    allowPrivate,
    allowSensitive,
    timeout
  } = req.body || {};

  const effectiveAllowedDomains = Array.isArray(allowedDomains) && allowedDomains.length
    ? allowedDomains
    : SECURE_ALLOWED_DOMAINS;

  if (!enforceA2ATool(req, res, 'vault_browser_execute')) return;
  if (!enforceA2ADomainList(req, res, effectiveAllowedDomains, 'vault_browser_execute')) return;

  if (!effectiveAllowedDomains.length) {
    return res.json({
      error: 'allowedDomains required',
      hint: 'Set SAKAKI_SECURE_ALLOWED_DOMAINS or pass allowedDomains in the request'
    });
  }

  const check = validateBrowserActions(actions, allowSensitive || VAULT_BROWSER_ALLOW_SENSITIVE);
  if (!check.ok) {
    return res.json(check);
  }

  const result = await vaultClient.browserExecute({
    actions,
    allowedDomains: effectiveAllowedDomains,
    allowSubdomains: !!allowSubdomains || SECURE_ALLOW_SUBDOMAINS,
    allowHttp: !!allowHttp || SECURE_ALLOW_HTTP,
    allowPrivate: !!allowPrivate || VAULT_BROWSER_ALLOW_PRIVATE,
    timeout
  });

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
app.get('/service/vault-enforcement', requireVaultAdmin, (req, res) => {
  res.json(vaultEnforcement.getConfig());
});

app.post('/service/vault-enforcement', requireVaultAdmin, (req, res) => {
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
app.post('/zkp/register-from-vault', requireVaultAdmin, async (req, res) => {
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
app.post('/zkp/verify-with-vault', requireVaultAdmin, async (req, res) => {
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
    a2a: getA2AStats(),
    rateLimit: rateLimiter.getStats(),
    resources: resourceMonitor.getStats(),
    threatIntel: threatIntel.getStats(),
    threatIntelCache: threatIntel.getCacheStats()
  });
});

app.get('/a2a/stats', (req, res) => {
  res.json(getA2AStats());
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
  const notifyStats = notificationCenter.getStats();
  const notifications = notificationCenter.list(10);

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
    .notif { padding: 8px 10px; border-bottom: 1px solid #1f2a4a; }
    .notif:last-child { border-bottom: none; }
    .notif .meta { font-size: 11px; opacity: 0.7; }
    .notif.warn { color: #ff0; }
    .notif.error { color: #f00; }
    .notif.info { color: #9ad; }
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

  <div class="card">
    <h2>Notifications</h2>
    <div class="stat">
      <div class="value">${notifyStats.total}</div>
      <div>Total Events</div>
    </div>
    <div class="stat">
      <div class="value">${notifyStats.webhooks}</div>
      <div>Webhooks</div>
    </div>
    <div class="stat">
      <div class="value ${notifyStats.emailConfigured ? '' : 'warn'}">${notifyStats.emailConfigured ? 'ON' : 'OFF'}</div>
      <div>Email</div>
    </div>
    <div style="margin-top: 10px; font-size: 12px;">
      ${notifications.length === 0 ? '<div class="notif info">No notifications</div>' : notifications.map(n => `
        <div class="notif ${n.severity}">
          <div><strong>${n.type}</strong> - ${n.message}</div>
          <div class="meta">${new Date(n.createdAt).toLocaleString()}</div>
        </div>
      `).join('')}
    </div>
  </div>

  <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>
  `);
});

// Notifications API (admin only for non-local access)
app.get('/notify/events', requireVaultAdmin, (req, res) => {
  const limit = parseInt(req.query.limit || '50', 10);
  res.json({ events: notificationCenter.list(limit) });
});

app.get('/notify/stats', requireVaultAdmin, (req, res) => {
  res.json(notificationCenter.getStats());
});

app.post('/notify/test', requireVaultAdmin, (req, res) => {
  const { type, message, severity, data } = req.body || {};
  const event = notificationCenter.notify({
    type: type || 'test_event',
    severity: severity || 'info',
    message: message || 'Test notification',
    data: data || { source: 'manual' }
  });
  res.json({ success: true, event });
});

app.get('/notify/webhooks', requireVaultAdmin, (req, res) => {
  res.json({ webhooks: notificationCenter.webhooks.slice() });
});

app.post('/notify/webhooks', requireVaultAdmin, (req, res) => {
  const { url } = req.body || {};
  const result = notificationCenter.registerWebhook(url);
  res.json(result);
});

app.delete('/notify/webhooks', requireVaultAdmin, (req, res) => {
  const { url } = req.body || {};
  const result = notificationCenter.unregisterWebhook(url);
  res.json(result);
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
      <div class="feature"><span class="icon">🚫</span> No public retrieve() API (Vault-only verification)</div>
      <div class="feature"><span class="icon">🔒</span> Separate process isolation</div>
      <div class="feature"><span class="icon">🧹</span> SecureBuffer auto-wipe</div>
      <div class="feature"><span class="icon">🛡️</span> Auto-lock on tamper</div>
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
  if (!enforceA2ATool(req, res, 'fast_open')) return;
  if (!enforceA2ADomain(req, res, url, 'fast_open')) return;

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
  if (!enforceA2ATool(req, res, 'fast_screenshot')) return;
  if (!enforceA2ADomain(req, res, pageData.page?.url?.(), 'fast_screenshot')) return;
  if (!enforceA2ATool(req, res, 'fast_dom')) return;
  if (!enforceA2ADomain(req, res, pageData.page?.url?.(), 'fast_dom')) return;
  if (!enforceA2ATool(req, res, 'fast_get_text')) return;
  if (!enforceA2ADomain(req, res, pageData.page?.url?.(), 'fast_get_text')) return;
  if (!enforceA2ATool(req, res, 'fast_type')) return;
  if (!enforceA2ADomain(req, res, pageData.page?.url?.(), 'fast_type')) return;
  if (!enforceA2ATool(req, res, 'fast_click')) return;
  if (!enforceA2ADomain(req, res, pageData.page?.url?.(), 'fast_click')) return;

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
  if (!enforceA2ATool(req, res, 'fast_close')) return;

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
  if (!enforceA2ATool(req, res, 'fast_login')) return;
  if (!enforceA2ADomain(req, res, url, 'fast_login')) return;

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

  if (!ADMIN_TOKEN && !ALLOW_INSECURE_VAULT) {
    console.warn('[Sakaki-Browser] SAKAKI_ADMIN_TOKEN not set. Vault endpoints are limited to local requests.');
  }
  if (!SECURE_ALLOWED_DOMAINS.length) {
    console.warn('[Sakaki-Browser] Secure lane disabled (SAKAKI_SECURE_ALLOWED_DOMAINS not set).');
  }

  if (SKIP_BROWSER_INIT) {
    console.warn('[Sakaki-Browser] SAKAKI_SKIP_BROWSER_INIT=1 (browser not initialized).');
  } else {
    await initBrowser();
  }

  const server = http.createServer(app);
  const wss = new WebSocket.Server({ server, path: '/remote/ws' });

  wss.on('connection', (ws, req) => {
    try {
      const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
      const sessionId = url.searchParams.get('session');
      const token = url.searchParams.get('token');

      if (!sessionId || !token) {
        ws.close();
        return;
      }

      const session = remoteSessions.get(sessionId);
      if (!session || session.token !== token) {
        ws.close();
        return;
      }

      session.clients.add(ws);
      session.lastFrameHash = null; // force next frame push
      touchRemoteSession(session);

      ws.send(JSON.stringify({
        type: 'hello',
        allowInput: session.allowInput,
        allowText: session.allowText,
        allowScroll: session.allowScroll,
        expiresAt: session.expiresAt
      }));

      ws.on('message', async (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (!msg || msg.type !== 'cmd') return;
          if (!session.allowInput) return;

          const counter = Number(msg.counter);
          const ts = Number(msg.ts || Date.now());
          if (!Number.isFinite(counter) || counter <= session.lastCommandCounter) return;
          if (Math.abs(Date.now() - ts) > 120000) return;

          const payload = [
            counter,
            ts,
            msg.cmd || '',
            msg.x ?? '',
            msg.y ?? '',
            msg.deltaY ?? '',
            msg.key ?? '',
            msg.text ?? ''
          ].join('|');

          if (!verifyRemotePayload(session.key, payload, msg.sig || '')) {
            return;
          }

          session.lastCommandCounter = counter;
          touchRemoteSession(session);

          if (session.lane === 'vault') {
            if (!session.vaultSessionId) return;
            await vaultClient.send('browserRemoteCommand', {
              sessionId: session.vaultSessionId,
              cmd: msg.cmd,
              x: msg.x,
              y: msg.y,
              deltaY: msg.deltaY,
              key: msg.key,
              text: msg.text
            });
            const now = Date.now();
            if (now - (session.lastChallengeCheckAt || 0) > 1000) {
              session.lastChallengeCheckAt = now;
              try {
                const chk = await vaultClient.send('browserRemoteChallenge', {
                  sessionId: session.vaultSessionId
                });
                await handleVaultChallengeResult(session, chk, 'vault');
              } catch {}
            }
            return;
          }

          const page = session.page;
          if (!page || page.isClosed()) {
            closeRemoteSession(session.id, 'page_closed');
            return;
          }

          const size = session.lastSize || await getViewportSize(page);
          const width = size.width || 1;
          const height = size.height || 1;

          if (msg.cmd === 'click') {
            const x = Math.max(0, Math.min(1, Number(msg.x)));
            const y = Math.max(0, Math.min(1, Number(msg.y)));
            await page.mouse.click(x * width, y * height);
            await maybeCheckChallengeForPage(session, page, session.lane === 'secure' ? 'secure' : 'public');
            return;
          }

          if (msg.cmd === 'scroll' && session.allowScroll) {
            const deltaY = Number(msg.deltaY) || 0;
            await page.mouse.wheel({ deltaY });
            await maybeCheckChallengeForPage(session, page, session.lane === 'secure' ? 'secure' : 'public');
            return;
          }

          if (msg.cmd === 'key' && session.allowText) {
            const key = String(msg.key || '');
            if (key.length === 0) return;
            if (REMOTE_VIEW_BLOCK_SENSITIVE) {
              const warnings = detectSensitiveData(key);
              if (warnings.length > 0) return;
            }
            await page.keyboard.press(key === 'Backspace' ? 'Backspace' : key);
            await maybeCheckChallengeForPage(session, page, session.lane === 'secure' ? 'secure' : 'public');
            return;
          }

          if (msg.cmd === 'type' && session.allowText) {
            const text = String(msg.text || '');
            const safe = sanitizeRemoteText(text);
            if (!safe.ok) return;
            await page.keyboard.type(text);
            await maybeCheckChallengeForPage(session, page, session.lane === 'secure' ? 'secure' : 'public');
            return;
          }
        } catch {
          // Ignore malformed commands
        }
      });

      ws.on('close', () => {
        session.clients.delete(ws);
      });
    } catch {
      ws.close();
    }
  });

  server.listen(PORT, BIND, () => {
    console.log(`[Sakaki-Browser] Listening on ${BIND}:${PORT}`);
    console.log(`[Sakaki-Browser] Dashboard: http://localhost:${PORT}/dashboard`);
    console.log('[Sakaki-Browser] Guardian + Phishing + RateLimiter + ResourceMonitor active');
  });
}

main().catch(console.error);
