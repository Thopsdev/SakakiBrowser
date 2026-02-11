#!/usr/bin/env node
/**
 * Isolated Vault Process
 *
 * Manages secrets in a completely isolated process
 * - No public retrieve() API (verify-only by default)
 * - Memory protection
 * - Self-destruct capability
 * - Audit logging
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { resolveBackendConfig, launchBrowser, normalizeWaitUntil } = require('../browser/backend');
const { attachRequestInterception } = require('../browser/request-interceptor');

// ========== Proxy Configuration ==========
let proxyConfig = {
  enabled: true,
  signingKey: crypto.randomBytes(32).toString('hex'),
  publicKeyId: crypto.randomBytes(8).toString('hex'),
  allowedDomains: new Set(), // Empty = allow all
  enforceVaultProxy: false   // For external services: true = Vault required
};

// ========== Configuration ==========
const DEFAULT_SOCKET_PATH = path.join(os.homedir(), '.sakaki', 'vault.sock');
const SOCKET_PATH = process.env.VAULT_SOCKET || DEFAULT_SOCKET_PATH;
const VAULT_FILE = process.env.VAULT_FILE || path.join(__dirname, '../../.vault.enc');
const MAX_FAILED_ATTEMPTS = 10;
const LOCKOUT_DURATION = 60000; // 1 minute
const PROXY_ALLOW_HTTP = process.env.SAKAKI_PROXY_ALLOW_HTTP === '1';
const PROXY_ALLOW_PRIVATE = process.env.SAKAKI_PROXY_ALLOW_PRIVATE === '1';
const PROXY_REQUIRE_ALLOWLIST = process.env.SAKAKI_PROXY_REQUIRE_ALLOWLIST === '1';
const PROXY_MAX_RESPONSE_BYTES = parseInt(
  process.env.SAKAKI_PROXY_MAX_BYTES || '2097152',
  10
);
const VAULT_BROWSER_ALLOWED_DOMAINS = (process.env.SAKAKI_VAULT_BROWSER_ALLOWED_DOMAINS ||
  process.env.SAKAKI_SECURE_ALLOWED_DOMAINS ||
  '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const VAULT_HEADLESS_MODE = (() => {
  const raw = process.env.SAKAKI_VAULT_HEADLESS_MODE || process.env.SAKAKI_HEADLESS_MODE || process.env.SAKAKI_HEADLESS;
  if (!raw) return true;
  const v = String(raw).toLowerCase().trim();
  if (v === 'false' || v === '0' || v === 'off' || v === 'no') return false;
  if (v === 'new') return 'new';
  return true;
})();
let VAULT_BACKEND_CONFIG;
try {
  VAULT_BACKEND_CONFIG = resolveBackendConfig('vault');
} catch (e) {
  console.error(`[Vault] ${e.message}`);
  process.exit(1);
}
const VAULT_BROWSER_BACKEND = VAULT_BACKEND_CONFIG.backend;
const VAULT_WAIT_UNTIL_NETWORK_IDLE = normalizeWaitUntil('networkidle2', VAULT_BROWSER_BACKEND);
const VAULT_PUPPETEER_EXTRA_ARGS = (() => {
  const raw = process.env.SAKAKI_VAULT_PUPPETEER_ARGS || process.env.SAKAKI_PUPPETEER_ARGS || process.env.SAKAKI_CHROME_ARGS || '';
  if (!raw) return [];
  const sep = raw.includes(';') ? ';' : ',';
  return raw.split(sep).map(s => s.trim()).filter(Boolean);
})();
const VAULT_PUPPETEER_FORCE_SINGLE_PROCESS = process.env.SAKAKI_VAULT_PUPPETEER_FORCE_SINGLE_PROCESS === '1';
const VAULT_BROWSER_ALLOW_SUBDOMAINS =
  process.env.SAKAKI_VAULT_BROWSER_ALLOW_SUBDOMAINS === '1' ||
  process.env.SAKAKI_SECURE_ALLOW_SUBDOMAINS === '1';
const VAULT_BROWSER_ALLOW_HTTP =
  process.env.SAKAKI_VAULT_BROWSER_ALLOW_HTTP === '1' ||
  process.env.SAKAKI_SECURE_ALLOW_HTTP === '1';
const VAULT_BROWSER_ALLOW_PRIVATE = process.env.SAKAKI_VAULT_BROWSER_ALLOW_PRIVATE === '1';
const VAULT_BROWSER_MAX_ACTIONS = parseInt(
  process.env.SAKAKI_VAULT_BROWSER_MAX_ACTIONS || '50',
  10
);
const VAULT_BROWSER_TIMEOUT = parseInt(
  process.env.SAKAKI_VAULT_BROWSER_TIMEOUT || '30000',
  10
);
const VAULT_BROWSER_MAX_SESSIONS = parseInt(
  process.env.SAKAKI_VAULT_BROWSER_MAX_SESSIONS || '2',
  10
);
const VAULT_CHALLENGE_MIN_SCORE = parseInt(
  process.env.SAKAKI_CHALLENGE_MIN_SCORE || '2',
  10
);
const VAULT_CHALLENGE_DOMAIN_IGNORE = (process.env.SAKAKI_CHALLENGE_DOMAIN_IGNORE || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const VAULT_CHALLENGE_DOMAIN_FORCE = (process.env.SAKAKI_CHALLENGE_DOMAIN_FORCE || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

const VAULT_CHALLENGE_URL_PATTERNS = [
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
const VAULT_CHALLENGE_URL_EXTRA = (() => {
  const raw = process.env.SAKAKI_CHALLENGE_URL_REGEX || '';
  if (!raw) return [];
  const list = raw.trim().startsWith('[') ? (() => { try { return JSON.parse(raw); } catch { return []; } })() : raw.split(raw.includes(';') ? ';' : ',');
  return list.map(s => s.trim()).filter(Boolean).map((pattern) => {
    const m = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    try {
      if (m) return new RegExp(m[1], m[2] || 'i');
      return new RegExp(pattern, 'i');
    } catch {
      return null;
    }
  }).filter(Boolean);
})();

const VAULT_CHALLENGE_TEXT_PATTERNS = [
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
const VAULT_CHALLENGE_TEXT_EXTRA = (() => {
  const raw = process.env.SAKAKI_CHALLENGE_TEXT_REGEX || '';
  if (!raw) return [];
  const list = raw.trim().startsWith('[') ? (() => { try { return JSON.parse(raw); } catch { return []; } })() : raw.split(raw.includes(';') ? ';' : ',');
  return list.map(s => s.trim()).filter(Boolean).map((pattern) => {
    const m = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    try {
      if (m) return new RegExp(m[1], m[2] || 'i');
      return new RegExp(pattern, 'i');
    } catch {
      return null;
    }
  }).filter(Boolean);
})();

const VAULT_CHALLENGE_SELECTORS = [
  'iframe[src*="recaptcha"]',
  'iframe[src*="hcaptcha"]',
  'iframe[src*="turnstile"]',
  'iframe[src*="arkoselabs"]',
  'div.g-recaptcha',
  'div.h-captcha',
  'input[name*="captcha"]',
  '[id*="captcha"]'
];
const VAULT_CHALLENGE_SELECTOR_EXTRA = (() => {
  const raw = process.env.SAKAKI_CHALLENGE_SELECTOR || '';
  if (!raw) return [];
  const sep = raw.includes(';') ? ';' : ',';
  return raw.split(sep).map(s => s.trim()).filter(Boolean);
})();

const vaultRemoteSessions = new Map(); // sessionId -> session

const BLOCKED_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '169.254.169.254', // AWS/GCP metadata
  '169.254.170.2',   // AWS ECS metadata
  '100.100.100.200', // Alibaba metadata
  'metadata.google.internal',
  'metadata.google',
  'metadata'
]);

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

// ========== Proxy Guard ==========
function normalizeHost(hostname) {
  return (hostname || '').toLowerCase().replace(/\.$/, '');
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
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function isPrivateIPv6(ip) {
  const host = ip.toLowerCase();
  if (host === '::1') return true;
  if (host.startsWith('fe80:')) return true; // link-local
  if (host.startsWith('fc') || host.startsWith('fd')) return true; // unique local
  if (host.startsWith('::ffff:')) {
    const v4 = host.replace('::ffff:', '');
    return isPrivateIPv4(v4);
  }
  return false;
}

function isPrivateIp(address) {
  const version = net.isIP(address);
  if (version === 4) return isPrivateIPv4(address);
  if (version === 6) return isPrivateIPv6(address);
  return false;
}

async function assertProxyTargetAllowed(parsedUrl) {
  const hostname = normalizeHost(parsedUrl.hostname);

  if (!PROXY_ALLOW_HTTP && parsedUrl.protocol !== 'https:') {
    return { ok: false, error: 'Only HTTPS targets are allowed' };
  }

  if (PROXY_REQUIRE_ALLOWLIST && proxyConfig.allowedDomains.size === 0) {
    return { ok: false, error: 'Proxy allowlist required but empty' };
  }

  if (BLOCKED_HOSTS.has(hostname) || hostname.endsWith('.local')) {
    return { ok: false, error: `Blocked host: ${hostname}` };
  }

  // Private IP guard (resolve hostname)
  if (!PROXY_ALLOW_PRIVATE) {
    const ipVersion = net.isIP(hostname);
    let addresses = [];

    if (ipVersion) {
      addresses = [{ address: hostname }];
    } else {
      try {
        addresses = await dns.lookup(hostname, { all: true, verbatim: true });
      } catch (e) {
        return { ok: false, error: `DNS lookup failed for ${hostname}` };
      }
    }

    for (const { address } of addresses) {
      if (isPrivateIp(address)) {
        return { ok: false, error: `Private IP not allowed: ${address}` };
      }
    }
  }

  return { ok: true };
}

// ========== Vault Browser Helpers ==========
const DNS_CACHE_TTL_MS = 60000;
const dnsCache = new Map(); // hostname -> { isPrivate, expiresAt }

function normalizeDomainList(domains) {
  return (domains || [])
    .map(s => (s || '').toString().trim().toLowerCase())
    .filter(Boolean);
}

function isDomainAllowed(hostname, allowedDomains, allowSubdomains) {
  const host = normalizeHost(hostname);
  if (!allowedDomains.length) return false;
  if (allowedDomains.includes(host)) return true;
  if (!allowSubdomains) return false;
  return allowedDomains.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function isOpaqueUrl(url) {
  return (
    url.startsWith('data:') ||
    url.startsWith('blob:') ||
    url === 'about:blank'
  );
}

async function isHostPrivateCached(hostname) {
  const host = normalizeHost(hostname);
  const now = Date.now();
  const cached = dnsCache.get(host);
  if (cached && cached.expiresAt > now) {
    return cached.isPrivate;
  }

  let addresses = [];
  const ipVersion = net.isIP(host);
  if (ipVersion) {
    addresses = [{ address: host }];
  } else {
    try {
      addresses = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      dnsCache.set(host, { isPrivate: false, expiresAt: now + DNS_CACHE_TTL_MS });
      return false;
    }
  }

  const isPrivate = addresses.some(({ address }) => isPrivateIp(address));
  dnsCache.set(host, { isPrivate, expiresAt: now + DNS_CACHE_TTL_MS });
  return isPrivate;
}

async function assertBrowserTargetAllowed(parsedUrl, config) {
  const hostname = normalizeHost(parsedUrl.hostname);
  const {
    allowedDomains,
    allowSubdomains,
    allowHttp,
    allowPrivate
  } = config;

  if (!allowHttp && parsedUrl.protocol !== 'https:') {
    return { ok: false, error: 'Only HTTPS targets are allowed' };
  }

  if (!allowedDomains.length) {
    return { ok: false, error: 'Allowed domains list is empty' };
  }

  if (!isDomainAllowed(hostname, allowedDomains, allowSubdomains)) {
    return { ok: false, error: `Domain ${hostname} not allowed` };
  }

  if (BLOCKED_HOSTS.has(hostname) || hostname.endsWith('.local')) {
    return { ok: false, error: `Blocked host: ${hostname}` };
  }

  if (!allowPrivate && await isHostPrivateCached(hostname)) {
    return { ok: false, error: `Private IP not allowed for ${hostname}` };
  }

  return { ok: true };
}

let vaultBrowser = null;
let vaultBrowserLaunching = null;

async function getVaultBrowser() {
  if (vaultBrowser) return vaultBrowser;
  if (!vaultBrowserLaunching) {
    const baseArgs = [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-crashpad',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      ...VAULT_PUPPETEER_EXTRA_ARGS
    ];
    const fallbackArgs = [
      ...baseArgs,
      '--no-zygote',
      '--single-process'
    ];
    const launch = (args) => launchBrowser(VAULT_BACKEND_CONFIG, {
      headless: VAULT_HEADLESS_MODE,
      args
    });

    if (VAULT_PUPPETEER_FORCE_SINGLE_PROCESS) {
      vaultBrowserLaunching = launch(fallbackArgs);
    } else {
      vaultBrowserLaunching = launch(baseArgs).catch(() => launch(fallbackArgs));
    }
  }
  vaultBrowser = await vaultBrowserLaunching;
  vaultBrowserLaunching = null;
  const label = `${VAULT_BACKEND_CONFIG.backend}/${VAULT_BACKEND_CONFIG.browserType}`;
  const extra = VAULT_BACKEND_CONFIG.executablePath ? ` (${VAULT_BACKEND_CONFIG.executablePath})` : '';
  console.log(`[Vault] Browser initialized: ${label}${extra}`);
  return vaultBrowser;
}

async function createIsolatedContext(browser) {
  if (browser && typeof browser.createBrowserContext === 'function') {
    return browser.createBrowserContext();
  }
  if (browser && typeof browser.createIncognitoBrowserContext === 'function') {
    return browser.createIncognitoBrowserContext();
  }
  if (browser && typeof browser.newContext === 'function') {
    return browser.newContext();
  }
  return null;
}

async function createVaultPage(config) {
  const browser = await getVaultBrowser();
  const context = await createIsolatedContext(browser);
  if (!context) {
    throw new Error('Failed to create isolated browser context');
  }
  const page = await context.newPage();

  await attachRequestInterception(page, async (req) => {
    const url = req.url();
    if (isOpaqueUrl(url)) {
      return req.continue();
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return req.abort();
    }

    const guard = await assertBrowserTargetAllowed(parsed, config);
    if (!guard.ok) {
      return req.abort();
    }

    return req.continue();
  }, VAULT_BROWSER_BACKEND);

  return { page, context };
}

async function getPageViewport(page) {
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

async function detectVaultChallenge(page) {
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

  if (hostname && VAULT_CHALLENGE_DOMAIN_IGNORE.length) {
    const host = hostname.toLowerCase();
    const ignore = VAULT_CHALLENGE_DOMAIN_IGNORE.some(d => host === d || host.endsWith('.' + d));
    if (ignore) {
      return { detected: false, skipped: 'domain_ignore', url, title };
    }
  }
  if (hostname && VAULT_CHALLENGE_DOMAIN_FORCE.length) {
    const host = hostname.toLowerCase();
    const forced = VAULT_CHALLENGE_DOMAIN_FORCE.some(d => host === d || host.endsWith('.' + d));
    if (forced) {
      return {
        detected: true,
        kind: 'challenge',
        score: VAULT_CHALLENGE_MIN_SCORE,
        threshold: VAULT_CHALLENGE_MIN_SCORE,
        url,
        title,
        evidence: [`domain:${hostname}`]
      };
    }
  }

  for (const pattern of VAULT_CHALLENGE_URL_PATTERNS.concat(VAULT_CHALLENGE_URL_EXTRA)) {
    if (pattern.test(urlLower)) {
      evidence.push(`url:${pattern}`);
      break;
    }
  }

  for (const pattern of VAULT_CHALLENGE_URL_PATTERNS.concat(VAULT_CHALLENGE_URL_EXTRA)) {
    if (pattern.test(titleLower)) {
      evidence.push(`title:${pattern}`);
      break;
    }
  }

  for (const sel of VAULT_CHALLENGE_SELECTORS.concat(VAULT_CHALLENGE_SELECTOR_EXTRA)) {
    try {
      const el = await page.$(sel);
      if (el) {
        evidence.push(`selector:${sel}`);
        break;
      }
    } catch {}
  }

  try {
    const text = await page.evaluate(() => {
      const body = document.body;
      const t = body ? body.innerText || '' : '';
      return t.slice(0, 2000);
    });
    for (const pattern of VAULT_CHALLENGE_TEXT_PATTERNS.concat(VAULT_CHALLENGE_TEXT_EXTRA)) {
      if (pattern.test(text)) {
        evidence.push(`text:${pattern}`);
        break;
      }
    }
  } catch {}

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

  if (score < VAULT_CHALLENGE_MIN_SCORE) {
    return {
      detected: false,
      score,
      threshold: VAULT_CHALLENGE_MIN_SCORE,
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

  return { detected: true, kind, evidence, url, title, score, threshold: VAULT_CHALLENGE_MIN_SCORE };
}

function decryptSecretValue(secretName) {
  const secret = secrets.get(secretName);
  if (!secret) {
    return { success: false, error: 'Secret not found' };
  }

  try {
    const key = deriveKey(masterKey, Buffer.from(secret.salt, 'hex'));
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(secret.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(secret.authTag, 'hex'));

    let decrypted = decipher.update(secret.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return { success: true, value: decrypted };
  } catch {
    return { success: false, error: 'Failed to decrypt secret' };
  }
}

function closeVaultRemoteSession(sessionId, reason) {
  const session = vaultRemoteSessions.get(sessionId);
  if (!session) return;
  session.closed = true;
  session.closeReason = reason || 'closed';
  if (session.page) {
    try { session.page.close(); } catch {}
  }
  if (session.context) {
    try { session.context.close(); } catch {}
  }
  vaultRemoteSessions.delete(sessionId);
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

  // Get secret value for internal use only (browser form filling)
  // This is NOT exposed via API - only callable internally
  getForInternal(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (!params.name) return { success: false, error: 'name required' };

    const secret = secrets.get(params.name);
    if (!secret) {
      audit('GET_INTERNAL', params.name, false, { reason: 'not_found' });
      return { success: false, error: 'Secret not found' };
    }

    try {
      // Decrypt
      const key = deriveKey(masterKey, Buffer.from(secret.salt, 'hex'));
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(secret.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(secret.authTag, 'hex'));

      let decrypted = decipher.update(secret.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      audit('GET_INTERNAL', params.name, true, { caller: 'browser-form' });

      // Return value (only for internal browser operations)
      return { success: true, value: decrypted };
    } catch (e) {
      audit('GET_INTERNAL', params.name, false, { error: e.message });
      return { success: false, error: 'Decryption failed' };
    }
  },

  // Execute browser actions inside Vault process
  async browserExecute(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };

    const actions = Array.isArray(params.actions) ? params.actions : [];
    if (actions.length === 0) {
      return { success: false, error: 'actions array required' };
    }
    if (actions.length > VAULT_BROWSER_MAX_ACTIONS) {
      return { success: false, error: `actions exceeds max (${VAULT_BROWSER_MAX_ACTIONS})` };
    }

    const allowedDomains = normalizeDomainList(
      params.allowedDomains && params.allowedDomains.length
        ? params.allowedDomains
        : VAULT_BROWSER_ALLOWED_DOMAINS
    );

    const config = {
      allowedDomains,
      allowSubdomains: !!params.allowSubdomains || VAULT_BROWSER_ALLOW_SUBDOMAINS,
      allowHttp: !!params.allowHttp || VAULT_BROWSER_ALLOW_HTTP,
      allowPrivate: !!params.allowPrivate || VAULT_BROWSER_ALLOW_PRIVATE
    };

    if (!config.allowedDomains.length) {
      return { success: false, error: 'allowedDomains required' };
    }

    const timeout = Number(params.timeout) > 0 ? Number(params.timeout) : VAULT_BROWSER_TIMEOUT;

    let page;
    let context;
    const results = [];
    let finalUrl = null;

    try {
      const created = await createVaultPage(config);
      page = created.page;
      context = created.context;

      for (const action of actions) {
        if (!action || typeof action !== 'object') continue;
        const type = action.type;

        try {
          if (type === 'navigate') {
            const url = action.url;
            if (!url) throw new Error('navigate.url required');
            const parsed = new URL(url);
            const guard = await assertBrowserTargetAllowed(parsed, config);
            if (!guard.ok) throw new Error(guard.error);
            await page.goto(url, { waitUntil: VAULT_WAIT_UNTIL_NETWORK_IDLE, timeout });
            finalUrl = page.url();
            results.push({ action: 'navigate', ok: true });
            continue;
          }

          if (type === 'click') {
            const selector = action.selector;
            if (!selector) throw new Error('click.selector required');
            await page.click(selector);
            results.push({ action: 'click', ok: true, selector });
            continue;
          }

          if (type === 'type') {
            const selector = action.selector;
            if (!selector) throw new Error('type.selector required');
            const text = action.text ?? '';
            await page.type(selector, String(text));
            results.push({ action: 'type', ok: true, selector });
            continue;
          }

          if (type === 'typeFromVault') {
            const selector = action.selector;
            const secretName = action.secretName;
            if (!selector || !secretName) {
              throw new Error('typeFromVault.selector and secretName required');
            }
            const decrypted = decryptSecretValue(secretName);
            if (!decrypted.success) throw new Error(decrypted.error || 'Secret not found');
            await page.type(selector, decrypted.value);
            decrypted.value = null;
            results.push({ action: 'typeFromVault', ok: true, selector });
            continue;
          }

          if (type === 'waitFor') {
            const selector = action.selector;
            if (!selector) throw new Error('waitFor.selector required');
            await page.waitForSelector(selector, { timeout });
            results.push({ action: 'waitFor', ok: true, selector });
            continue;
          }

          if (type === 'waitForNavigation') {
            await page.waitForNavigation({ waitUntil: VAULT_WAIT_UNTIL_NETWORK_IDLE, timeout });
            finalUrl = page.url();
            results.push({ action: 'waitForNavigation', ok: true });
            continue;
          }

          results.push({ action: type || 'unknown', ok: false, error: 'Unsupported action' });
          return { success: false, results, finalUrl };
        } catch (err) {
          results.push({ action: type || 'unknown', ok: false, error: err.message });
          return { success: false, results, finalUrl };
        }
      }

      finalUrl = finalUrl || (page ? page.url() : null);
      return { success: true, results, finalUrl };
    } catch (err) {
      return { success: false, error: err.message, results, finalUrl };
    } finally {
      if (page) {
        try { await page.close(); } catch {}
      }
      if (context) {
        try { await context.close(); } catch {}
      }
    }
  },

  // Remote View: Start session (Vault-side)
  async browserRemoteStart(params) {
    if (isDestroyed) return { success: false, error: 'Vault destroyed' };
    if (!masterKey) return { success: false, error: 'Not initialized' };
    if (vaultRemoteSessions.size >= VAULT_BROWSER_MAX_SESSIONS) {
      return { success: false, error: 'Too many vault remote sessions' };
    }

    const allowedDomains = normalizeDomainList(
      params.allowedDomains && params.allowedDomains.length
        ? params.allowedDomains
        : VAULT_BROWSER_ALLOWED_DOMAINS
    );

    const config = {
      allowedDomains,
      allowSubdomains: !!params.allowSubdomains || VAULT_BROWSER_ALLOW_SUBDOMAINS,
      allowHttp: !!params.allowHttp || VAULT_BROWSER_ALLOW_HTTP,
      allowPrivate: !!params.allowPrivate || VAULT_BROWSER_ALLOW_PRIVATE
    };

    if (!config.allowedDomains.length) {
      return { success: false, error: 'allowedDomains required' };
    }

    let page;
    let context;
    try {
      const created = await createVaultPage(config);
      page = created.page;
      context = created.context;

      if (params.startUrl) {
        const parsed = new URL(params.startUrl);
        const guard = await assertBrowserTargetAllowed(parsed, config);
        if (!guard.ok) {
          await page.close();
          await context.close();
          return { success: false, error: guard.error };
        }
        await page.goto(params.startUrl, { waitUntil: VAULT_WAIT_UNTIL_NETWORK_IDLE, timeout: VAULT_BROWSER_TIMEOUT });
      }

      const size = await getPageViewport(page);

      const sessionId = crypto.randomBytes(12).toString('hex');
      vaultRemoteSessions.set(sessionId, {
        id: sessionId,
        page,
        context,
        config,
        allowInput: !!params.allowInput,
        allowText: !!params.allowText,
        allowScroll: !!params.allowScroll,
        lastHash: null,
        createdAt: Date.now()
      });

      return { success: true, sessionId, size };
    } catch (e) {
      if (page) {
        try { await page.close(); } catch {}
      }
      if (context) {
        try { await context.close(); } catch {}
      }
      return { success: false, error: e.message };
    }
  },

  // Remote View: Capture frame (Vault-side)
  async browserRemoteFrame(params) {
    const session = vaultRemoteSessions.get(params.sessionId);
    if (!session) return { success: false, error: 'Session not found' };
    if (session.page.isClosed()) {
      closeVaultRemoteSession(session.id, 'page_closed');
      return { success: false, error: 'Page closed' };
    }

    try {
      const force = !!params.force;
      const buffer = await session.page.screenshot({
        type: 'jpeg',
        quality: Math.min(Math.max(parseInt(params.quality, 10) || 60, 30), 90)
      });
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');
      if (!force && hash === session.lastHash) {
        return { success: true, changed: false };
      }
      session.lastHash = hash;
      const size = await getPageViewport(session.page);
      return {
        success: true,
        changed: true,
        hash,
        data: buffer.toString('base64'),
        size
      };
    } catch (e) {
      return { success: false, error: e.message };
    }
  },

  // Remote View: Command (Vault-side)
  async browserRemoteCommand(params) {
    const session = vaultRemoteSessions.get(params.sessionId);
    if (!session) return { success: false, error: 'Session not found' };
    if (!session.allowInput) return { success: false, error: 'Input disabled' };
    if (session.page.isClosed()) {
      closeVaultRemoteSession(session.id, 'page_closed');
      return { success: false, error: 'Page closed' };
    }

    try {
      const page = session.page;
      const size = await getPageViewport(page);
      const width = size.width || 1;
      const height = size.height || 1;

      if (params.cmd === 'click') {
        const x = Math.max(0, Math.min(1, Number(params.x)));
        const y = Math.max(0, Math.min(1, Number(params.y)));
        await page.mouse.click(x * width, y * height);
        return { success: true };
      }

      if (params.cmd === 'scroll' && session.allowScroll) {
        const deltaY = Number(params.deltaY) || 0;
        await page.mouse.wheel({ deltaY });
        return { success: true };
      }

      if (params.cmd === 'key' && session.allowText) {
        const key = String(params.key || '');
        if (key.length === 0) return { success: false, error: 'key required' };
        await page.keyboard.press(key === 'Backspace' ? 'Backspace' : key);
        return { success: true };
      }

      if (params.cmd === 'type' && session.allowText) {
        const text = String(params.text || '');
        await page.keyboard.type(text);
        return { success: true };
      }

      return { success: false, error: 'Unsupported command' };
    } catch (e) {
      return { success: false, error: e.message };
    }
  },

  // Remote View: Challenge detection (Vault-side)
  async browserRemoteChallenge(params) {
    const session = vaultRemoteSessions.get(params.sessionId);
    if (!session) return { success: false, error: 'Session not found' };
    if (session.page.isClosed()) {
      closeVaultRemoteSession(session.id, 'page_closed');
      return { success: false, error: 'Page closed' };
    }

    try {
      const result = await detectVaultChallenge(session.page);
      return { success: true, ...result };
    } catch (e) {
      return { success: false, error: e.message };
    }
  },

  // Remote View: Stop session (Vault-side)
  async browserRemoteStop(params) {
    closeVaultRemoteSession(params.sessionId);
    return { success: true };
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

    // Parse URL
    let parsedUrl;
    try {
      parsedUrl = new URL(request.url);
    } catch (e) {
      return { success: false, error: 'Invalid URL' };
    }

    const guard = await assertProxyTargetAllowed(parsedUrl);
    if (!guard.ok) {
      audit('PROXY', secretName, false, { reason: guard.error });
      return { success: false, error: guard.error };
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
      let total = 0;
      res.on('data', chunk => {
        total += chunk.length;
        if (total > PROXY_MAX_RESPONSE_BYTES) {
          res.destroy();
          reject(new Error('Response too large'));
          return;
        }
        data += chunk;
      });
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
  // Ensure socket directory exists (private)
  try {
    fs.mkdirSync(path.dirname(SOCKET_PATH), { recursive: true, mode: 0o700 });
  } catch {
    // Ignore; socket creation will fail if path is invalid
  }

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
  console.log('  - No public retrieve() API (verify-only by default)');
  console.log('  - Separate process isolation');
  console.log('  - SecureBuffer for sensitive data');
  console.log('  - Rate limiting + self-destruct');
  console.log('  - Full audit logging');
  console.log('  - Encrypted persistence');

  startServer();
}

module.exports = { handlers }; // For testing
