#!/usr/bin/env node
/**
 * Sakaki Browser CLI
 *
 * Command-line interface for Sakaki Browser operations
 */

const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const readline = require('readline');

const BASE_URL = process.env.SAKAKI_URL || 'http://localhost:18800';
const ADMIN_TOKEN = process.env.SAKAKI_ADMIN_TOKEN || '';
const LAST_REMOTE_PATH = path.join(os.homedir(), '.sakaki', 'remote-session.json');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m'
};

function success(msg) {
  console.log(`${colors.green}✓${colors.reset} ${msg}`);
}

function error(msg) {
  console.log(`${colors.red}✗${colors.reset} ${msg}`);
}

function info(msg) {
  console.log(`${colors.cyan}→${colors.reset} ${msg}`);
}

function parseStartArgs(args = []) {
  const env = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--headful') {
      env.SAKAKI_HEADLESS_MODE = 'false';
      continue;
    }
    if (arg === '--headless') {
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        env.SAKAKI_HEADLESS_MODE = next;
        i++;
      } else {
        env.SAKAKI_HEADLESS_MODE = 'true';
      }
      continue;
    }
    if (arg === '--chrome-args' || arg === '--args') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_PUPPETEER_ARGS = next;
        i++;
      }
      continue;
    }
    if (arg === '--single-process') {
      env.SAKAKI_PUPPETEER_FORCE_SINGLE_PROCESS = '1';
      continue;
    }
    if (arg === '--vault-headful') {
      env.SAKAKI_VAULT_HEADLESS_MODE = 'false';
      continue;
    }
    if (arg === '--vault-headless') {
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        env.SAKAKI_VAULT_HEADLESS_MODE = next;
        i++;
      } else {
        env.SAKAKI_VAULT_HEADLESS_MODE = 'true';
      }
      continue;
    }
    if (arg === '--vault-args') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_VAULT_PUPPETEER_ARGS = next;
        i++;
      }
      continue;
    }
    if (arg === '--vault-single-process') {
      env.SAKAKI_VAULT_PUPPETEER_FORCE_SINGLE_PROCESS = '1';
      continue;
    }
    if (arg === '--bind') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_BIND = next;
        i++;
      }
      continue;
    }
    if (arg === '--backend') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_BACKEND = next;
        i++;
      }
      continue;
    }
    if (arg === '--browser') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_BROWSER = next;
        i++;
      }
      continue;
    }
    if (arg === '--browser-path') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_BROWSER_PATH = next;
        i++;
      }
      continue;
    }
    if (arg === '--port') {
      const next = args[i + 1];
      if (next) {
        env.PORT = next;
        i++;
      }
      continue;
    }
    if (arg === '--remote-view') {
      env.SAKAKI_REMOTE_VIEW = '1';
      continue;
    }
    if (arg === '--admin-token') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_ADMIN_TOKEN = next;
        i++;
      }
      continue;
    }
    if (arg === '--vault-backend') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_VAULT_BACKEND = next;
        i++;
      }
      continue;
    }
    if (arg === '--vault-browser') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_VAULT_BROWSER = next;
        i++;
      }
      continue;
    }
    if (arg === '--vault-browser-path') {
      const next = args[i + 1];
      if (next) {
        env.SAKAKI_VAULT_BROWSER_PATH = next;
        i++;
      }
      continue;
    }
  }
  return env;
}

/**
 * Make HTTP request to Sakaki server
 */
async function request(method, endpoint, body = null, extraHeaders = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, BASE_URL);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const headers = {
      'Content-Type': 'application/json',
      ...(extraHeaders || {})
    };
    if (!headers.Authorization && ADMIN_TOKEN) {
      headers.Authorization = `Bearer ${ADMIN_TOKEN}`;
    }

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: method,
      headers
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });

    req.on('error', (e) => {
      reject(new Error(`Connection failed: ${e.message}. Is the server running?`));
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Check if server is running
 */
async function checkServer() {
  try {
    await request('GET', '/health');
    return true;
  } catch {
    return false;
  }
}

function saveLastRemote(data) {
  try {
    fs.mkdirSync(path.dirname(LAST_REMOTE_PATH), { recursive: true });
    fs.writeFileSync(LAST_REMOTE_PATH, JSON.stringify(data, null, 2));
  } catch {}
}

function loadLastRemote() {
  try {
    if (!fs.existsSync(LAST_REMOTE_PATH)) return null;
    return JSON.parse(fs.readFileSync(LAST_REMOTE_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function clearLastRemote() {
  try { fs.unlinkSync(LAST_REMOTE_PATH); } catch {}
}

function parseRemoteArgs(args = []) {
  const payload = {
    lane: 'public',
    allowInput: true
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--lane') {
      payload.lane = args[++i] || payload.lane;
      continue;
    }
    if (arg === '--start-url') {
      payload.startUrl = args[++i];
      continue;
    }
    if (arg === '--allowed') {
      payload.allowedDomains = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
      continue;
    }
    if (arg === '--allow-subdomains') {
      payload.allowSubdomains = true;
      continue;
    }
    if (arg === '--allow-http') {
      payload.allowHttp = true;
      continue;
    }
    if (arg === '--allow-private') {
      payload.allowPrivate = true;
      continue;
    }
    if (arg === '--allow-input') {
      payload.allowInput = true;
      continue;
    }
    if (arg === '--allow-text') {
      payload.allowText = true;
      continue;
    }
    if (arg === '--allow-scroll') {
      payload.allowScroll = true;
      continue;
    }
    if (arg === '--fps') {
      payload.fps = Number(args[++i]);
      continue;
    }
    if (arg === '--quality') {
      payload.quality = Number(args[++i]);
      continue;
    }
  }
  return payload;
}

/**
 * Commands
 */
const commands = {
  // Server commands
  async start(...startArgs) {
    const running = await checkServer();
    if (running) {
      info('Server is already running');
      return;
    }

    const serverPath = path.join(__dirname, '..', 'src', 'index.js');
    const startEnv = parseStartArgs(startArgs);
    const child = spawn('node', [serverPath], {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, ...startEnv }
    });
    child.unref();

    info('Starting server...');

    // Wait for server to be ready
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 500));
      if (await checkServer()) {
        success('Server started on http://localhost:18800');
        return;
      }
    }
    error('Server failed to start');
  },

  async stop() {
    try {
      const { exec } = require('child_process');
      exec('pkill -f "node.*sakaki-browser.*index.js"');
      success('Server stopped');
    } catch {
      error('Failed to stop server');
    }
  },

  async status() {
    try {
      const { data } = await request('GET', '/health');
      success('Server is running');
      console.log(`  Browser: ${data.browser ? 'Ready' : 'Not ready'}`);
      console.log(`  Security: Rate limiter ${data.security?.rateLimiter || 'unknown'}`);
    } catch {
      error('Server is not running');
      console.log(`  Run: ${colors.cyan}sakaki start${colors.reset}`);
    }
  },

  // Remote View commands
  async 'remote start'(...args) {
    try {
      const payload = parseRemoteArgs(args);
      const { data } = await request('POST', '/remote/start', payload);
      if (data.success) {
        success('Remote view started');
        console.log(`  sessionId: ${data.sessionId}`);
        console.log(`  viewUrl: ${data.viewUrl}`);
        saveLastRemote({
          sessionId: data.sessionId,
          viewUrl: data.viewUrl,
          startedAt: new Date().toISOString()
        });
      } else {
        error(data.error || 'Failed to start remote view');
        if (data.reason) console.log(`  reason: ${data.reason}`);
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'remote stop'(sessionIdOrFlag) {
    try {
      let sessionId = sessionIdOrFlag;
      if (!sessionId || sessionId === '--last') {
        const last = loadLastRemote();
        if (last && last.sessionId) {
          sessionId = last.sessionId;
        }
      }
      if (!sessionId) {
        error('Usage: sakaki remote stop <sessionId> or sakaki remote stop --last');
        return;
      }
      const { data } = await request('POST', '/remote/stop', { sessionId });
      if (data.success) {
        success('Remote view stopped');
        clearLastRemote();
      } else {
        error(data.error || 'Failed to stop remote view');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Bridge: read JSON commands from stdin (NDJSON)
  async bridge() {
    if (process.stdin.isTTY) {
      error('bridge expects JSON lines from stdin');
      console.log('Example:');
      console.log('  echo \'{\"id\":\"1\",\"method\":\"POST\",\"path\":\"/navigate\",\"body\":{\"url\":\"https://example.com\"}}\' | sakaki bridge');
      return;
    }

    const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

    const META_KEYS = new Set([
      'id', 'requestId', 'request_id',
      'action', 'cmd',
      'method', 'httpMethod',
      'path', 'endpoint',
      'headers', 'header',
      'query', 'params', 'qs',
      'token', 'bearer', 'adminToken',
      'timeoutMs'
    ]);

    const actionMap = {
      navigate: { method: 'POST', path: '/navigate' },
      click: { method: 'POST', path: '/click' },
      type: { method: 'POST', path: '/type' },
      screenshot: { method: 'POST', path: '/screenshot' },
      close: { method: 'POST', path: '/close' },
      'secure.navigate': { method: 'POST', path: '/secure/navigate' },
      'secure.click': { method: 'POST', path: '/secure/click' },
      'secure.type': { method: 'POST', path: '/secure/type' },
      'secure.submit': { method: 'POST', path: '/secure/submit-form' },
      'remote.start': { method: 'POST', path: '/remote/start' },
      'remote.stop': { method: 'POST', path: '/remote/stop' },
      'vault.init': { method: 'POST', path: '/vault/init' },
      'vault.store': { method: 'POST', path: '/vault/store' },
      'vault.list': { method: 'GET', path: '/vault/list' }
    };

    const normalizeBody = (msg) => {
      const body = msg.body ?? msg.payload ?? msg.args ?? msg.data;
      if (body !== undefined) return body;
      const filtered = {};
      for (const [key, value] of Object.entries(msg)) {
        if (!META_KEYS.has(key)) filtered[key] = value;
      }
      return Object.keys(filtered).length > 0 ? filtered : null;
    };

    const applyQuery = (path, query) => {
      try {
        const url = new URL(path, BASE_URL);
        for (const [key, value] of Object.entries(query || {})) {
          if (value === undefined || value === null) continue;
          url.searchParams.set(key, String(value));
        }
        return url.toString();
      } catch {
        return path;
      }
    };

    const writeOut = (obj) => {
      process.stdout.write(JSON.stringify(obj) + '\n');
    };

    for await (const line of rl) {
      const trimmed = (line || '').trim();
      if (!trimmed) continue;
      let msg;
      try {
        msg = JSON.parse(trimmed);
      } catch (e) {
        writeOut({ ok: false, error: 'invalid_json', message: e.message });
        continue;
      }

      const id = msg.id ?? msg.requestId ?? msg.request_id;
      let method = msg.method || msg.httpMethod;
      let path = msg.path || msg.endpoint;
      let body = normalizeBody(msg);
      const query = msg.query || msg.params || msg.qs;
      const headers = { ...(msg.headers || msg.header || {}) };
      const token = msg.adminToken || msg.token || msg.bearer;
      if (token && !headers.Authorization) {
        headers.Authorization = `Bearer ${token}`;
      }

      if (!method || !path) {
        const action = msg.action || msg.cmd;
        const mapped = action ? actionMap[action] : null;
        if (mapped) {
          method = mapped.method;
          path = mapped.path;
          body = body ?? normalizeBody(msg);
        }
      }

      if (!method || !path) {
        writeOut({ id, ok: false, error: 'missing_method_or_path' });
        continue;
      }

      try {
        const finalPath = query ? applyQuery(path, query) : path;
        const res = await request(String(method).toUpperCase(), finalPath, body || null, headers);
        writeOut({
          id,
          ok: res.status >= 200 && res.status < 300,
          status: res.status,
          data: res.data
        });
      } catch (e) {
        writeOut({ id, ok: false, error: e.message });
      }
    }
  },

  async agent() {
    return commands.bridge();
  },

  // Vault commands
  async 'vault init'(masterKey) {
    if (!masterKey) {
      error('Usage: sakaki vault init <masterKey>');
      console.log('  Master key must be at least 16 characters');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/init', { masterKey });
      if (data.success) {
        success(`Vault initialized (${data.secretCount} secrets loaded)`);
      } else {
        error(data.error || 'Failed to initialize vault');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault store'(name, value) {
    if (!name || !value) {
      error('Usage: sakaki vault store <name> <value>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/store', { name, value });
      if (data.success) {
        success(`Secret "${name}" stored`);
      } else {
        error(data.error || 'Failed to store secret');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault list'() {
    try {
      const { data } = await request('GET', '/vault/list');
      if (data.success) {
        if (data.secrets.length === 0) {
          info('No secrets stored');
        } else {
          console.log(`\n${colors.cyan}Secrets:${colors.reset}`);
          for (const secret of data.secrets) {
            console.log(`  • ${secret.name} ${colors.dim}(${new Date(secret.createdAt).toLocaleDateString()})${colors.reset}`);
          }
          console.log();
        }
      } else {
        error(data.error || 'Failed to list secrets');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault verify'(name, value) {
    if (!name || !value) {
      error('Usage: sakaki vault verify <name> <value>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/verify', { name, value });
      if (data.success) {
        if (data.valid) {
          success('Value matches');
        } else {
          error('Value does not match');
        }
      } else {
        error(data.error || 'Verification failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault delete'(name) {
    if (!name) {
      error('Usage: sakaki vault delete <name>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/delete', { name });
      if (data.success) {
        success(`Secret "${name}" deleted`);
      } else {
        error(data.error || 'Failed to delete secret');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Browser commands
  async navigate(url) {
    if (!url) {
      error('Usage: sakaki navigate <url>');
      return;
    }

    try {
      const { data } = await request('POST', '/navigate', { url });
      if (data.success) {
        success(`Navigated to: ${data.title}`);
        console.log(`  URL: ${data.url}`);
        console.log(`  Risk: ${data.risk}`);
        if (data.phishingScore > 0) {
          console.log(`  ${colors.yellow}Phishing Score: ${data.phishingScore}${colors.reset}`);
        }
      } else {
        error(data.error || 'Navigation failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async click(selector) {
    if (!selector) {
      error('Usage: sakaki click <selector or description>');
      return;
    }

    try {
      const { data } = await request('POST', '/click', { selector });
      if (data.success) {
        success(`Clicked: ${selector}`);
      } else {
        error(data.error || 'Click failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async type(selector, text) {
    if (!selector || !text) {
      error('Usage: sakaki type <selector> <text>');
      return;
    }

    try {
      const { data } = await request('POST', '/type', { selector, text });
      if (data.success) {
        success(`Typed into: ${selector}`);
      } else {
        error(data.error || 'Type failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'type-secret'(selector, secretName) {
    if (!selector || !secretName) {
      error('Usage: sakaki type-secret <selector> <secretName>');
      console.log('  (Disabled) Use vault browser execution with typeFromVault');
      return;
    }

    error('type-secret is disabled (410). Use vault browser execution instead.');
    console.log(`  Example: ${colors.dim}POST /vault/browserExecute with typeFromVault${colors.reset}`);
  },

  async screenshot(outputPath) {
    const output = outputPath || `screenshot-${Date.now()}.png`;

    try {
      const { data } = await request('POST', '/screenshot', { path: path.resolve(output) });
      if (data.success || data.path) {
        success(`Screenshot saved: ${data.path || output}`);
      } else {
        error(data.error || 'Screenshot failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Audit
  async audit(limit = 20) {
    try {
      const { data } = await request('GET', `/audit-log?limit=${limit}`);
      if (Array.isArray(data)) {
        if (data.length === 0) {
          info('No audit logs');
          return;
        }
        console.log(`\n${colors.cyan}Audit Log:${colors.reset}`);
        for (const entry of data.slice(-limit)) {
          const time = new Date(entry.timestamp).toLocaleTimeString();
          const status = entry.blocked ? colors.red + 'BLOCKED' : colors.green + 'OK';
          console.log(`  ${colors.dim}${time}${colors.reset} ${entry.action} ${status}${colors.reset}`);
        }
        console.log();
      } else {
        error('Failed to get audit log');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Secrets commands
  async 'secrets config'() {
    try {
      const { data } = await request('GET', '/secrets/config');
      console.log(`\n${colors.cyan}Secret Detection Config:${colors.reset}`);
      console.log(`  Enabled: ${data.enabled ? colors.green + 'Yes' : colors.red + 'No'}${colors.reset}`);
      console.log(`  Built-in patterns: ${data.builtinPatterns?.length || 0}`);
      console.log(`  Custom patterns: ${data.customPatterns?.length || 0}`);
      console.log(`  Sensitive fields: ${data.sensitiveFields?.length || 0}`);
      if (data.customPatterns?.length > 0) {
        console.log(`\n  Custom patterns:`);
        data.customPatterns.forEach(p => console.log(`    • ${p.name} (${p.severity})`));
      }
      console.log();
    } catch (e) {
      error(e.message);
    }
  },

  async 'secrets add-pattern'(name, pattern, severity = 'high') {
    if (!name || !pattern) {
      error('Usage: sakaki secrets add-pattern <name> <pattern> [severity]');
      console.log('  Example: sakaki secrets add-pattern "Custom Token" "CUST_[A-Z0-9]{20}"');
      return;
    }
    try {
      const { data } = await request('POST', '/secrets/pattern', { name, pattern, severity });
      if (data.success) {
        success(`Pattern "${name}" added`);
      } else {
        error(data.error || 'Failed to add pattern');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'secrets add-field'(field) {
    if (!field) {
      error('Usage: sakaki secrets add-field <fieldName>');
      return;
    }
    try {
      const { data } = await request('POST', '/secrets/field', { field });
      if (data.success) {
        success(`Field "${field}" added to sensitive list`);
      } else {
        error(data.error || 'Failed to add field');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'secrets stats'() {
    try {
      const { data } = await request('GET', '/secrets/stats');
      console.log(`\n${colors.cyan}Secret Detection Stats:${colors.reset}`);
      console.log(`  Scanned: ${data.scanned}`);
      console.log(`  Detected: ${data.detected}`);
      console.log(`  Protected: ${data.protected}`);
      if (Object.keys(data.byType || {}).length > 0) {
        console.log(`\n  By Type:`);
        for (const [type, count] of Object.entries(data.byType)) {
          console.log(`    • ${type}: ${count}`);
        }
      }
      console.log();
    } catch (e) {
      error(e.message);
    }
  },

  async 'secrets test'(testData) {
    if (!testData) {
      error('Usage: sakaki secrets test <string>');
      console.log('  Tests if the string contains detectable secrets');
      return;
    }
    try {
      const { data } = await request('POST', '/secrets/test', { data: testData });
      if (data.clean) {
        success('No secrets detected');
      } else {
        console.log(`\n${colors.yellow}Secrets detected:${colors.reset}`);
        for (const finding of data.findings) {
          console.log(`  ${colors.red}•${colors.reset} ${finding.type} (${finding.severity})`);
        }
        console.log();
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Help
  help() {
    console.log(`
${colors.cyan}Sakaki Browser CLI${colors.reset}

${colors.yellow}Server:${colors.reset}
  sakaki start              Start the server
    --headless [true|false|new]
    --headful
    --backend <puppeteer|playwright>
    --browser <chrome|edge|brave|chromium|firefox|webkit>
    --browser-path <path>
    --chrome-args "<args>"
    --single-process
    --vault-headless [true|false|new]
    --vault-headful
    --vault-args "<args>"
    --vault-single-process
    --vault-backend <puppeteer|playwright>
    --vault-browser <chrome|edge|brave|chromium|firefox|webkit>
    --vault-browser-path <path>
    --bind <ip>
    --port <port>
    --remote-view
    --admin-token <token>
  sakaki stop               Stop the server
  sakaki status             Check server status

${colors.yellow}Remote View:${colors.reset}
  sakaki remote start [options]
    --lane <public|secure|vault>
    --start-url <url>
    --allowed <domains>
    --allow-subdomains
    --allow-http
    --allow-private
    --allow-input
    --allow-text
    --allow-scroll
    --fps <n>
    --quality <n>
  sakaki remote stop <sessionId>
  sakaki remote stop --last

${colors.yellow}Vault:${colors.reset}
  sakaki vault init <key>   Initialize vault with master key (16+ chars)
  sakaki vault store <n> <v> Store a secret
  sakaki vault list         List all secrets (names only)
  sakaki vault verify <n> <v> Verify a secret value (ZKP)
  sakaki vault delete <n>   Delete a secret

${colors.yellow}Browser:${colors.reset}
  sakaki navigate <url>     Navigate to URL
  sakaki click <selector>   Click element (CSS or semantic)
  sakaki type <sel> <text>  Type text into element
  sakaki type-secret <sel> <name>  Disabled (use vault browser execution)
  sakaki screenshot [path]  Take screenshot

${colors.yellow}Secret Detection:${colors.reset}
  sakaki secrets config     Show detection config
  sakaki secrets stats      Show detection stats
  sakaki secrets test <str> Test if string contains secrets
  sakaki secrets add-pattern <name> <regex> [severity]
  sakaki secrets add-field <name>

${colors.yellow}Other:${colors.reset}
  sakaki audit [limit]      View audit log
  sakaki bridge             NDJSON bridge (stdin/stdout)
  sakaki agent              Alias for bridge
  sakaki help               Show this help

${colors.dim}Environment:${colors.reset}
  SAKAKI_URL    Server URL (default: http://localhost:18800)
`);
  }
};

// Parse arguments and run
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    commands.help();
    return;
  }

  // Handle compound commands (vault init, vault store, etc.)
  const cmd1 = args[0];
  const cmd2 = args[1];
  const compound = `${cmd1} ${cmd2}`;

  if (commands[compound]) {
    await commands[compound](...args.slice(2));
  } else if (commands[cmd1]) {
    await commands[cmd1](...args.slice(1));
  } else {
    error(`Unknown command: ${cmd1}`);
    console.log(`Run ${colors.cyan}sakaki help${colors.reset} for usage`);
  }
}

main().catch(e => {
  error(e.message);
  process.exit(1);
});
