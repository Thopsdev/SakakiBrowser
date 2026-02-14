#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');

const PORT = Number(process.env.SAKAKI_STRICT_TEST_PORT || (19000 + Math.floor(Math.random() * 1000)));
const ADMIN_TOKEN = 'strict-test-token';
const MASTER_KEY = 'test-master-key-16chars';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForHealth() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (res.ok) return true;
    } catch {}
    await sleep(250);
  }
  return false;
}

async function fetchJson(pathname, body, options = {}) {
  const res = await fetch(`http://127.0.0.1:${PORT}${pathname}`, {
    method: options.method || 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}

async function run() {
  const child = spawn('node', ['src/index.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      SAKAKI_BIND: '127.0.0.1',
      SAKAKI_ADMIN_TOKEN: ADMIN_TOKEN,
      SAKAKI_MODE: 'strict',
      SAKAKI_SKIP_BROWSER_INIT: '1',
      SAKAKI_PUBLIC_ALLOW_HTTP: '1',
      SAKAKI_SECURE_ALLOW_HTTP: '1',
      SAKAKI_SECURE_ALLOW_PRIVATE: '1',
      SAKAKI_SECURE_ALLOW_SENSITIVE: '1',
      SAKAKI_VAULT_BROWSER_ALLOW_HTTP: '1',
      SAKAKI_VAULT_BROWSER_ALLOW_PRIVATE: '1',
      SAKAKI_VAULT_BROWSER_ALLOW_SENSITIVE: '1',
      SAKAKI_PROXY_ALLOW_HTTP: '1',
      SAKAKI_PROXY_ALLOW_PRIVATE: '1',
      SAKAKI_PROXY_REQUIRE_ALLOWLIST: '0'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', (d) => process.stdout.write(d));
  child.stderr.on('data', (d) => process.stderr.write(d));

  const healthy = await waitForHealth();
  if (!healthy) {
    child.kill('SIGKILL');
    throw new Error('Sakaki server failed to start');
  }

  const adminHeaders = { Authorization: `Bearer ${ADMIN_TOKEN}` };
  const init = await fetchJson('/vault/init', { masterKey: MASTER_KEY }, { headers: adminHeaders });
  if (!init.data || init.data.success !== true) {
    throw new Error(`Vault init failed: ${JSON.stringify(init.data)}`);
  }

  const typeRes = await fetchJson('/type', {
    selector: '#input',
    text: 'api_key=sk-test-1234567890abcdef'
  });
  if (!typeRes.data || typeRes.data.blocked !== true) {
    throw new Error('Strict mode did not block sensitive /type input');
  }

  const typeSecretRes = await fetch(`http://127.0.0.1:${PORT}/type-secret`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  if (typeSecretRes.status !== 410) {
    throw new Error('/type-secret should return 410');
  }

  const proxyRes = await fetchJson('/vault/proxy', {
    secretName: 'MISSING',
    request: {
      method: 'POST',
      url: 'https://example.com',
      headers: { 'Content-Type': 'application/json' },
      body: { ping: 'pong' }
    },
    injectAs: 'Authorization: Bearer ${secret}'
  }, { headers: adminHeaders });
  if (!proxyRes.data || !String(proxyRes.data.error || '').toLowerCase().includes('allowlist')) {
    throw new Error('Strict mode did not enforce proxy allowlist');
  }

  const configRes = await fetchJson('/vault/proxy/config', {
    enabled: false,
    enforceVaultProxy: false
  }, { headers: adminHeaders });
  if (!configRes.data || configRes.data.success !== false) {
    throw new Error('Strict mode allowed proxy config relaxation');
  }

  child.kill('SIGTERM');
  console.log('[STRICT] OK');
}

run().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
