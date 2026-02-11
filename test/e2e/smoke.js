#!/usr/bin/env node
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const SAKAKI_PORT = 18900;
const TEST_PORT = 18901;
const ADMIN_TOKEN = 'e2e-token';
const DEFAULT_CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const detectedChromePath = process.platform === 'darwin' && fs.existsSync(DEFAULT_CHROME_PATH)
  ? DEFAULT_CHROME_PATH
  : '';

const E2E_BACKEND = process.env.SAKAKI_E2E_BACKEND
  || (detectedChromePath ? 'puppeteer' : 'playwright');
const E2E_BROWSER = process.env.SAKAKI_E2E_BROWSER
  || (detectedChromePath ? 'chrome' : 'chromium');
const E2E_BROWSER_PATH = process.env.SAKAKI_E2E_BROWSER_PATH || detectedChromePath;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}

function startTestServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/challenge') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!doctype html><html><body>
        <h1>Captcha Required</h1>
        <div>captcha verification</div>
        <iframe src="https://www.google.com/recaptcha/api2/anchor"></iframe>
      </body></html>`);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>ok</body></html>');
  });
  return new Promise((resolve) => {
    server.listen(TEST_PORT, '127.0.0.1', () => resolve(server));
  });
}

async function waitForHealth() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${SAKAKI_PORT}/health`);
      if (res.ok) return true;
    } catch {}
    await sleep(250);
  }
  return false;
}

async function run() {
  const testServer = await startTestServer();

  const child = spawn('node', ['src/index.js'], {
    cwd: __dirname + '/../../',
    env: {
      ...process.env,
      PORT: String(SAKAKI_PORT),
      SAKAKI_BIND: '127.0.0.1',
      SAKAKI_ADMIN_TOKEN: ADMIN_TOKEN,
      SAKAKI_BACKEND: E2E_BACKEND,
      SAKAKI_BROWSER: E2E_BROWSER,
      ...(E2E_BROWSER_PATH ? { SAKAKI_BROWSER_PATH: E2E_BROWSER_PATH } : {}),
      SAKAKI_PUBLIC_ALLOW_HTTP: '1',
      SAKAKI_SECURE_ALLOWED_DOMAINS: '127.0.0.1,localhost',
      SAKAKI_SECURE_ALLOW_HTTP: '1',
      SAKAKI_SECURE_ALLOW_PRIVATE: '1',
      SAKAKI_REMOTE_VIEW: '1',
      SAKAKI_CHALLENGE_MIN_SCORE: '1',
      SAKAKI_CHALLENGE_NOTIFY_COOLDOWN_MS: '0'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', (d) => process.stdout.write(d));
  child.stderr.on('data', (d) => process.stderr.write(d));

  const healthy = await waitForHealth();
  if (!healthy) {
    child.kill('SIGKILL');
    testServer.close();
    throw new Error('Sakaki server failed to start');
  }

  console.log('[E2E] public navigate + screenshot');
  const nav = await fetchJson(`http://127.0.0.1:${SAKAKI_PORT}/navigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: `http://127.0.0.1:${TEST_PORT}/` })
  });
  if (!nav.data || nav.data.success !== true) {
    console.error('[E2E] navigate response', nav);
    throw new Error('Public navigate failed');
  }

  const shot = await fetchJson(`http://127.0.0.1:${SAKAKI_PORT}/screenshot`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: `/tmp/sakaki-e2e-${Date.now()}.png` })
  });
  if (!(shot.data && (shot.data.success || shot.data.path))) {
    throw new Error('Screenshot failed');
  }

  await sleep(1200);

  console.log('[E2E] secure challenge + remote view');
  const sec = await fetchJson(`http://127.0.0.1:${SAKAKI_PORT}/secure/navigate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ADMIN_TOKEN}`
    },
    body: JSON.stringify({ url: `http://127.0.0.1:${TEST_PORT}/challenge` })
  });
  if (!sec.data || sec.data.reason !== 'challenge_required') {
    console.error('[E2E] secure response', sec);
    throw new Error('Challenge not detected in secure lane');
  }
  if (!sec.data.remoteView || !sec.data.remoteView.sessionId) {
    throw new Error('Remote view not started');
  }

  await fetchJson(`http://127.0.0.1:${SAKAKI_PORT}/remote/stop`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ADMIN_TOKEN}`
    },
    body: JSON.stringify({ sessionId: sec.data.remoteView.sessionId })
  });

  child.kill('SIGTERM');
  testServer.close();
  console.log('[E2E] OK');
}

run().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
