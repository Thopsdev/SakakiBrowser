# Sakaki Browser

**Secure Browser Automation Framework for AI Agents**

## The Problem

AI agents are now browsing the web, clicking buttons, filling forms, and calling APIs on behalf of users. But there's a critical flaw:

**Agents need credentials to act, but credentials in agent memory = credentials at risk.**

Current reality:
- Agents store API keys in memory → Prompt injection can extract them
- Agents log requests → Secrets appear in logs
- Agents crash → Memory dumps contain credentials
- No way for service providers to verify if requests are legitimately secured

Recent incidents show that agent-led credential exposure is a real risk.

## The Solution

Sakaki Browser takes a different approach: **Secrets are encrypted and managed in an isolated Vault process.**

```
Traditional: Agent → Get API Key → Send Request → Leak Risk
Sakaki:      Agent → Vault Proxy → Send Request → Secret Never Exposed
```

The agent requests actions, but never sees or handles the actual credentials.
Public APIs never return secret values; verification is ZKP-like (hash match).
For internal automation (e.g., form fill), a controlled internal retrieval is used.

---

## Benefits for Users (Agent Operators)

| Problem | Sakaki Solution |
|---------|-----------------|
| API keys stolen via prompt injection | Secrets in isolated process - agent can't access |
| Credentials in logs/memory dumps | No public retrieve API - extraction not exposed |
| Slow browser automation | 97% faster (1082ms → 30ms) with browser pool |
| Brittle CSS selectors break | Semantic search finds elements by meaning |
| No audit trail | Every operation logged with timestamps |

**You get:** Safe agent operations without worrying about credential theft.

## Benefits for Service Providers (API/SaaS Companies)

| Problem | Sakaki Solution |
|---------|-----------------|
| Can't verify if client secures credentials | `enforceVaultProxy` rejects non-Vault requests |
| API key abuse from compromised agents | Signature verification proves Vault origin |
| No visibility into agent behavior | Request signing creates audit trail |
| Supporting insecure integrations | Offer "Vault-only" tier for security-conscious users |

**You get:** Confidence that credentials are handled securely, even by AI agents.

```javascript
// Enforce Vault-only access
app.use(createVaultVerificationMiddleware({
  enforceVaultProxy: true,  // Reject requests not from Vault
  allowedKeyIds: ['user-123', 'user-456']
}));
// X-Vault-Signature header automatically verified
```

---

## Features

### 1. ZKP Vault - Process Isolation

- Secrets stored in **separate process** (Unix Socket IPC)
- No public retrieve endpoint; verification is ZKP-like (hash match)
- Proxy makes HTTP requests - secrets injected internally
- SHA-256 for Vault verification (fast hashing module supports BLAKE3 where applicable)

### 2. Bidirectional Trust Chain

- **Agent side:** Credentials never exposed to agent code
- **Provider side:** Can enforce Vault-only requests
- **Both sides:** Cryptographic signatures prove secure handling

### 3. High-Speed Browser Automation

| Metric | Traditional | Sakaki |
|--------|-------------|--------|
| Page Operation | 1082ms | **30ms** |
| Improvement | - | **97%** |

- Browser pool (pre-launched, reused)
- Resource blocking (images/CSS/fonts disabled)
- Semantic element search (resilient to UI changes)

### 4. Realtime Support

- WebSocket Proxy - secure WS connections
- Webhook Receiver - signature-verified webhooks
- Full audit logging

---

## Installation

Requirements:
- Node.js 18+
- Chromium/Chrome (recommended for Puppeteer)

```bash
git clone https://github.com/Thopsdev/SakakiBrowser.git
cd SakakiBrowser
npm install
```

## Start

```bash
npm start
# http://localhost:18800/dashboard
```

## Security Defaults

- Binds to `127.0.0.1` by default (`SAKAKI_BIND=0.0.0.0` to expose).
- Vault endpoints require an admin token for non-local access (`SAKAKI_ADMIN_TOKEN`).
- Vault socket defaults to `~/.sakaki/vault.sock` (`VAULT_SOCKET` to override).
- `/zkp/*` endpoints are admin-protected.
- `/type-secret` is disabled (410) to prevent secrets entering the main process.
- Public lane blocks HTTP by default. Override: `SAKAKI_PUBLIC_ALLOW_HTTP=1`.
- Vault proxy blocks private/metadata targets and allows **HTTPS only** by default.
  - Override: `SAKAKI_PROXY_ALLOW_HTTP=1`, `SAKAKI_PROXY_ALLOW_PRIVATE=1`
  - Optional: `SAKAKI_PROXY_REQUIRE_ALLOWLIST=1` to force `allowedDomains` usage
  - Response size limit: `SAKAKI_PROXY_MAX_BYTES` (default 2MB)
- Secure lane requires an allowlist:
  - `SAKAKI_SECURE_ALLOWED_DOMAINS=example.com,login.example.com`
  - Optional: `SAKAKI_SECURE_ALLOW_SUBDOMAINS=1`
  - Optional: `SAKAKI_SECURE_ALLOW_HTTP=1`
  - Optional: `SAKAKI_SECURE_ALLOW_PRIVATE=1` **(dev/local only — DO NOT enable in production)**
  - Optional: `SAKAKI_SECURE_ALLOW_SENSITIVE=1` (not recommended)
- Vault browser execution:
  - `SAKAKI_VAULT_BROWSER_ALLOWED_DOMAINS` (defaults to `SAKAKI_SECURE_ALLOWED_DOMAINS`)
  - Optional: `SAKAKI_VAULT_BROWSER_ALLOW_SUBDOMAINS=1`
  - Optional: `SAKAKI_VAULT_BROWSER_ALLOW_HTTP=1`
  - Optional: `SAKAKI_VAULT_BROWSER_ALLOW_PRIVATE=1` (not recommended)
  - Optional: `SAKAKI_VAULT_BROWSER_ALLOW_SENSITIVE=1` (not recommended)
  - Optional: `SAKAKI_VAULT_BROWSER_MAX_ACTIONS=50`, `SAKAKI_VAULT_BROWSER_TIMEOUT=30000`
- Remote View (disabled by default):
  - Enable: `SAKAKI_REMOTE_VIEW=1`
  - Limits: `SAKAKI_REMOTE_VIEW_MAX_SESSIONS=3`, `SAKAKI_REMOTE_VIEW_TTL_MS=900000`
  - Quality: `SAKAKI_REMOTE_VIEW_FPS=5`, `SAKAKI_REMOTE_VIEW_QUALITY=60`
  - Input: `SAKAKI_REMOTE_VIEW_ALLOW_TEXT=1`, `SAKAKI_REMOTE_VIEW_ALLOW_SCROLL=1`
  - Sensitive block: `SAKAKI_REMOTE_VIEW_BLOCK_SENSITIVE=1` (default on)
  - Vault lane: `/remote/start` with `"lane":"vault"` + `allowedDomains` + `startUrl`

Production template: `docs/production.env.example`.

## Reverse Proxy (TLS)

Bind Sakaki to localhost and terminate TLS at a reverse proxy.

```nginx
server {
  listen 443 ssl;
  server_name sakaki.example.com;
  ssl_certificate     /etc/letsencrypt/live/sakaki.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/sakaki.example.com/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:18800;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

Always set `SAKAKI_ADMIN_TOKEN` when exposed, and keep Secure/Vault lanes protected.

## Threat Model (Short)

- **Assumption:** The host running Sakaki Browser is trusted.
- **Default stance:** Vault and ZKP endpoints are **admin-only** and **local-only** unless explicitly exposed.
- **If you expose the service:** Use `SAKAKI_ADMIN_TOKEN`, put it behind a reverse proxy, and restrict by IP or mTLS.
- **Secrets handling:** Public APIs never return secret values. Storage still passes through the main process on `/vault/store`.
- **Form fill:** `/type-secret` is disabled by default to prevent accidental secret exposure outside the Vault process.
- **Proxy SSRF guard:** Private IPs and common metadata hosts are blocked unless explicitly allowed.

## Operating Modes

Set `SAKAKI_MODE` to control safety posture.

- `default`: Warn on suspicious input, but do not force Vault-only behavior.
- `strict`: Enforce Vault-only rules (blocks sensitive input outside Vault, requires proxy allowlist, defaults `enforceVaultProxy=true`).
- `vault_only`: Alias of `strict` for compatibility (same as `SAKAKI_VAULT_ONLY=1`).

## Strict Vault-Only Mode (Recommended for AI Agents)

Set `SAKAKI_MODE=strict` (or `SAKAKI_MODE=vault_only`, `SAKAKI_VAULT_ONLY=1`) to enforce the following:

- Sensitive input is **blocked** in public and secure lanes. Use `/vault/browser/execute` with `typeFromVault`.
- Vault proxy requires an **allowlist** (`SAKAKI_PROXY_REQUIRE_ALLOWLIST=1` enforced).
- External APIs can be forced to accept **Vault-signed requests only** (`enforceVaultProxy=true`).
- Unsafe toggles are **forced OFF** (HTTP/private/sensitive allow flags are ignored).

This mode is designed for “agent runs without secret exposure.”

Provider template:
- `examples/provider/express-vault-enforcement.js`

## Vault Proxy Signature Spec

Vault-signed requests include these headers:

- `X-Vault-Signature`
- `X-Vault-KeyId`
- `X-Vault-Timestamp`
- `X-Vault-Proxy`

Signature payload (HMAC-SHA256):

```
${METHOD}\n${FULL_URL}\n${TIMESTAMP}\n${BODY}
```

Rules:

- `METHOD` is uppercased.
- `FULL_URL` is `scheme://host/path?query`. In reverse proxies, use `X-Forwarded-Proto` and `X-Forwarded-Host` if present.
- `TIMESTAMP` is milliseconds since epoch (string). Default acceptance window is 5 minutes.
- `BODY` is `JSON.stringify(req.body)` for JSON requests, otherwise the raw body string. Empty body = empty string.

This spec matches the default `createVaultVerificationMiddleware()` implementation.

## Responsible Use

Sakaki Browser is a defensive security tool for **user-authorized automation** and **secret protection**.
Do not use it to access systems without permission, bypass security controls, or violate site terms.
Operators are responsible for compliance with applicable laws and service policies.

## Limitations (Read This)

- **Host trust is required.** If the host is compromised, secrets can be exposed.
- **Remote View is a human assist.** Anything typed by a human can still be leaked by that human.
- **Allowlists and tokens are mandatory for safe operation.** Misconfiguration can negate protections.
- **Some sites actively block automation.** Remote View exists for those cases, but success is never guaranteed.
- **Constrained environments may block browser launch.** If Puppeteer/Playwright cannot start, use the fallback options below.

### Browser Launch Fallbacks

If the browser fails to launch in restricted environments (CI, MDM, containers):

- Set `SAKAKI_BROWSER_PATH` to a real installed browser binary.
- Switch backend: `SAKAKI_BACKEND=playwright` (often more tolerant).
- API-only mode: `SAKAKI_SKIP_BROWSER_INIT=1` (Vault Proxy / signatures / allowlists still work).

## Security Checklist (Recommended)

- Keep default bind on localhost unless you must expose it.
- If exposed, always set `SAKAKI_ADMIN_TOKEN` and put it behind a reverse proxy.
- Use allowlists for secure lane and vault browser actions.
- Keep `SAKAKI_SECURE_ALLOW_PRIVATE` disabled in production.
- Rotate admin tokens periodically.
- Enable audit logs and monitor for unexpected access.

## Common Misconfigurations (Avoid)

- Exposing the service publicly without `SAKAKI_ADMIN_TOKEN`.
- Running secure lane without allowlists.
- Enabling `SAKAKI_SECURE_ALLOW_PRIVATE=1` in production.
- Storing secrets in plain files or logs outside the Vault.
- Allowing HTTP for the public lane in production.

## Audit Logs (How to Read)

Audit logs record **who did what and when**. Use them to detect misuse or unexpected automation.

```
# Example (JSON line)
{"timestamp":"2026-02-11T12:00:00Z","action":"vault.store","success":true,"meta":{"name":"openai-key"}}
{"timestamp":"2026-02-11T12:01:00Z","action":"secure.navigate","success":true,"meta":{"url":"https://example.com"}}
{"timestamp":"2026-02-11T12:02:10Z","action":"vault.proxy","success":false,"meta":{"reason":"blocked_private"}}
```

What to watch:
- Repeated failures (possible misconfig or probing)
- Requests to private or metadata targets
- Unexpected domains or off-hours activity

## Quick Start

### 60-Second Demo (Vault → Proxy → Secure Lane)

```bash
# 1) Start
npm start

# 2) Store a secret (local only)
curl -X POST http://localhost:18800/vault/store \
  -H "Content-Type: application/json" \
  -d '{"name":"openai-key","value":"sk-..."}'

# 3) Call an API via Vault Proxy (secret never leaves Vault)
curl -X POST http://localhost:18800/vault/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "secretName": "openai-key",
    "url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "headerTemplate": "Bearer ${secret}",
    "body": {"model": "gpt-4", "messages": [{"role":"user","content":"hello"}]}
  }'

# 4) Secure lane (allowlist required)
export SAKAKI_SECURE_ALLOWED_DOMAINS="example.com"
export SAKAKI_ADMIN_TOKEN="change-me"
curl -X POST http://localhost:18800/secure/navigate \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### Store a Secret

```bash
curl -X POST http://localhost:18800/vault/store \
  -H "Content-Type: application/json" \
  -d '{"name":"openai-key","value":"sk-..."}'
```

If you bind to a non-local interface, set an admin token and pass it:

```bash
export SAKAKI_ADMIN_TOKEN="change-me"
curl -X POST http://localhost:18800/vault/store \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"openai-key","value":"sk-..."}'
```

### Make API Call via Vault Proxy

```bash
curl -X POST http://localhost:18800/vault/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "secretName": "openai-key",
    "url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "headerTemplate": "Bearer ${secret}",
    "body": {"model": "gpt-4", "messages": [...]}
  }'
```

→ API key injected inside Vault process. Agent never sees it.

## CLI Bridge (NDJSON for Any AI CLI)

Any AI CLI can speak NDJSON over stdin/stdout. This makes Sakaki usable from any tool
that can pipe JSON.

See `docs/bridge.md` for the full protocol.
Ollama wrappers are in `examples/ollama/README.md`.
Codex/Claude/Gemini wrappers are in `examples/cli/README.md`.

```bash
# HTTP-style
echo '{"id":"1","method":"GET","path":"/health"}' | sakaki bridge

# Action-style (maps to endpoints)
echo '{"id":"2","action":"navigate","url":"https://example.com"}' | sakaki bridge
echo '{"id":"3","action":"vault.list"}' | sakaki bridge

# Per-message auth token
echo '{"id":"4","action":"vault.list","adminToken":"change-me"}' | sakaki bridge
```

Stable CLI usage:

```bash
# Claude: de-duplicate repeated NDJSON lines
SAKAKI_DEDUPLICATE=1 ./examples/cli/claude-bridge.sh "Open https://example.com"

# Codex: uses codex exec + output schema by default
./examples/cli/codex-bridge.sh "Open https://example.com"
```

Codex note: Codex is most stable with `codex exec --output-schema` (used by default in the wrapper).
If you override `CODEX_CMD`, keep `--output-schema` and `--output-last-message` to avoid noisy output.

Supported fields:
`id`, `method`, `path`, `body`, `action`, `headers`, `query`, `adminToken`.
If `method/path` are missing, `action` is mapped to the endpoint.

## Two-Lane Browsing (Public / Secure)

- **Public lane** (`/navigate`, `/click`, `/type`): Free exploration. No secrets.
- **Secure lane** (`/secure/*`): Allowlist + HTTPS enforced. All sensitive actions live here.

Secure lane requires an allowlist:

```bash
export SAKAKI_SECURE_ALLOWED_DOMAINS="example.com,login.example.com"
export SAKAKI_ADMIN_TOKEN="change-me"
```

Example:

```bash
curl -X POST http://localhost:18800/secure/navigate \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://login.example.com"}'
```

## Vault Browser Execution (Secrets Stay Inside Vault)

If the agent must handle secrets, execute browser actions **inside the Vault process**.
This keeps secrets out of the main process.

```bash
curl -X POST http://localhost:18800/vault/browser/execute \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "allowedDomains": ["login.example.com"],
    "actions": [
      { "type": "navigate", "url": "https://login.example.com" },
      { "type": "typeFromVault", "selector": "#email", "secretName": "account-email" },
      { "type": "typeFromVault", "selector": "#password", "secretName": "account-pass" },
      { "type": "click", "selector": "button[type=submit]" },
      { "type": "waitForNavigation" }
    ]
  }'
```

Notes:
- Empty `allowedDomains` is rejected.
- Non-HTTPS and private/local targets are blocked.
- If Chromium fails to launch, set `PUPPETEER_EXECUTABLE_PATH`.

## Remote View (Human-in-the-Loop Streaming)

For CAPTCHA or 2FA steps. **Default OFF**.
Frames and commands are **HMAC-SHA256 signed**.

```bash
export SAKAKI_REMOTE_VIEW=1
export SAKAKI_ADMIN_TOKEN="change-me"
```

Start:

```bash
curl -X POST http://localhost:18800/remote/start \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"lane":"secure","fps":5,"quality":60,"allowInput":true}'
```

The response includes `viewUrl` (tokenized). Open it to view the stream.
Do not share `viewUrl` publicly.

To stream a Vault lane session:

```bash
curl -X POST http://localhost:18800/remote/start \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"lane":"vault","startUrl":"https://www.wikipedia.org/","allowedDomains":["wikipedia.org"],"allowSubdomains":true,"allowInput":true}'
```

## Headless / Headful

```bash
# Toggle headless (true|false|new)
export SAKAKI_HEADLESS_MODE=true

# Extra Chrome flags
export SAKAKI_PUPPETEER_ARGS="--disable-features=Translate;--lang=en-US"

# Force single-process if needed
export SAKAKI_PUPPETEER_FORCE_SINGLE_PROCESS=1

# Vault side overrides
export SAKAKI_VAULT_HEADLESS_MODE=false
export SAKAKI_VAULT_PUPPETEER_ARGS="--lang=en-US"
export SAKAKI_VAULT_PUPPETEER_FORCE_SINGLE_PROCESS=1
```

## Browser Backend / OS and Browser Support

Sakaki supports **Puppeteer (Chromium)** or **Playwright (Chromium/Firefox/WebKit)**.

```bash
# Backend
export SAKAKI_BACKEND=puppeteer   # default
export SAKAKI_BACKEND=playwright

# Browser selection (auto-detect)
export SAKAKI_BROWSER=chrome|edge|brave|chromium|firefox|webkit

# Explicit path (Chrome/Edge/Brave)
export SAKAKI_BROWSER_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
export PUPPETEER_EXECUTABLE_PATH="/usr/bin/google-chrome"   # legacy

# Vault side overrides
export SAKAKI_VAULT_BACKEND=playwright
export SAKAKI_VAULT_BROWSER=firefox
export SAKAKI_VAULT_BROWSER_PATH="/usr/bin/firefox"
```

For Playwright:

```bash
npm install playwright-core
npx playwright install
```

## Challenge Gate (CAPTCHA/2FA Detection → Pause → Notify)

When CAPTCHA/2FA is detected, automation pauses and a notification is sent.
If Remote View is enabled, a session is created automatically and `viewUrl` is returned.

### Environment variables

```bash
# Auto start Remote View on challenge (default: on)
export SAKAKI_CHALLENGE_AUTO_REMOTE=1

# Cooldown between notifications (ms, default: 60000)
export SAKAKI_CHALLENGE_NOTIFY_COOLDOWN_MS=60000

# Text scan limit (default: 2000)
export SAKAKI_CHALLENGE_TEXT_LIMIT=2000

# Detection score threshold (default: 2)
export SAKAKI_CHALLENGE_MIN_SCORE=2

# Ignore or force specific domains
export SAKAKI_CHALLENGE_DOMAIN_IGNORE="docs.example.com,blog.example.com"
export SAKAKI_CHALLENGE_DOMAIN_FORCE="accounts.example.com"

# Extra detection patterns (regex or strings; use ; to separate)
export SAKAKI_CHALLENGE_URL_REGEX="challenge;recaptcha"
export SAKAKI_CHALLENGE_TEXT_REGEX="verify your identity;one-time code"
export SAKAKI_CHALLENGE_SELECTOR="iframe[src*='recaptcha'];#challenge"
```

### Response example

```json
{
  "blocked": true,
  "reason": "challenge_required",
  "challenge": { "kind": "captcha", "evidence": ["selector:iframe[src*=\"recaptcha\"]"] },
  "remoteView": { "viewUrl": "/remote/view/abcd?token=..." },
  "eventId": "..."
}
```

Notification events:
- `challenge_required`
- `challenge_resolved`

Note: Challenge auto-initiated Remote View sessions are closed automatically when the challenge resolves.

### Remote View TTL / Idle

```bash
# Base TTL (default: 900000ms)
export SAKAKI_REMOTE_VIEW_TTL_MS=900000

# Max TTL (default: TTL x2)
export SAKAKI_REMOTE_VIEW_MAX_TTL_MS=1800000

# Idle timeout (default: 120000ms)
export SAKAKI_REMOTE_VIEW_IDLE_TIMEOUT_MS=120000

# TTL extension on activity (default: TTL)
export SAKAKI_REMOTE_VIEW_ACTIVITY_EXTEND_MS=900000
```

## Notifications (In-App / Webhook / Email)

Use notifications for human approval flows (sensitive inputs, challenges).

### Environment variables

```bash
# Webhook (multiple allowed)
export SAKAKI_NOTIFY_WEBHOOKS="https://example.com/webhook,https://hooks.slack.com/..."
export SAKAKI_NOTIFY_WEBHOOK_SECRET="optional-shared-secret"

# Email (SMTP)
export SAKAKI_SMTP_HOST="smtp.example.com"
export SAKAKI_SMTP_PORT="587"
export SAKAKI_SMTP_SECURE="false"
export SAKAKI_SMTP_USER="smtp-user"
export SAKAKI_SMTP_PASS="smtp-pass"
export SAKAKI_NOTIFY_EMAIL_FROM="sakaki@example.com"
export SAKAKI_NOTIFY_EMAIL_TO="ops@example.com,security@example.com"
```

Note: Email notifications require `nodemailer`.

### API

```bash
# List events
curl http://localhost:18800/notify/events \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN"

# Test notification
curl -X POST http://localhost:18800/notify/test \
  -H "Authorization: Bearer $SAKAKI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"challenge_required","message":"Human input needed"}'
```

## Semantic Element Search

```javascript
const { fastBrowser } = require('./src/browser/fast-browser');

await fastBrowser.open('https://example.com/login');
await fastBrowser.type('email_input', 'user@example.com');
await fastBrowser.type('password_input', 'password');
await fastBrowser.click('login_button');

// No CSS selectors. Works even when UI changes.
```

---

## API Reference

### Vault

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/vault/store` | POST | Store secret |
| `/vault/verify` | POST | ZKP verification (confirm without revealing) |
| `/vault/proxy` | POST | HTTP request via Proxy |
| `/vault/browser/execute` | POST | Execute browser actions inside Vault |
| `/vault/list` | GET | List secrets (names only) |

### Browser

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/navigate` | POST | Navigate URL (with security check) |
| `/screenshot` | POST | Take screenshot |
| `/click` | POST | Click element |
| `/type` | POST | Type text |
| `/secure/navigate` | POST | Secure lane navigate |
| `/secure/click` | POST | Secure lane click |
| `/secure/type` | POST | Secure lane type |
| `/remote/start` | POST | Start Remote View |
| `/remote/stop` | POST | Stop Remote View |
| `/fast/open` | POST | Fast open (pool) |
| `/fast/click` | POST | Fast click |
| `/fast/type` | POST | Fast type |
| `/fast/dom` | POST | Fast DOM snapshot |

### Security

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/detect-sensitive` | POST | Detect sensitive data |
| `/scan/file` | POST | Antivirus scan |
| `/audit-log` | GET | Get operation log |
| `/health` | GET | Health check |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Sakaki Browser                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Browser    │    │   Guardian   │    │   Antivirus  │  │
│  │    Pool      │    │  (audit)     │    │   Scanner    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Semantic    │    │   WebSocket  │    │   Webhook    │  │
│  │   Finder     │    │    Proxy     │    │   Receiver   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Unix Socket IPC                           │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  Vault Process                        │  │
│  │   • Complete process isolation                        │  │
│  │   • No public retrieve API (verify-only)              │  │
│  │   • Proxy injects secrets internally                  │  │
│  │   • BLAKE3 + SecureBuffer (auto-zeroing)              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Benchmark

### Browser Speed
```
Traditional: 1082ms
Sakaki:      30ms
Improvement: 97%
```

### Hash Speed (1MB)
```
SHA256:  193ms
BLAKE3:  24ms
Improvement: 8x
```
Measured on local macOS dev machine; results vary by hardware.

---

## Security

Found a vulnerability? Contact directly - do not create public issues.

## Antivirus Compatibility (User Environment)

Sakaki runs alongside your existing antivirus. It does **not** disable or replace it.
If you use AV products that perform HTTPS inspection or aggressive sandboxing,
you may see connection errors or headless browser launch failures.

Troubleshooting tips:
- If you see TLS/certificate errors, try excluding the Sakaki process (`node`) and the browser (`chrome`/`msedge`/`brave`) from HTTPS inspection.
- If browser launch fails, whitelist the browser executable and `node` in your AV.
- You can also run in `headful` mode temporarily to confirm whether the AV is interfering.

## License

MIT

## Contributing

PRs welcome.
