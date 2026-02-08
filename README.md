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

**2026 has already seen critical RCEs and mass API key leaks from AI agent frameworks.**

## The Solution

Sakaki Browser takes a different approach: **Secrets never leave the Vault process.**

```
Traditional: Agent → Get API Key → Send Request → Leak Risk
Sakaki:      Agent → Vault Proxy → Send Request → Secret Never Exposed
```

The agent requests actions, but never sees or handles the actual credentials.

---

## Benefits for Users (Agent Operators)

| Problem | Sakaki Solution |
|---------|-----------------|
| API keys stolen via prompt injection | Secrets in isolated process - agent can't access |
| Credentials in logs/memory dumps | No `retrieve()` method - extraction impossible |
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
- No `retrieve()` method - values cannot be extracted
- Proxy makes HTTP requests - secrets injected internally
- BLAKE3 hashing (8x faster than SHA256)

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

```bash
git clone https://github.com/Thopsdev/SakakiBrowser.git
cd SakakiBrowser
npm install
```

## Start

```bash
npm start
# http://localhost:18800
```

## Quick Start

### Store a Secret

```bash
curl -X POST http://localhost:18800/vault/store \
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

### Semantic Element Search

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
| `/vault/list` | GET | List secrets (names only) |

### Browser

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/navigate` | POST | Navigate URL (with security check) |
| `/screenshot` | POST | Take screenshot |
| `/click` | POST | Click element |
| `/type` | POST | Type text |

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
│  │   • No retrieve() - extraction impossible             │  │
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

---

## Security

Found a vulnerability? Contact directly - do not create public issues.

## License

MIT

## Contributing

PRs welcome.
