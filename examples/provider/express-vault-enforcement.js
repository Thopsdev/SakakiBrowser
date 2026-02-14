#!/usr/bin/env node
/**
 * Example: Provider-side Vault enforcement middleware (Express)
 *
 * This shows how a service can require Vault-signed requests only.
 *
 * Required env:
 * - VAULT_KEY_ID: Public key ID issued by Sakaki Vault
 * - VAULT_SIGNING_KEY: Shared signing key from /vault/proxy/signing-key
 *
 * Optional:
 * - ENFORCE_VAULT_PROXY=1 (default)
 * - VAULT_ALLOWED_PROXIES="sakaki-vault,company-vault"
 */

const express = require('express');
const { createVaultVerificationMiddleware } = require('../../src/security/vault-proxy');

const app = express();
app.use(express.json());

const VAULT_KEY_ID = process.env.VAULT_KEY_ID || '';
const VAULT_SIGNING_KEY = process.env.VAULT_SIGNING_KEY || '';
const ENFORCE_VAULT_PROXY = process.env.ENFORCE_VAULT_PROXY !== '0';
const ALLOWED_PROXIES = (process.env.VAULT_ALLOWED_PROXIES || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

if (!VAULT_KEY_ID || !VAULT_SIGNING_KEY) {
  console.error('Missing VAULT_KEY_ID or VAULT_SIGNING_KEY');
  process.exit(1);
}

const vaultOnly = createVaultVerificationMiddleware({
  signingKey: VAULT_SIGNING_KEY,
  publicKeyId: VAULT_KEY_ID,
  enforceVaultProxy: ENFORCE_VAULT_PROXY,
  allowedProxyNames: ALLOWED_PROXIES
});

app.post('/api/protected', vaultOnly, (req, res) => {
  res.json({
    ok: true,
    vaultVerified: req.vaultVerified === true,
    vaultKeyId: req.vaultKeyId || null,
    vaultProxy: req.vaultProxy || null
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[provider] listening on http://127.0.0.1:${PORT}`);
});
