/**
 * Example: Service Provider using ZKP Authentication
 *
 * Authenticate clients without ever seeing their API keys
 */

const express = require('express');
const { ZKPProvider, createZKPMiddleware } = require('../src/plugins/zkp-provider');

const app = express();
app.use(express.json());

// ZKP Provider instance
const zkp = new ZKPProvider({ name: 'example-api' });
const middleware = createZKPMiddleware(zkp);

// === Admin: API key registration ===
// (Typically done via dashboard or CLI)
app.post('/admin/register-key', (req, res) => {
  const { keyId, apiKey, metadata } = req.body;
  const result = zkp.registerKey(keyId, apiKey, metadata);
  res.json(result);
});

// === Authentication flow ===

// Step 1: client requests a challenge
app.post('/auth/challenge', middleware.challenge);

// Step 2: client submits response for verification
app.post('/auth/verify', middleware.verify);

// === Protected API ===
// Endpoints that require ZKP authentication
app.get('/api/protected', middleware.authenticate, (req, res) => {
  res.json({
    message: 'Welcome! You are authenticated via ZKP',
    keyId: req.zkpAuth.keyId,
    metadata: req.zkpAuth.metadata
  });
});

// Public API
app.get('/api/public', (req, res) => {
  res.json({ message: 'This is public' });
});

// Stats
app.get('/admin/stats', (req, res) => {
  res.json(zkp.getStats());
});

const PORT = 18801;
app.listen(PORT, () => {
  console.log(`[Example API] Listening on port ${PORT}`);
  console.log('[Example API] ZKP authentication enabled');
});
