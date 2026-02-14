/**
 * Example: Client using ZKP to authenticate
 *
 * Authenticate without sending API keys over the network
 */

const { ZKPClient } = require('../src/plugins/zkp-provider');

// Simulation
async function simulateAuth() {
  const API_KEY = 'demo-key-12345';
  const KEY_ID = 'user-123';

  // Initialize client (stores only the key hash)
  const client = new ZKPClient(API_KEY);

  console.log('=== ZKP Authentication Flow ===\n');

  // Step 1: request challenge from server
  console.log('1. Request challenge from server');
  console.log(`   POST /auth/challenge { keyId: "${KEY_ID}" }`);

  // (In practice, use fetch)
  // const { sessionId, challenge } = await fetch('/auth/challenge', {...})

  // Simulated challenge
  const challenge = 'abc123...server-generated-random';
  const sessionId = 'session-xyz';

  console.log(`   Response: { sessionId: "${sessionId}", challenge: "${challenge.slice(0, 20)}..." }\n`);

  // Step 2: respond to challenge
  console.log('2. Compute response (locally, key never leaves client)');
  const response = client.respondToChallenge(challenge);
  console.log(`   response = hash(keyHash + challenge) = "${response.slice(0, 20)}..."\n`);

  // Step 3: send response to server
  console.log('3. Send response to server');
  console.log(`   POST /auth/verify { sessionId: "${sessionId}", response: "${response.slice(0, 20)}..." }`);
  console.log('   Response: { valid: true, keyId: "user-123" }\n');

  // Step 4: access protected API
  console.log('4. Access protected API with ZKP auth header');
  console.log('   GET /api/protected');
  console.log('   Header: X-ZKP-Auth: { sessionId, response }');
  console.log('   Response: { message: "Welcome!" }\n');

  console.log('=== Key Benefits ===');
  console.log('- API key NEVER transmitted over network');
  console.log('- Server only stores hash, not actual key');
  console.log('- Challenge-response prevents replay attempts');
  console.log('- Even if traffic is intercepted, key is safe');
}

// Real HTTP example
async function realAuth(baseUrl, keyId, apiKey) {
  const client = new ZKPClient(apiKey);

  // Step 1: get challenge
  const challengeRes = await fetch(`${baseUrl}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ keyId })
  });
  const { sessionId, challenge, error } = await challengeRes.json();

  if (error) throw new Error(error);

  // Step 2: compute response and send
  const response = client.respondToChallenge(challenge);

  const verifyRes = await fetch(`${baseUrl}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, response })
  });

  return verifyRes.json();
}

// Run
simulateAuth();

module.exports = { realAuth };
