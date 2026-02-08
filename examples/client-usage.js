/**
 * Example: Client using ZKP to authenticate
 *
 * APIキーをネットワークに流さずに認証
 */

const { ZKPClient } = require('../src/plugins/zkp-provider');

// シミュレーション用
async function simulateAuth() {
  const API_KEY = 'sk-super-secret-key-12345';
  const KEY_ID = 'user-123';

  // クライアント初期化 (キーのハッシュのみ保持)
  const client = new ZKPClient(API_KEY);

  console.log('=== ZKP Authentication Flow ===\n');

  // Step 1: サーバーにチャレンジを要求
  console.log('1. Request challenge from server');
  console.log(`   POST /auth/challenge { keyId: "${KEY_ID}" }`);

  // (実際はfetchで行う)
  // const { sessionId, challenge } = await fetch('/auth/challenge', {...})

  // シミュレーション用のチャレンジ
  const challenge = 'abc123...server-generated-random';
  const sessionId = 'session-xyz';

  console.log(`   Response: { sessionId: "${sessionId}", challenge: "${challenge.slice(0, 20)}..." }\n`);

  // Step 2: チャレンジに応答
  console.log('2. Compute response (locally, key never leaves client)');
  const response = client.respondToChallenge(challenge);
  console.log(`   response = hash(keyHash + challenge) = "${response.slice(0, 20)}..."\n`);

  // Step 3: サーバーに応答を送信
  console.log('3. Send response to server');
  console.log(`   POST /auth/verify { sessionId: "${sessionId}", response: "${response.slice(0, 20)}..." }`);
  console.log('   Response: { valid: true, keyId: "user-123" }\n');

  // Step 4: 保護されたAPIにアクセス
  console.log('4. Access protected API with ZKP auth header');
  console.log('   GET /api/protected');
  console.log('   Header: X-ZKP-Auth: { sessionId, response }');
  console.log('   Response: { message: "Welcome!" }\n');

  console.log('=== Key Benefits ===');
  console.log('- API key NEVER transmitted over network');
  console.log('- Server only stores hash, not actual key');
  console.log('- Challenge-response prevents replay attacks');
  console.log('- Even if traffic is intercepted, key is safe');
}

// 実際のHTTP呼び出し例
async function realAuth(baseUrl, keyId, apiKey) {
  const client = new ZKPClient(apiKey);

  // Step 1: チャレンジ取得
  const challengeRes = await fetch(`${baseUrl}/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ keyId })
  });
  const { sessionId, challenge, error } = await challengeRes.json();

  if (error) throw new Error(error);

  // Step 2: 応答を計算して送信
  const response = client.respondToChallenge(challenge);

  const verifyRes = await fetch(`${baseUrl}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, response })
  });

  return verifyRes.json();
}

// 実行
simulateAuth();

module.exports = { realAuth };
