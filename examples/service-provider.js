/**
 * Example: Service Provider using ZKP Authentication
 *
 * APIキーを一度も見ずにクライアントを認証
 */

const express = require('express');
const { ZKPProvider, createZKPMiddleware } = require('../src/plugins/zkp-provider');

const app = express();
app.use(express.json());

// ZKP Provider インスタンス
const zkp = new ZKPProvider({ name: 'example-api' });
const middleware = createZKPMiddleware(zkp);

// === 管理者用: APIキー登録 ===
// (実際はダッシュボードやCLIで行う)
app.post('/admin/register-key', (req, res) => {
  const { keyId, apiKey, metadata } = req.body;
  const result = zkp.registerKey(keyId, apiKey, metadata);
  res.json(result);
});

// === 認証フロー ===

// Step 1: クライアントがチャレンジを要求
app.post('/auth/challenge', middleware.challenge);

// Step 2: クライアントが応答を送信して検証
app.post('/auth/verify', middleware.verify);

// === 保護されたAPI ===
// ZKP認証が必要なエンドポイント
app.get('/api/protected', middleware.authenticate, (req, res) => {
  res.json({
    message: 'Welcome! You are authenticated via ZKP',
    keyId: req.zkpAuth.keyId,
    metadata: req.zkpAuth.metadata
  });
});

// 公開API
app.get('/api/public', (req, res) => {
  res.json({ message: 'This is public' });
});

// 統計
app.get('/admin/stats', (req, res) => {
  res.json(zkp.getStats());
});

const PORT = 18801;
app.listen(PORT, () => {
  console.log(`[Example API] Listening on port ${PORT}`);
  console.log('[Example API] ZKP authentication enabled');
});
