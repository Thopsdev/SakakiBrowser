#!/usr/bin/env node
/**
 * Vault Security Test
 *
 * 全ての脆弱性が潰されているか検証
 */

const { spawn } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');

const SOCKET_PATH = '/tmp/sakaki-vault-test.sock';
const VAULT_FILE = '/tmp/sakaki-vault-test.enc';
const VAULT_PROCESS = path.join(__dirname, '../src/security/vault-process.js');

let vaultProc = null;
let passed = 0;
let failed = 0;

// テストユーティリティ
function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.log(`  ✗ ${message}`);
    failed++;
  }
}

async function sendCommand(command, params = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(SOCKET_PATH);
    let buffer = '';

    socket.on('connect', () => {
      socket.write(JSON.stringify({ command, params }) + '\n');
    });

    socket.on('data', (data) => {
      buffer += data.toString();
      if (buffer.endsWith('\n')) {
        socket.end();
        resolve(JSON.parse(buffer.trim()));
      }
    });

    socket.on('error', reject);
    socket.setTimeout(5000);
  });
}

async function startVault(keepData = false) {
  // クリーンアップ
  try { fs.unlinkSync(SOCKET_PATH); } catch {}
  if (!keepData) {
    try { fs.unlinkSync(VAULT_FILE); } catch {}
  }

  return new Promise((resolve, reject) => {
    vaultProc = spawn('node', [VAULT_PROCESS], {
      env: { ...process.env, VAULT_SOCKET: SOCKET_PATH, VAULT_FILE: VAULT_FILE },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    vaultProc.stdout.on('data', (data) => {
      if (data.toString().includes('Listening')) {
        setTimeout(resolve, 100);
      }
    });

    vaultProc.on('error', reject);
    setTimeout(() => reject(new Error('Timeout')), 5000);
  });
}

function stopVault() {
  if (vaultProc) {
    vaultProc.kill('SIGTERM');
    vaultProc = null;
  }
  try { fs.unlinkSync(SOCKET_PATH); } catch {}
}

// ========== テストケース ==========

async function test1_NoRetrieveMethod() {
  console.log('\n[Test 1] retrieve() メソッドが存在しないこと');

  // retrieve コマンドを送信
  const result = await sendCommand('retrieve', { name: 'test' });

  assert(result.error === 'Unknown command', 'retrieve コマンドは存在しない');
}

async function test2_MasterKeyRequired() {
  console.log('\n[Test 2] マスターキーが必須');

  // 短すぎるキー
  const result1 = await sendCommand('init', { masterKey: 'short' });
  assert(!result1.success, '短いキーは拒否される');
  assert(result1.error.includes('16 characters'), 'エラーメッセージが適切');

  // キーなし
  const result2 = await sendCommand('init', {});
  assert(!result2.success, 'キーなしは拒否される');
}

async function test3_StoreAndVerify() {
  console.log('\n[Test 3] 保存と検証 (ZKP)');

  // 初期化
  await sendCommand('init', { masterKey: 'test-master-key-16chars' });

  // 保存
  const storeResult = await sendCommand('store', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(storeResult.success, 'シークレット保存成功');
  assert(!storeResult.value, '保存結果に値が含まれていない');

  // 正しい値で検証
  const verifyOk = await sendCommand('verify', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(verifyOk.valid === true, '正しい値で検証成功');
  assert(!verifyOk.value, '検証結果に値が含まれていない');

  // 間違った値で検証
  const verifyFail = await sendCommand('verify', {
    name: 'api_key',
    value: 'wrong-value'
  });
  assert(verifyFail.valid === false, '間違った値は検証失敗');
}

async function test4_ListOnlyNames() {
  console.log('\n[Test 4] 一覧は名前のみ返す');

  const listResult = await sendCommand('list');
  assert(listResult.success, '一覧取得成功');
  assert(Array.isArray(listResult.secrets), '配列が返される');

  for (const secret of listResult.secrets) {
    assert(secret.name !== undefined, '名前が含まれる');
    assert(secret.value === undefined, '値が含まれていない');
    assert(secret.encrypted === undefined, '暗号化データが含まれていない');
    assert(secret.hash === undefined, 'ハッシュが含まれていない');
  }
}

async function test5_BruteForceProtection() {
  console.log('\n[Test 5] ブルートフォース対策');

  // 10回連続で間違った値を送信
  for (let i = 0; i < 10; i++) {
    await sendCommand('verify', {
      name: 'api_key',
      value: `wrong-attempt-${i}`
    });
  }

  // 11回目はロックアウト
  const lockedResult = await sendCommand('verify', {
    name: 'api_key',
    value: 'another-attempt'
  });

  assert(!lockedResult.success, 'ロックアウトされる');
  assert(lockedResult.error.includes('Too many'), 'レート制限エラー');
}

async function test6_AuditLogging() {
  console.log('\n[Test 6] 監査ログ');

  const auditResult = await sendCommand('audit', { limit: 50 });
  assert(auditResult.success, '監査ログ取得成功');
  assert(Array.isArray(auditResult.log), 'ログ配列が返される');
  assert(auditResult.log.length > 0, 'ログが記録されている');

  // ログエントリの構造を確認
  const entry = auditResult.log[0];
  assert(entry.timestamp, 'タイムスタンプがある');
  assert(entry.action, 'アクションがある');
  assert(entry.success !== undefined, '成功/失敗フラグがある');
}

async function test7_Persistence() {
  console.log('\n[Test 7] 永続化');

  // Vaultを再起動 (データは保持)
  stopVault();
  await startVault(true); // keepData = true

  // 再初期化
  await sendCommand('init', { masterKey: 'test-master-key-16chars' });

  // 以前のシークレットが残っているか
  const listResult = await sendCommand('list');
  assert(listResult.secrets.some(s => s.name === 'api_key'), '再起動後もシークレットが残る');

  // 検証もできる
  const verifyResult = await sendCommand('verify', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(verifyResult.valid === true, '再起動後も検証できる');
}

async function test8_ProcessIsolation() {
  console.log('\n[Test 8] プロセス分離');

  const status = await sendCommand('status');
  assert(status.pid !== process.pid, 'Vaultは別プロセスで動作');
  assert(status.pid > 0, '有効なPID');
}

async function test9_DeleteSecret() {
  console.log('\n[Test 9] シークレット削除');

  // 新しいシークレットを追加
  await sendCommand('store', { name: 'to_delete', value: 'temp' });

  // 削除
  const deleteResult = await sendCommand('delete', { name: 'to_delete' });
  assert(deleteResult.success, '削除成功');

  // 検証しようとすると失敗
  const verifyResult = await sendCommand('verify', { name: 'to_delete', value: 'temp' });
  assert(!verifyResult.success || !verifyResult.valid, '削除後は検証できない');
}

async function test10_NoDefaultKey() {
  console.log('\n[Test 10] デフォルトキーなし');

  // vault.jsのソースコードを検査
  const vaultSource = fs.readFileSync(VAULT_PROCESS, 'utf8');

  assert(!vaultSource.includes("'default'"), "ハードコードされた 'default' キーがない");
  assert(!vaultSource.includes('"default"'), 'ハードコードされた "default" キーがない');
}

async function test11_RandomSaltPerSecret() {
  console.log('\n[Test 11] シークレット毎にランダムsalt');

  // vault.jsのソースコードを検査
  const vaultSource = fs.readFileSync(VAULT_PROCESS, 'utf8');

  assert(!vaultSource.includes("'salt'"), "ハードコードされた 'salt' がない");
  assert(vaultSource.includes('randomBytes(32)'), 'ランダムsalt生成がある');
}

// ========== メイン ==========

async function main() {
  console.log('='.repeat(60));
  console.log('Vault Security Test');
  console.log('='.repeat(60));

  try {
    await startVault();

    await test1_NoRetrieveMethod();
    await test2_MasterKeyRequired();
    await test3_StoreAndVerify();
    await test4_ListOnlyNames();
    await test5_BruteForceProtection();
    await test6_AuditLogging();
    await test7_Persistence();
    await test8_ProcessIsolation();
    await test9_DeleteSecret();
    await test10_NoDefaultKey();
    await test11_RandomSaltPerSecret();

  } catch (e) {
    console.error('\nError:', e.message);
    failed++;
  } finally {
    stopVault();
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(60));

  // クリーンアップ
  try { fs.unlinkSync(VAULT_FILE); } catch {}

  process.exit(failed > 0 ? 1 : 0);
}

main();
