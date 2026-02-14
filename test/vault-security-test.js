#!/usr/bin/env node
/**
 * Vault Security Test
 *
 * Verify that known security issues are mitigated
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

// Test utilities
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
  // Cleanup
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

// ========== Test cases ==========

async function test1_NoRetrieveMethod() {
  console.log('\n[Test 1] retrieve() method is not available');

  // Send retrieve command
  const result = await sendCommand('retrieve', { name: 'test' });

  assert(result.error === 'Unknown command', 'retrieve command is not available');
}

async function test2_MasterKeyRequired() {
  console.log('\n[Test 2] master key is required');

  // Key too short
  const result1 = await sendCommand('init', { masterKey: 'short' });
  assert(!result1.success, 'short keys are rejected');
  assert(result1.error.includes('16 characters'), 'error message is correct');

  // Missing key
  const result2 = await sendCommand('init', {});
  assert(!result2.success, 'missing key is rejected');
}

async function test3_StoreAndVerify() {
  console.log('\n[Test 3] store and verify (ZKP)');

  // Initialize
  await sendCommand('init', { masterKey: 'test-master-key-16chars' });

  // Store
  const storeResult = await sendCommand('store', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(storeResult.success, 'secret stored successfully');
  assert(!storeResult.value, 'stored result does not include value');

  // Verify with correct value
  const verifyOk = await sendCommand('verify', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(verifyOk.valid === true, 'verification succeeds with correct value');
  assert(!verifyOk.value, 'verification result does not include value');

  // Verify with incorrect value
  const verifyFail = await sendCommand('verify', {
    name: 'api_key',
    value: 'wrong-value'
  });
  assert(verifyFail.valid === false, 'verification fails with wrong value');
}

async function test4_ListOnlyNames() {
  console.log('\n[Test 4] list returns names only');

  const listResult = await sendCommand('list');
  assert(listResult.success, 'list succeeds');
  assert(Array.isArray(listResult.secrets), 'returns array');

  for (const secret of listResult.secrets) {
    assert(secret.name !== undefined, 'name is present');
    assert(secret.value === undefined, 'value is not present');
    assert(secret.encrypted === undefined, 'encrypted data is not present');
    assert(secret.hash === undefined, 'hash is not present');
  }
}

async function test5_BruteForceProtection() {
  console.log('\n[Test 5] brute-force protection');

  // Send 10 incorrect attempts
  for (let i = 0; i < 10; i++) {
    await sendCommand('verify', {
      name: 'api_key',
      value: `wrong-attempt-${i}`
    });
  }

  // 11th attempt should be locked out
  const lockedResult = await sendCommand('verify', {
    name: 'api_key',
    value: 'another-attempt'
  });

  assert(!lockedResult.success, 'locked out');
  assert(lockedResult.error.includes('Too many'), 'rate limit error');
}

async function test6_AuditLogging() {
  console.log('\n[Test 6] audit log');

  const auditResult = await sendCommand('audit', { limit: 50 });
  assert(auditResult.success, 'audit log fetch succeeds');
  assert(Array.isArray(auditResult.log), 'returns log array');
  assert(auditResult.log.length > 0, 'log entries recorded');

  // Check log entry structure
  const entry = auditResult.log[0];
  assert(entry.timestamp, 'timestamp exists');
  assert(entry.action, 'action exists');
  assert(entry.success !== undefined, 'success flag exists');
}

async function test7_Persistence() {
  console.log('\n[Test 7] persistence');

  // Restart vault (keep data)
  stopVault();
  await startVault(true); // keepData = true

  // Re-init
  await sendCommand('init', { masterKey: 'test-master-key-16chars' });

  // Ensure previous secrets remain
  const listResult = await sendCommand('list');
  assert(listResult.secrets.some(s => s.name === 'api_key'), 'secrets remain after restart');

  // Verification still works
  const verifyResult = await sendCommand('verify', {
    name: 'api_key',
    value: 'sk-secret12345'
  });
  assert(verifyResult.valid === true, 'verification works after restart');
}

async function test8_ProcessIsolation() {
  console.log('\n[Test 8] process isolation');

  const status = await sendCommand('status');
  assert(status.pid !== process.pid, 'vault runs in a separate process');
  assert(status.pid > 0, 'valid PID');
}

async function test9_DeleteSecret() {
  console.log('\n[Test 9] secret deletion');

  // Add a new secret
  await sendCommand('store', { name: 'to_delete', value: 'temp' });

  // Delete
  const deleteResult = await sendCommand('delete', { name: 'to_delete' });
  assert(deleteResult.success, 'deletion succeeds');

  // Verification should fail
  const verifyResult = await sendCommand('verify', { name: 'to_delete', value: 'temp' });
  assert(!verifyResult.success || !verifyResult.valid, 'verification fails after deletion');
}

async function test10_NoDefaultKey() {
  console.log('\n[Test 10] no default key');

  // Inspect vault.js source
  const vaultSource = fs.readFileSync(VAULT_PROCESS, 'utf8');

  assert(!vaultSource.includes("'default'"), "no hardcoded 'default' key");
  assert(!vaultSource.includes('"default"'), 'no hardcoded "default" key');
}

async function test11_RandomSaltPerSecret() {
  console.log('\n[Test 11] random salt per secret');

  // Inspect vault.js source
  const vaultSource = fs.readFileSync(VAULT_PROCESS, 'utf8');

  assert(!vaultSource.includes("'salt'"), "no hardcoded 'salt'");
  assert(vaultSource.includes('randomBytes(32)'), 'random salt generation exists');
}

// ========== Main ==========

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

  // Cleanup
  try { fs.unlinkSync(VAULT_FILE); } catch {}

  process.exit(failed > 0 ? 1 : 0);
}

main();
