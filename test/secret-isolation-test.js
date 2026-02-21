/**
 * Secret isolation policy tests
 */

const { SecretDetector } = require('../src/security/secret-detector');

const OPENAI_KEY = 'sk-1234567890abcdefghij1234567890abcdefghij12345678';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed += 1;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed += 1;
  }
}

function assertTrue(condition, message) {
  if (!condition) throw new Error(message);
}

async function run() {
  console.log('============================================================');
  console.log('Secret Isolation Tests');
  console.log('============================================================\n');

  await test('stores to isolated endpoint when enabled', async () => {
    const calls = [];
    const detector = new SecretDetector();
    detector
      .setIsolatedStoreClient({
        isConfigured: () => true,
        store: async (payload) => {
          calls.push(payload);
          return { success: true, ref: 'iso-ref-1' };
        }
      })
      .configureIsolation({ enabled: true, enforce: true, allowVaultFallback: false });

    const data = { token: OPENAI_KEY };
    const scan = detector.scanObject(data);
    const result = await detector.autoStore(scan.findings, data, { path: '/type', method: 'POST' });

    assertTrue(result.mode === 'isolated', 'mode should be isolated');
    assertTrue(result.stored === 1, 'stored should be 1');
    assertTrue(calls.length === 1, 'isolated store should be called once');
    assertTrue(calls[0].value === OPENAI_KEY, 'stored value mismatch');
  });

  await test('enforce mode fails closed if isolated endpoint missing', async () => {
    const detector = new SecretDetector();
    detector.configureIsolation({ enabled: true, enforce: true, allowVaultFallback: false });

    const data = { token: OPENAI_KEY };
    const scan = detector.scanObject(data);

    let threw = false;
    try {
      await detector.autoStore(scan.findings, data, { path: '/type', method: 'POST' });
    } catch (e) {
      threw = true;
      assertTrue(e.message.includes('Isolated secret store is not configured'), 'unexpected error');
    }
    assertTrue(threw, 'expected fail-close error');
  });

  await test('falls back to local vault only when explicitly enabled', async () => {
    const stores = [];
    const detector = new SecretDetector();
    detector
      .setVaultClient({
        store: async (name, value) => {
          stores.push({ name, value });
          return { success: true };
        }
      })
      .configureIsolation({ enabled: true, enforce: true, allowVaultFallback: true });

    const data = { token: OPENAI_KEY };
    const scan = detector.scanObject(data);
    const result = await detector.autoStore(scan.findings, data, { path: '/type', method: 'POST' });

    assertTrue(result.mode === 'vault-fallback', 'mode should be vault-fallback');
    assertTrue(result.stored === 1, 'vault fallback should store 1 finding');
    assertTrue(stores.length === 1, 'vault store should be called once');
  });

  await test('enforce mode rejects partial isolated-store failure', async () => {
    const detector = new SecretDetector();
    detector
      .setIsolatedStoreClient({
        isConfigured: () => true,
        store: async () => ({ success: false, error: 'remote unavailable' })
      })
      .configureIsolation({ enabled: true, enforce: true, allowVaultFallback: false });

    const data = { token: OPENAI_KEY };
    const scan = detector.scanObject(data);

    let threw = false;
    try {
      await detector.autoStore(scan.findings, data, { path: '/type', method: 'POST' });
    } catch (e) {
      threw = true;
      assertTrue(e.message.includes('Isolated secret store failed'), 'unexpected enforce failure text');
    }
    assertTrue(threw, 'expected fail-close on isolated-store failure');
  });

  console.log('\n============================================================');
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
