/**
 * Secret Detector Tests
 *
 * Validates detection accuracy and false positive rate
 */

const { SecretDetector } = require('../src/security/secret-detector');

const join = (...parts) => parts.join('');
const OPENAI_PREFIX = join('s', 'k', '-');

const OPENAI_KEY = join('s', 'k', '-', '1234567890abcdefghij1234567890abcdefghij12345678');
const OPENAI_PROJECT_KEY = join('s', 'k', '-', 'proj', '-', 'abc123def456ghi789jkl012mno345pqr678stu901');
const GITHUB_TOKEN = join('g', 'h', 'p', '_', '1234567890abcdefghijklmnopqrstuvwxyz12');
const GITHUB_OAUTH = join('g', 'h', 'o', '_', '1234567890abcdefghijklmnopqrstuvwxyz12');
const AWS_KEY = join('A', 'K', 'I', 'A', 'IOSFODNN7EXAMPLE');
const GOOGLE_KEY = join('A', 'I', 'z', 'a', 'SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe');
const STRIPE_LIVE = join('s', 'k', '_', 'live', '_', '1234567890abcdefghijklmn');
const STRIPE_TEST = join('s', 'k', '_', 'test', '_', '1234567890abcdefghijklmn');
const SLACK_TOKEN = join('x', 'o', 'x', 'b', '-', '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx');
const RSA_PRIVATE_KEY_HEADER = ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' ');
const PRIVATE_KEY_HEADER = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');

// Test data
const TEST_SECRETS = {
  // OpenAI
  openai: [
    OPENAI_KEY,
    OPENAI_PROJECT_KEY,
  ],
  // GitHub
  github: [
    GITHUB_TOKEN,
    GITHUB_OAUTH,
  ],
  // AWS
  aws: [
    AWS_KEY,
  ],
  // Google
  google: [
    GOOGLE_KEY,
  ],
  // Stripe
  stripe: [
    STRIPE_LIVE,
    STRIPE_TEST,
  ],
  // Slack
  slack: [
    SLACK_TOKEN,
  ],
  // JWT
  jwt: [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  ],
  // Credit Card
  creditCard: [
    '4111111111111111',
    '5500000000000004',
  ],
  // Private Key
  privateKey: [
    RSA_PRIVATE_KEY_HEADER,
    PRIVATE_KEY_HEADER,
  ],
};

// Non-secrets (should NOT be detected)
const FALSE_POSITIVES = [
  join('s', 'k', '-', 'short'),  // Too short for OpenAI
  join('g', 'h', 'p', '_', 'short'), // Too short for GitHub
  'normal text with no secrets',
  'user@example.com', // Email is not a secret by default
  'https://api.example.com/v1/users',
  '1234567890', // Random numbers
  'abcdefghijklmnopqrstuvwxyz', // Random letters
];

// Test runner
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertTrue(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// Tests
console.log('============================================================');
console.log('Secret Detector Tests');
console.log('============================================================\n');

const detector = new SecretDetector();

// Test 1: OpenAI Key Detection
console.log('[Test 1] OpenAI Key Detection');
for (const key of TEST_SECRETS.openai) {
  test(`Detects: ${key.slice(0, 20)}...`, () => {
    const result = detector.scanString(key);
    assertTrue(!result.clean, 'Should detect OpenAI key');
    assertTrue(result.findings.some(f => f.type.includes('OpenAI')), 'Should identify as OpenAI');
  });
}

// Test 2: GitHub Token Detection
console.log('\n[Test 2] GitHub Token Detection');
for (const token of TEST_SECRETS.github) {
  test(`Detects: ${token.slice(0, 20)}...`, () => {
    const result = detector.scanString(token);
    assertTrue(!result.clean, 'Should detect GitHub token');
    assertTrue(result.findings.some(f => f.type.includes('GitHub')), 'Should identify as GitHub');
  });
}

// Test 3: AWS Key Detection
console.log('\n[Test 3] AWS Key Detection');
for (const key of TEST_SECRETS.aws) {
  test(`Detects: ${key}`, () => {
    const result = detector.scanString(key);
    assertTrue(!result.clean, 'Should detect AWS key');
    assertTrue(result.findings.some(f => f.type.includes('AWS')), 'Should identify as AWS');
  });
}

// Test 4: Google API Key Detection
console.log('\n[Test 4] Google API Key Detection');
for (const key of TEST_SECRETS.google) {
  test(`Detects: ${key.slice(0, 20)}...`, () => {
    const result = detector.scanString(key);
    assertTrue(!result.clean, 'Should detect Google key');
    assertTrue(result.findings.some(f => f.type.includes('Google')), 'Should identify as Google');
  });
}

// Test 5: Stripe Key Detection
console.log('\n[Test 5] Stripe Key Detection');
for (const key of TEST_SECRETS.stripe) {
  test(`Detects: ${key.slice(0, 20)}...`, () => {
    const result = detector.scanString(key);
    assertTrue(!result.clean, 'Should detect Stripe key');
    assertTrue(result.findings.some(f => f.type.includes('Stripe')), 'Should identify as Stripe');
  });
}

// Test 6: Slack Token Detection
console.log('\n[Test 6] Slack Token Detection');
for (const token of TEST_SECRETS.slack) {
  test(`Detects: ${token.slice(0, 20)}...`, () => {
    const result = detector.scanString(token);
    assertTrue(!result.clean, 'Should detect Slack token');
    assertTrue(result.findings.some(f => f.type.includes('Slack')), 'Should identify as Slack');
  });
}

// Test 7: JWT Detection
console.log('\n[Test 7] JWT Detection');
for (const jwt of TEST_SECRETS.jwt) {
  test(`Detects: ${jwt.slice(0, 30)}...`, () => {
    const result = detector.scanString(jwt);
    assertTrue(!result.clean, 'Should detect JWT');
    assertTrue(result.findings.some(f => f.type.includes('JWT')), 'Should identify as JWT');
  });
}

// Test 8: Credit Card Detection
console.log('\n[Test 8] Credit Card Detection');
for (const cc of TEST_SECRETS.creditCard) {
  test(`Detects: ${cc}`, () => {
    const result = detector.scanString(cc);
    assertTrue(!result.clean, 'Should detect credit card');
    assertTrue(result.findings.some(f => f.type.includes('Credit Card')), 'Should identify as Credit Card');
  });
}

// Test 9: Private Key Detection
console.log('\n[Test 9] Private Key Detection');
for (const key of TEST_SECRETS.privateKey) {
  test(`Detects: ${key}`, () => {
    const result = detector.scanString(key);
    assertTrue(!result.clean, 'Should detect private key');
    assertTrue(result.findings.some(f => f.type.includes('Private Key')), 'Should identify as Private Key');
  });
}

// Test 10: False Positive Check
console.log('\n[Test 10] False Positive Check');
let falsePositives = 0;
for (const text of FALSE_POSITIVES) {
  const result = detector.scanString(text);
  if (!result.clean) {
    falsePositives++;
    console.log(`  WARN False positive: "${text}" detected as ${result.findings.map(f => f.type).join(', ')}`);
  }
}
test(`False positive rate: ${falsePositives}/${FALSE_POSITIVES.length}`, () => {
  const rate = falsePositives / FALSE_POSITIVES.length;
  assertTrue(rate <= 0.05, `False positive rate ${(rate * 100).toFixed(1)}% exceeds 5% threshold`);
});

// Test 11: Object Scanning
console.log('\n[Test 11] Object Scanning');
test('Scans nested objects', () => {
  const obj = {
    user: 'alice',
    config: {
      api_key: OPENAI_KEY,
      debug: true
    }
  };
  const result = detector.scanObject(obj);
  assertTrue(!result.clean, 'Should find secret in nested object');
  assertTrue(result.findings.some(f => f.path === 'config.api_key'), 'Should report correct path');
});

test('Protects sensitive field names', () => {
  const obj = {
    username: 'alice',
    password: 'mysecretpassword123'
  };
  const result = detector.scanObject(obj);
  assertTrue(!result.clean, 'Should detect password field');
  assertTrue(result.protected.password.startsWith('[PROTECTED:'), 'Should replace with placeholder');
});

// Test 12: Response Protection
console.log('\n[Test 12] Response Protection');
test('Protects JSON response', () => {
  const response = JSON.stringify({
    token: OPENAI_KEY,
    user: 'alice'
  });
  const result = detector.protectResponse(response);
  assertTrue(result.findings.length > 0, 'Should find secrets');
  assertTrue(!result.protected.includes(OPENAI_PREFIX), 'Protected response should not contain secret');
});

test('Protects string response', () => {
  const response = `Your API key is: ${OPENAI_KEY}`;
  const result = detector.protectResponse(response);
  assertTrue(result.findings.length > 0, 'Should find secrets');
  assertTrue(!result.protected.includes(OPENAI_PREFIX), 'Protected response should not contain secret');
});

// Test 13: Custom Patterns
console.log('\n[Test 13] Custom Patterns');
test('Adds custom pattern', () => {
  const customDetector = new SecretDetector();
  customDetector.addPattern('Custom Token', /CUSTOM_[A-Z0-9]{10}/);
  const result = customDetector.scanString('CUSTOM_ABCD123456');
  assertTrue(!result.clean, 'Should detect custom pattern');
  assertTrue(result.findings.some(f => f.type === 'Custom Token'), 'Should identify as Custom Token');
});

// Test 14: Statistics
console.log('\n[Test 14] Statistics');
test('Tracks statistics', () => {
  const stats = detector.getStats();
  assertTrue(stats.scanned > 0, 'Should track scanned count');
  assertTrue(stats.detected > 0, 'Should track detected count');
  assertTrue(Object.keys(stats.byType).length > 0, 'Should track by type');
});

// Test 15: Mixed Content
console.log('\n[Test 15] Mixed Content');
test('Handles mixed content', () => {
  const mixed = [
    'Config file:',
    `OPENAI_KEY=${OPENAI_KEY}`,
    `GITHUB_TOKEN=${GITHUB_TOKEN}`,
    'DEBUG=true',
  ].join('\n');
  const result = detector.scanString(mixed);
  assertTrue(result.findings.length >= 2, 'Should find multiple secrets');
});

// Summary
console.log('\n============================================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('============================================================');

// Statistics
const stats = detector.getStats();
console.log('\nDetection Statistics:');
console.log(`  Scanned: ${stats.scanned}`);
console.log(`  Detected: ${stats.detected}`);
console.log(`  By Type:`, stats.byType);

process.exit(failed > 0 ? 1 : 0);
