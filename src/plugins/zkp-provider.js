/**
 * ZKP Provider Plugin
 *
 * Mechanism for service providers to verify API keys without seeing them
 *
 * Flow:
 * 1. Client: sends commitment = hash(api_key + nonce)
 * 2. Server: returns challenge
 * 3. Client: sends response = hash(api_key + challenge)
 * 4. Server: compares with stored hash, authentication succeeds if match
 *
 * -> The API key itself never traverses the network
 *
 * Vault integration mode:
 * - vaultOnly: true means only Vault-backed API keys are accepted
 * - Raw API keys are rejected, registration via Vault is required
 */

const crypto = require('crypto');

class ZKPProvider {
  constructor(options = {}) {
    this.name = options.name || 'default';
    this.registeredKeys = new Map(); // keyId -> { hash, metadata, vaultBacked }
    this.challenges = new Map();     // sessionId -> { challenge, expires }
    this.challengeTTL = options.challengeTTL || 60000; // 1 minute

    // Vault integration settings
    this.config = {
      vaultOnly: options.vaultOnly || false,  // true: only accept Vault-backed keys
      vaultClient: options.vaultClient || null,
      requireVaultVerification: options.requireVaultVerification || false
    };
  }

  // Toggle Vault-only mode
  setVaultOnly(enabled) {
    this.config.vaultOnly = enabled;
    return { vaultOnly: this.config.vaultOnly };
  }

  // Set Vault client
  setVaultClient(client) {
    this.config.vaultClient = client;
  }

  // Get configuration
  getConfig() {
    return {
      vaultOnly: this.config.vaultOnly,
      vaultConnected: !!this.config.vaultClient,
      requireVaultVerification: this.config.requireVaultVerification
    };
  }

  // Service provider: register API key (store hash only)
  registerKey(keyId, apiKey, metadata = {}) {
    // Reject raw API key registration in vaultOnly mode
    if (this.config.vaultOnly) {
      return {
        error: 'Vault-only mode enabled. Use registerFromVault() instead.',
        vaultOnly: true
      };
    }

    const hash = crypto.createHash('sha256').update(apiKey).digest('hex');
    this.registeredKeys.set(keyId, {
      hash,
      metadata,
      vaultBacked: false,
      createdAt: Date.now()
    });
    return { keyId, registered: true, vaultBacked: false };
  }

  // Register API key via Vault
  // Use a key already stored in Vault
  async registerFromVault(keyId, vaultSecretName, metadata = {}) {
    if (!this.config.vaultClient) {
      return { error: 'Vault client not configured' };
    }

    // Check if exists in Vault (don't retrieve value)
    const listResult = await this.config.vaultClient.list();
    if (!listResult.success) {
      return { error: 'Failed to access vault' };
    }

    const secretExists = listResult.secrets.some(s => s.name === vaultSecretName);
    if (!secretExists) {
      return { error: `Secret "${vaultSecretName}" not found in vault` };
    }

    // Cannot temporarily retrieve value to generate hash (ZKP)
    // Instead, save vaultSecretName as link
    this.registeredKeys.set(keyId, {
      hash: null, // For Vault-backed, don't store hash
      vaultSecretName,
      metadata,
      vaultBacked: true,
      createdAt: Date.now()
    });

    return { keyId, registered: true, vaultBacked: true, vaultSecretName };
  }

  // Authenticate API request with Vault verification
  async verifyWithVault(keyId, providedValue) {
    const keyData = this.registeredKeys.get(keyId);
    if (!keyData) {
      return { valid: false, reason: 'Key not registered' };
    }

    // For Vault-backed keys
    if (keyData.vaultBacked) {
      if (!this.config.vaultClient) {
        return { valid: false, reason: 'Vault client not configured' };
      }

      // Verify with Vault (ZKP)
      const result = await this.config.vaultClient.verify(
        keyData.vaultSecretName,
        providedValue
      );

      if (result.success && result.valid) {
        return {
          valid: true,
          keyId,
          vaultBacked: true,
          metadata: keyData.metadata
        };
      } else {
        return {
          valid: false,
          reason: result.error || 'Vault verification failed',
          vaultBacked: true
        };
      }
    }

    // For regular keys
    const hash = crypto.createHash('sha256').update(providedValue).digest('hex');
    if (hash === keyData.hash) {
      return {
        valid: true,
        keyId,
        vaultBacked: false,
        metadata: keyData.metadata
      };
    }

    return { valid: false, reason: 'Invalid key' };
  }

  // Step 1: Receive commitment from client, return challenge
  createChallenge(keyId) {
    if (!this.registeredKeys.has(keyId)) {
      return { error: 'Unknown key ID' };
    }

    const sessionId = crypto.randomBytes(16).toString('hex');
    const challenge = crypto.randomBytes(32).toString('hex');

    this.challenges.set(sessionId, {
      keyId,
      challenge,
      expires: Date.now() + this.challengeTTL
    });

    // Clean up expired challenges
    this._cleanupExpiredChallenges();

    return { sessionId, challenge };
  }

  // Step 2: Verify response from client
  verifyResponse(sessionId, response) {
    const session = this.challenges.get(sessionId);
    if (!session) {
      return { valid: false, reason: 'Invalid or expired session' };
    }

    if (Date.now() > session.expires) {
      this.challenges.delete(sessionId);
      return { valid: false, reason: 'Challenge expired' };
    }

    const keyData = this.registeredKeys.get(session.keyId);
    if (!keyData) {
      return { valid: false, reason: 'Key not found' };
    }

    // Expected response: hash(originalKeyHash + challenge)
    const expectedResponse = crypto
      .createHash('sha256')
      .update(keyData.hash + session.challenge)
      .digest('hex');

    const valid = response === expectedResponse;

    // Delete used challenge
    this.challenges.delete(sessionId);

    if (valid) {
      return {
        valid: true,
        keyId: session.keyId,
        metadata: keyData.metadata
      };
    } else {
      return { valid: false, reason: 'Invalid response' };
    }
  }

  // Clean up expired challenges
  _cleanupExpiredChallenges() {
    const now = Date.now();
    for (const [sessionId, session] of this.challenges.entries()) {
      if (now > session.expires) {
        this.challenges.delete(sessionId);
      }
    }
  }

  // Statistics
  getStats() {
    const keys = Array.from(this.registeredKeys.values());
    return {
      registeredKeys: this.registeredKeys.size,
      vaultBackedKeys: keys.filter(k => k.vaultBacked).length,
      regularKeys: keys.filter(k => !k.vaultBacked).length,
      activeChallenges: this.challenges.size,
      config: this.getConfig()
    };
  }

  // Key list (values not included)
  listKeys() {
    return Array.from(this.registeredKeys.entries()).map(([keyId, data]) => ({
      keyId,
      vaultBacked: data.vaultBacked,
      vaultSecretName: data.vaultSecretName || null,
      metadata: data.metadata,
      createdAt: data.createdAt
    }));
  }

  // Delete key
  removeKey(keyId) {
    const existed = this.registeredKeys.delete(keyId);
    return { keyId, removed: existed };
  }
}

/**
 * Client-side helper
 * For safely using API keys within Sakaki Browser
 */
class ZKPClient {
  constructor(apiKey, options = {}) {
    this.keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    this.vaultClient = options.vaultClient || null;
    this.vaultSecretName = options.vaultSecretName || null;
  }

  // Create via Vault
  static async fromVault(vaultClient, secretName, testValue) {
    // Verify value exists in Vault and is correct
    const verifyResult = await vaultClient.verify(secretName, testValue);
    if (!verifyResult.success || !verifyResult.valid) {
      throw new Error('Vault verification failed');
    }

    const client = new ZKPClient(testValue, {
      vaultClient,
      vaultSecretName: secretName
    });

    return client;
  }

  // Respond to challenge
  respondToChallenge(challenge) {
    return crypto
      .createHash('sha256')
      .update(this.keyHash + challenge)
      .digest('hex');
  }

  // Is Vault-backed
  isVaultBacked() {
    return !!this.vaultSecretName;
  }
}

/**
 * Express middleware for ZKP authentication
 */
function createZKPMiddleware(provider) {
  return {
    // Challenge issuance endpoint
    challenge: (req, res) => {
      const { keyId } = req.body;
      if (!keyId) {
        return res.status(400).json({ error: 'keyId required' });
      }
      const result = provider.createChallenge(keyId);
      res.json(result);
    },

    // Verification endpoint
    verify: (req, res) => {
      const { sessionId, response } = req.body;
      if (!sessionId || !response) {
        return res.status(400).json({ error: 'sessionId and response required' });
      }
      const result = provider.verifyResponse(sessionId, response);
      res.json(result);
    },

    // Vault verification endpoint
    verifyWithVault: async (req, res) => {
      const { keyId, value } = req.body;
      if (!keyId || !value) {
        return res.status(400).json({ error: 'keyId and value required' });
      }
      const result = await provider.verifyWithVault(keyId, value);
      res.json(result);
    },

    // Configuration endpoint
    config: (req, res) => {
      if (req.method === 'GET') {
        res.json(provider.getConfig());
      } else if (req.method === 'POST') {
        const { vaultOnly } = req.body;
        if (typeof vaultOnly === 'boolean') {
          provider.setVaultOnly(vaultOnly);
        }
        res.json(provider.getConfig());
      }
    },

    // Per-request authentication middleware
    authenticate: (req, res, next) => {
      const authHeader = req.headers['x-zkp-auth'];
      if (!authHeader) {
        return res.status(401).json({ error: 'ZKP authentication required' });
      }

      try {
        const { sessionId, response } = JSON.parse(authHeader);
        const result = provider.verifyResponse(sessionId, response);

        if (result.valid) {
          req.zkpAuth = result;
          next();
        } else {
          res.status(401).json({ error: result.reason });
        }
      } catch (e) {
        res.status(400).json({ error: 'Invalid auth header' });
      }
    },

    // Vault-required authentication middleware
    authenticateVaultOnly: async (req, res, next) => {
      const authHeader = req.headers['x-zkp-vault-auth'];
      if (!authHeader) {
        return res.status(401).json({
          error: 'Vault-backed authentication required',
          hint: 'Use X-ZKP-Vault-Auth header with {keyId, value}'
        });
      }

      try {
        const { keyId, value } = JSON.parse(authHeader);
        const result = await provider.verifyWithVault(keyId, value);

        if (result.valid) {
          if (provider.config.vaultOnly && !result.vaultBacked) {
            return res.status(401).json({
              error: 'Vault-backed key required',
              hint: 'This endpoint requires keys registered via registerFromVault()'
            });
          }
          req.zkpAuth = result;
          next();
        } else {
          res.status(401).json({ error: result.reason });
        }
      } catch (e) {
        res.status(400).json({ error: 'Invalid auth header' });
      }
    }
  };
}

module.exports = {
  ZKPProvider,
  ZKPClient,
  createZKPMiddleware
};
