/**
 * Vault Client
 *
 * Client that communicates with the isolated Vault process
 * - Secret values do not pass through this process
 * - No public retrieve() API
 */

const net = require('net');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const DEFAULT_SOCKET_PATH = path.join(os.homedir(), '.sakaki', 'vault.sock');
const SOCKET_PATH = process.env.VAULT_SOCKET || DEFAULT_SOCKET_PATH;
const VAULT_PROCESS = path.join(__dirname, 'vault-process.js');

function ensureSocketDir() {
  const dir = path.dirname(SOCKET_PATH);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch {
    // Ignore errors; socket creation will fail if path is invalid
  }
}

class VaultClient {
  constructor() {
    this.vaultProcess = null;
    this.initialized = false;
  }

  async isSocketAlive() {
    return new Promise((resolve) => {
      const socket = net.createConnection(SOCKET_PATH);
      const timer = setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, 500);
      socket.on('connect', () => {
        clearTimeout(timer);
        socket.end();
        resolve(true);
      });
      socket.on('error', () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
  }

  /**
   * Start the Vault process
   */
  async startVaultProcess() {
    return new Promise(async (resolve, reject) => {
      ensureSocketDir();
      // If socket exists, process is already running
      if (fs.existsSync(SOCKET_PATH)) {
        const alive = await this.isSocketAlive();
        if (alive) {
          console.log('[VaultClient] Vault process already running');
          resolve();
          return;
        }
        try { fs.unlinkSync(SOCKET_PATH); } catch {}
      }

      console.log('[VaultClient] Starting vault process...');

      this.vaultProcess = spawn('node', [VAULT_PROCESS], {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false
      });

      this.vaultProcess.stdout.on('data', (data) => {
        console.log(data.toString().trim());
      });

      this.vaultProcess.stderr.on('data', (data) => {
        console.error(data.toString().trim());
      });

      this.vaultProcess.on('error', (err) => {
        reject(new Error(`Failed to start vault process: ${err.message}`));
      });

      this.vaultProcess.on('exit', (code) => {
        console.log(`[VaultClient] Vault process exited with code ${code}`);
        this.vaultProcess = null;
      });

      // Wait for socket to be created
      const checkSocket = () => {
        if (fs.existsSync(SOCKET_PATH)) {
          resolve();
        } else {
          setTimeout(checkSocket, 100);
        }
      };

      setTimeout(checkSocket, 100);

      // Timeout
      setTimeout(() => {
        reject(new Error('Vault process start timeout'));
      }, 5000);
    });
  }

  /**
   * Send command to Vault process
   */
  async send(command, params = {}) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(SOCKET_PATH);
      let responseBuffer = '';

      socket.on('connect', () => {
        const request = JSON.stringify({ command, params }) + '\n';
        socket.write(request);
      });

      socket.on('data', (data) => {
        responseBuffer += data.toString();

        // Complete when ending with newline
        if (responseBuffer.endsWith('\n')) {
          try {
            const response = JSON.parse(responseBuffer.trim());
            socket.end();
            resolve(response);
          } catch (e) {
            socket.end();
            reject(new Error('Invalid response from vault'));
          }
        }
      });

      socket.on('error', (err) => {
        reject(new Error(`Vault connection error: ${err.message}`));
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Vault connection timeout'));
      });

      socket.setTimeout(5000);
    });
  }

  /**
   * Initialize Vault
   */
  async init(masterKey) {
    if (!masterKey) {
      throw new Error('Master key is required');
    }
    if (masterKey.length < 16) {
      throw new Error('Master key must be at least 16 characters');
    }

    await this.startVaultProcess();
    const result = await this.send('init', { masterKey });

    if (result.success) {
      this.initialized = true;
      console.log(`[VaultClient] Initialized with ${result.secretCount} secrets`);
    }

    return result;
  }

  /**
   * Store a secret
   * Note: value passes through this process but is not retained after sending to Vault process
   */
  async store(name, value) {
    if (!this.initialized) {
      return { success: false, error: 'Vault not initialized' };
    }

    // Send value (encrypted in Vault process)
    const result = await this.send('store', { name, value });

    // Local variable becomes eligible for GC when function ends
    // (No complete guarantee, but reference is not retained)
    return result;
  }

  /**
   * ZKP verification
   * Returns only whether value matches (does not return the value itself)
   */
  async verify(name, value) {
    if (!this.initialized) {
      return { success: false, error: 'Vault not initialized' };
    }

    return await this.send('verify', { name, value });
  }

  /**
   * Secret list (names only)
   */
  async list() {
    if (!this.initialized) {
      return { success: false, error: 'Vault not initialized' };
    }

    return await this.send('list', {});
  }

  /**
   * Delete secret
   */
  async delete(name) {
    if (!this.initialized) {
      return { success: false, error: 'Vault not initialized' };
    }

    return await this.send('delete', { name });
  }

  /**
   * Get audit log
   */
  async getAuditLog(limit = 100) {
    return await this.send('audit', { limit });
  }

  /**
   * Get status
   */
  async getStatus() {
    try {
      return await this.send('status', {});
    } catch (e) {
      return {
        success: false,
        initialized: false,
        error: e.message
      };
    }
  }

  /**
   * Execute browser actions inside Vault process
   */
  async browserExecute(params) {
    return await this.send('browserExecute', params || {});
  }

  /**
   * Stop Vault process
   */
  stop() {
    if (this.vaultProcess) {
      this.vaultProcess.kill('SIGTERM');
      this.vaultProcess = null;
    }
    this.initialized = false;
  }
}

// Singleton instance
const vaultClient = new VaultClient();

// Legacy API compatibility (detectSensitiveData is retained)
const SENSITIVE_PATTERNS = [
  { name: 'API Key', pattern: /api[_-]?key/i },
  { name: 'Secret', pattern: /secret/i },
  { name: 'Password', pattern: /password|passwd|pwd/i },
  { name: 'Token', pattern: /token|bearer/i },
  { name: 'Private Key', pattern: /private[_-]?key|-----BEGIN/i },
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/i },
  { name: 'Credit Card', pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/ },
];

function detectSensitiveData(content) {
  const warnings = [];

  if (typeof content === 'object') {
    content = JSON.stringify(content);
  }

  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    if (pattern.test(content)) {
      warnings.push({
        type: name,
        severity: 'high',
        message: `Potential ${name} detected in content`
      });
    }
  }

  return warnings;
}

module.exports = {
  VaultClient,
  vaultClient,
  detectSensitiveData,
  SENSITIVE_PATTERNS
};
