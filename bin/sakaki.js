#!/usr/bin/env node
/**
 * Sakaki Browser CLI
 *
 * Command-line interface for Sakaki Browser operations
 */

const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const BASE_URL = process.env.SAKAKI_URL || 'http://localhost:18800';

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m'
};

function success(msg) {
  console.log(`${colors.green}✓${colors.reset} ${msg}`);
}

function error(msg) {
  console.log(`${colors.red}✗${colors.reset} ${msg}`);
}

function info(msg) {
  console.log(`${colors.cyan}→${colors.reset} ${msg}`);
}

/**
 * Make HTTP request to Sakaki server
 */
async function request(method, endpoint, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, BASE_URL);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });

    req.on('error', (e) => {
      reject(new Error(`Connection failed: ${e.message}. Is the server running?`));
    });

    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Check if server is running
 */
async function checkServer() {
  try {
    await request('GET', '/health');
    return true;
  } catch {
    return false;
  }
}

/**
 * Commands
 */
const commands = {
  // Server commands
  async start() {
    const running = await checkServer();
    if (running) {
      info('Server is already running');
      return;
    }

    const serverPath = path.join(__dirname, '..', 'src', 'index.js');
    const child = spawn('node', [serverPath], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();

    info('Starting server...');

    // Wait for server to be ready
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 500));
      if (await checkServer()) {
        success('Server started on http://localhost:18800');
        return;
      }
    }
    error('Server failed to start');
  },

  async stop() {
    try {
      const { exec } = require('child_process');
      exec('pkill -f "node.*sakaki-browser.*index.js"');
      success('Server stopped');
    } catch {
      error('Failed to stop server');
    }
  },

  async status() {
    try {
      const { data } = await request('GET', '/health');
      success('Server is running');
      console.log(`  Browser: ${data.browser ? 'Ready' : 'Not ready'}`);
      console.log(`  Security: Rate limiter ${data.security?.rateLimiter || 'unknown'}`);
    } catch {
      error('Server is not running');
      console.log(`  Run: ${colors.cyan}sakaki start${colors.reset}`);
    }
  },

  // Vault commands
  async 'vault init'(masterKey) {
    if (!masterKey) {
      error('Usage: sakaki vault init <masterKey>');
      console.log('  Master key must be at least 16 characters');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/init', { masterKey });
      if (data.success) {
        success(`Vault initialized (${data.secretCount} secrets loaded)`);
      } else {
        error(data.error || 'Failed to initialize vault');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault store'(name, value) {
    if (!name || !value) {
      error('Usage: sakaki vault store <name> <value>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/store', { name, value });
      if (data.success) {
        success(`Secret "${name}" stored`);
      } else {
        error(data.error || 'Failed to store secret');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault list'() {
    try {
      const { data } = await request('GET', '/vault/list');
      if (data.success) {
        if (data.secrets.length === 0) {
          info('No secrets stored');
        } else {
          console.log(`\n${colors.cyan}Secrets:${colors.reset}`);
          for (const secret of data.secrets) {
            console.log(`  • ${secret.name} ${colors.dim}(${new Date(secret.createdAt).toLocaleDateString()})${colors.reset}`);
          }
          console.log();
        }
      } else {
        error(data.error || 'Failed to list secrets');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault verify'(name, value) {
    if (!name || !value) {
      error('Usage: sakaki vault verify <name> <value>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/verify', { name, value });
      if (data.success) {
        if (data.valid) {
          success('Value matches');
        } else {
          error('Value does not match');
        }
      } else {
        error(data.error || 'Verification failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'vault delete'(name) {
    if (!name) {
      error('Usage: sakaki vault delete <name>');
      return;
    }

    try {
      const { data } = await request('POST', '/vault/delete', { name });
      if (data.success) {
        success(`Secret "${name}" deleted`);
      } else {
        error(data.error || 'Failed to delete secret');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Browser commands
  async navigate(url) {
    if (!url) {
      error('Usage: sakaki navigate <url>');
      return;
    }

    try {
      const { data } = await request('POST', '/navigate', { url });
      if (data.success) {
        success(`Navigated to: ${data.title}`);
        console.log(`  URL: ${data.url}`);
        console.log(`  Risk: ${data.risk}`);
        if (data.phishingScore > 0) {
          console.log(`  ${colors.yellow}Phishing Score: ${data.phishingScore}${colors.reset}`);
        }
      } else {
        error(data.error || 'Navigation failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async click(selector) {
    if (!selector) {
      error('Usage: sakaki click <selector or description>');
      return;
    }

    try {
      const { data } = await request('POST', '/click', { selector });
      if (data.success) {
        success(`Clicked: ${selector}`);
      } else {
        error(data.error || 'Click failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async type(selector, text) {
    if (!selector || !text) {
      error('Usage: sakaki type <selector> <text>');
      return;
    }

    try {
      const { data } = await request('POST', '/type', { selector, text });
      if (data.success) {
        success(`Typed into: ${selector}`);
      } else {
        error(data.error || 'Type failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async 'type-secret'(selector, secretName) {
    if (!selector || !secretName) {
      error('Usage: sakaki type-secret <selector> <secretName>');
      console.log('  Types a secret from vault without exposing its value');
      return;
    }

    try {
      const { data } = await request('POST', '/type-secret', { selector, secretName });
      if (data.success) {
        success(`Typed secret "${secretName}" into: ${selector}`);
        console.log(`  ${colors.dim}(value never exposed)${colors.reset}`);
      } else {
        error(data.error || 'Type secret failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  async screenshot(outputPath) {
    const output = outputPath || `screenshot-${Date.now()}.png`;

    try {
      const { data } = await request('POST', '/screenshot', { path: path.resolve(output) });
      if (data.success || data.path) {
        success(`Screenshot saved: ${data.path || output}`);
      } else {
        error(data.error || 'Screenshot failed');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Audit
  async audit(limit = 20) {
    try {
      const { data } = await request('GET', `/audit-log?limit=${limit}`);
      if (Array.isArray(data)) {
        if (data.length === 0) {
          info('No audit logs');
          return;
        }
        console.log(`\n${colors.cyan}Audit Log:${colors.reset}`);
        for (const entry of data.slice(-limit)) {
          const time = new Date(entry.timestamp).toLocaleTimeString();
          const status = entry.blocked ? colors.red + 'BLOCKED' : colors.green + 'OK';
          console.log(`  ${colors.dim}${time}${colors.reset} ${entry.action} ${status}${colors.reset}`);
        }
        console.log();
      } else {
        error('Failed to get audit log');
      }
    } catch (e) {
      error(e.message);
    }
  },

  // Help
  help() {
    console.log(`
${colors.cyan}Sakaki Browser CLI${colors.reset}

${colors.yellow}Server:${colors.reset}
  sakaki start              Start the server
  sakaki stop               Stop the server
  sakaki status             Check server status

${colors.yellow}Vault:${colors.reset}
  sakaki vault init <key>   Initialize vault with master key (16+ chars)
  sakaki vault store <n> <v> Store a secret
  sakaki vault list         List all secrets (names only)
  sakaki vault verify <n> <v> Verify a secret value (ZKP)
  sakaki vault delete <n>   Delete a secret

${colors.yellow}Browser:${colors.reset}
  sakaki navigate <url>     Navigate to URL
  sakaki click <selector>   Click element (CSS or semantic)
  sakaki type <sel> <text>  Type text into element
  sakaki type-secret <sel> <name>  Type secret from vault (safe)
  sakaki screenshot [path]  Take screenshot

${colors.yellow}Other:${colors.reset}
  sakaki audit [limit]      View audit log
  sakaki help               Show this help

${colors.dim}Environment:${colors.reset}
  SAKAKI_URL    Server URL (default: http://localhost:18800)
`);
  }
};

// Parse arguments and run
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    commands.help();
    return;
  }

  // Handle compound commands (vault init, vault store, etc.)
  const cmd1 = args[0];
  const cmd2 = args[1];
  const compound = `${cmd1} ${cmd2}`;

  if (commands[compound]) {
    await commands[compound](...args.slice(2));
  } else if (commands[cmd1]) {
    await commands[cmd1](...args.slice(1));
  } else {
    error(`Unknown command: ${cmd1}`);
    console.log(`Run ${colors.cyan}sakaki help${colors.reset} for usage`);
  }
}

main().catch(e => {
  error(e.message);
  process.exit(1);
});
