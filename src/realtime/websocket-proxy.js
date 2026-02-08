/**
 * WebSocket Proxy
 *
 * Secure WebSocket connections via Vault
 * - Auth credentials injected from Vault
 * - All messages audit logged
 * - Connection multiplexing
 */

const WebSocket = require('ws');
const crypto = require('crypto');

class WebSocketProxy {
  constructor(options = {}) {
    this.vaultClient = options.vaultClient || null;
    this.connections = new Map(); // connectionId -> { ws, target, created }
    this.messageHandlers = new Map(); // connectionId -> [handlers]

    // Statistics
    this.stats = {
      totalConnections: 0,
      activeConnections: 0,
      messagesSent: 0,
      messagesReceived: 0,
      errors: 0
    };

    // Audit log
    this.auditLog = [];
  }

  /**
   * Record audit log
   */
  _audit(action, connectionId, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      connectionId,
      ...details
    };
    this.auditLog.push(entry);
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Create WebSocket connection
   */
  async connect(url, options = {}) {
    const connectionId = crypto.randomBytes(8).toString('hex');

    // Build headers
    const headers = { ...(options.headers || {}) };

    // Inject auth credentials via Vault
    if (options.authFromVault && this.vaultClient) {
      const { secretName, injectAs } = options.authFromVault;

      // Request Vault process to inject auth
      // Note: For WebSocket, can only inject into connection headers
      try {
        const result = await this.vaultClient.send('getAuthHeader', {
          secretName,
          injectAs
        });

        if (result.success && result.header) {
          const [headerName, headerValue] = result.header.split(': ');
          headers[headerName] = headerValue;
        }
      } catch (e) {
        // Skip if Vault not supported
        console.warn('[WSProxy] Vault auth injection not available');
      }
    }

    return new Promise((resolve, reject) => {
      try {
        const ws = new WebSocket(url, {
          headers,
          handshakeTimeout: options.timeout || 10000
        });

        ws.on('open', () => {
          this.stats.totalConnections++;
          this.stats.activeConnections++;

          this.connections.set(connectionId, {
            ws,
            target: url,
            created: Date.now(),
            messagesIn: 0,
            messagesOut: 0
          });

          this._audit('CONNECT', connectionId, { url });

          resolve({
            success: true,
            connectionId,
            url
          });
        });

        ws.on('message', (data) => {
          const conn = this.connections.get(connectionId);
          if (conn) {
            conn.messagesIn++;
            this.stats.messagesReceived++;
          }

          // Notify registered handlers
          const handlers = this.messageHandlers.get(connectionId) || [];
          for (const handler of handlers) {
            try {
              handler(data.toString(), connectionId);
            } catch (e) {
              console.error('[WSProxy] Handler error:', e);
            }
          }

          this._audit('MESSAGE_IN', connectionId, {
            size: data.length
          });
        });

        ws.on('close', (code, reason) => {
          this.stats.activeConnections--;
          this.connections.delete(connectionId);
          this.messageHandlers.delete(connectionId);

          this._audit('DISCONNECT', connectionId, {
            code,
            reason: reason?.toString()
          });
        });

        ws.on('error', (err) => {
          this.stats.errors++;
          this._audit('ERROR', connectionId, { error: err.message });
        });

        // Timeout
        setTimeout(() => {
          if (ws.readyState === WebSocket.CONNECTING) {
            ws.terminate();
            reject(new Error('Connection timeout'));
          }
        }, options.timeout || 10000);

      } catch (e) {
        this.stats.errors++;
        reject(e);
      }
    });
  }

  /**
   * Send message
   */
  send(connectionId, message) {
    const conn = this.connections.get(connectionId);
    if (!conn) {
      return { success: false, error: 'Connection not found' };
    }

    if (conn.ws.readyState !== WebSocket.OPEN) {
      return { success: false, error: 'Connection not open' };
    }

    try {
      const data = typeof message === 'object' ? JSON.stringify(message) : message;
      conn.ws.send(data);

      conn.messagesOut++;
      this.stats.messagesSent++;

      this._audit('MESSAGE_OUT', connectionId, { size: data.length });

      return { success: true };
    } catch (e) {
      this.stats.errors++;
      return { success: false, error: e.message };
    }
  }

  /**
   * Register message handler
   */
  onMessage(connectionId, handler) {
    if (!this.messageHandlers.has(connectionId)) {
      this.messageHandlers.set(connectionId, []);
    }
    this.messageHandlers.get(connectionId).push(handler);
  }

  /**
   * Close connection
   */
  close(connectionId) {
    const conn = this.connections.get(connectionId);
    if (!conn) {
      return { success: false, error: 'Connection not found' };
    }

    conn.ws.close();
    this.connections.delete(connectionId);
    this.messageHandlers.delete(connectionId);

    return { success: true };
  }

  /**
   * Close all connections
   */
  closeAll() {
    for (const [id, conn] of this.connections) {
      conn.ws.close();
    }
    this.connections.clear();
    this.messageHandlers.clear();
  }

  /**
   * Get connection info
   */
  getConnection(connectionId) {
    const conn = this.connections.get(connectionId);
    if (!conn) return null;

    return {
      connectionId,
      target: conn.target,
      created: conn.created,
      uptime: Date.now() - conn.created,
      messagesIn: conn.messagesIn,
      messagesOut: conn.messagesOut,
      readyState: conn.ws.readyState
    };
  }

  /**
   * List all connections
   */
  listConnections() {
    return Array.from(this.connections.keys()).map(id => this.getConnection(id));
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      connections: this.listConnections()
    };
  }

  /**
   * Get audit log
   */
  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }
}

// Singleton
const wsProxy = new WebSocketProxy();

module.exports = { WebSocketProxy, wsProxy };
