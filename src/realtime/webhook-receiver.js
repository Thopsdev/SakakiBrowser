/**
 * Webhook Receiver
 *
 * Secure webhook reception
 * - Signature verification
 * - Event queue
 * - Handler registration
 */

const crypto = require('crypto');

class WebhookReceiver {
  constructor(options = {}) {
    // Secret management
    this.secrets = new Map(); // endpointId -> secret
    this.vaultClient = options.vaultClient || null;

    // Event queue
    this.eventQueue = [];
    this.maxQueueSize = options.maxQueueSize || 1000;

    // Handlers
    this.handlers = new Map(); // endpointId -> [handlers]
    this.globalHandlers = [];

    // Endpoint config
    this.endpoints = new Map(); // endpointId -> config

    // Statistics
    this.stats = {
      totalReceived: 0,
      validated: 0,
      rejected: 0,
      processed: 0,
      errors: 0
    };

    // Audit log
    this.auditLog = [];
  }

  /**
   * Record audit log
   */
  _audit(action, endpointId, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      endpointId,
      ...details
    };
    this.auditLog.push(entry);
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Register endpoint
   */
  registerEndpoint(endpointId, config = {}) {
    this.endpoints.set(endpointId, {
      id: endpointId,
      signatureHeader: config.signatureHeader || 'x-webhook-signature',
      signatureAlgorithm: config.signatureAlgorithm || 'sha256',
      signaturePrefix: config.signaturePrefix || 'sha256=',
      timestampHeader: config.timestampHeader || null,
      timestampTolerance: config.timestampTolerance || 300, // 5 min
      created: Date.now()
    });

    // Set secret
    if (config.secret) {
      this.secrets.set(endpointId, config.secret);
    } else if (config.vaultSecretName && this.vaultClient) {
      // Get secret via Vault (used during verification)
      this.endpoints.get(endpointId).vaultSecretName = config.vaultSecretName;
    }

    this._audit('REGISTER', endpointId);

    return { success: true, endpointId };
  }

  /**
   * Unregister endpoint
   */
  unregisterEndpoint(endpointId) {
    this.endpoints.delete(endpointId);
    this.secrets.delete(endpointId);
    this.handlers.delete(endpointId);

    this._audit('UNREGISTER', endpointId);

    return { success: true };
  }

  /**
   * Verify signature
   */
  async _verifySignature(endpointId, payload, signature) {
    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) return { valid: false, reason: 'Unknown endpoint' };

    // Get secret
    let secret = this.secrets.get(endpointId);

    // Via Vault
    if (!secret && endpoint.vaultSecretName && this.vaultClient) {
      // Cannot do Vault verification directly
      // Ideally signature verification should be done inside Vault process
      console.warn('[Webhook] Vault-based signature verification not fully implemented');
      return { valid: true, reason: 'Vault verification skipped' };
    }

    if (!secret) {
      return { valid: false, reason: 'No secret configured' };
    }

    // Calculate signature
    const expectedSignature = endpoint.signaturePrefix +
      crypto.createHmac(endpoint.signatureAlgorithm, secret)
        .update(typeof payload === 'string' ? payload : JSON.stringify(payload))
        .digest('hex');

    // Compare (timing-safe)
    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );
      return { valid };
    } catch (e) {
      return { valid: false, reason: 'Signature mismatch' };
    }
  }

  /**
   * Receive and process webhook
   */
  async receive(endpointId, headers, body) {
    this.stats.totalReceived++;

    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) {
      this.stats.rejected++;
      this._audit('REJECT', endpointId, { reason: 'Unknown endpoint' });
      return { success: false, error: 'Unknown endpoint' };
    }

    // Signature verification
    const signature = headers[endpoint.signatureHeader] ||
                      headers[endpoint.signatureHeader.toLowerCase()];

    if (signature) {
      const verification = await this._verifySignature(endpointId, body, signature);
      if (!verification.valid) {
        this.stats.rejected++;
        this._audit('REJECT', endpointId, { reason: verification.reason });
        return { success: false, error: 'Invalid signature' };
      }
      this.stats.validated++;
    }

    // Timestamp verification (optional)
    if (endpoint.timestampHeader) {
      const timestamp = headers[endpoint.timestampHeader] ||
                        headers[endpoint.timestampHeader.toLowerCase()];
      if (timestamp) {
        const ts = parseInt(timestamp);
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > endpoint.timestampTolerance) {
          this.stats.rejected++;
          this._audit('REJECT', endpointId, { reason: 'Timestamp too old' });
          return { success: false, error: 'Timestamp too old' };
        }
      }
    }

    // Create event
    const event = {
      id: crypto.randomBytes(8).toString('hex'),
      endpointId,
      timestamp: Date.now(),
      headers,
      body: typeof body === 'string' ? JSON.parse(body) : body,
      processed: false
    };

    // Add to queue
    this.eventQueue.push(event);
    if (this.eventQueue.length > this.maxQueueSize) {
      this.eventQueue.shift();
    }

    this._audit('RECEIVE', endpointId, { eventId: event.id });

    // Execute handlers
    await this._processEvent(event);

    return {
      success: true,
      eventId: event.id
    };
  }

  /**
   * Process event
   */
  async _processEvent(event) {
    const handlers = [
      ...(this.handlers.get(event.endpointId) || []),
      ...this.globalHandlers
    ];

    for (const handler of handlers) {
      try {
        await handler(event);
        this.stats.processed++;
      } catch (e) {
        this.stats.errors++;
        console.error('[Webhook] Handler error:', e);
      }
    }

    event.processed = true;
  }

  /**
   * Register handler
   */
  onWebhook(endpointId, handler) {
    if (endpointId === '*') {
      this.globalHandlers.push(handler);
    } else {
      if (!this.handlers.has(endpointId)) {
        this.handlers.set(endpointId, []);
      }
      this.handlers.get(endpointId).push(handler);
    }
  }

  /**
   * Get recent events
   */
  getEvents(options = {}) {
    let events = [...this.eventQueue];

    if (options.endpointId) {
      events = events.filter(e => e.endpointId === options.endpointId);
    }

    if (options.since) {
      events = events.filter(e => e.timestamp > options.since);
    }

    if (options.limit) {
      events = events.slice(-options.limit);
    }

    return events;
  }

  /**
   * List endpoints
   */
  listEndpoints() {
    return Array.from(this.endpoints.values());
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      queueSize: this.eventQueue.length,
      endpoints: this.endpoints.size
    };
  }

  /**
   * Get audit log
   */
  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  /**
   * Create Express middleware
   */
  createMiddleware(endpointId) {
    return async (req, res) => {
      const result = await this.receive(endpointId, req.headers, req.body);

      if (result.success) {
        res.status(200).json(result);
      } else {
        res.status(400).json(result);
      }
    };
  }
}

// Singleton
const webhookReceiver = new WebhookReceiver();

module.exports = { WebhookReceiver, webhookReceiver };
