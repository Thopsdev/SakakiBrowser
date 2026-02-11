/**
 * Notification Center
 *
 * Channels:
 *  - In-App (dashboard)
 *  - Webhook (outbound)
 *  - Email (SMTP)
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');

const DEFAULT_MAX_EVENTS = 200;

function parseList(value) {
  if (!value) return [];
  return String(value)
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
}

function safeJson(data) {
  try {
    return JSON.stringify(data);
  } catch {
    return '"<unserializable>"';
  }
}

class NotificationCenter {
  constructor() {
    this.events = [];
    this.maxEvents = DEFAULT_MAX_EVENTS;
    this.webhooks = [];
    this.webhookSecret = null;
    this.smtp = {
      host: '',
      port: 587,
      secure: false,
      user: '',
      pass: ''
    };
    this.email = {
      from: '',
      to: []
    };
    this._transporter = null;
  }

  configureFromEnv(env = process.env) {
    const max = parseInt(env.SAKAKI_NOTIFY_MAX_EVENTS || env.SAKAKI_NOTIFY_MAX || DEFAULT_MAX_EVENTS, 10);
    if (Number.isFinite(max) && max > 0) this.maxEvents = max;
    this.webhooks = parseList(env.SAKAKI_NOTIFY_WEBHOOKS);
    this.webhookSecret = env.SAKAKI_NOTIFY_WEBHOOK_SECRET || null;

    this.smtp.host = env.SAKAKI_SMTP_HOST || '';
    this.smtp.port = parseInt(env.SAKAKI_SMTP_PORT || '587', 10);
    this.smtp.secure = String(env.SAKAKI_SMTP_SECURE || '').toLowerCase() === 'true';
    this.smtp.user = env.SAKAKI_SMTP_USER || '';
    this.smtp.pass = env.SAKAKI_SMTP_PASS || '';

    this.email.from = env.SAKAKI_NOTIFY_EMAIL_FROM || '';
    this.email.to = parseList(env.SAKAKI_NOTIFY_EMAIL_TO);
  }

  list(limit = 50) {
    return this.events.slice(-limit).reverse();
  }

  getStats() {
    const last = this.events[this.events.length - 1];
    return {
      total: this.events.length,
      lastEventAt: last ? last.createdAt : null,
      webhooks: this.webhooks.length,
      emailConfigured: !!(this.smtp.host && this.email.from && this.email.to.length)
    };
  }

  registerWebhook(url) {
    if (!url) return { success: false, error: 'url required' };
    if (!this.webhooks.includes(url)) this.webhooks.push(url);
    return { success: true, webhooks: this.webhooks.slice() };
  }

  unregisterWebhook(url) {
    if (!url) return { success: false, error: 'url required' };
    this.webhooks = this.webhooks.filter(w => w !== url);
    return { success: true, webhooks: this.webhooks.slice() };
  }

  notify(event) {
    const entry = {
      id: crypto.randomBytes(12).toString('hex'),
      type: event.type || 'event',
      severity: event.severity || 'info',
      message: event.message || '',
      data: event.data || {},
      createdAt: new Date().toISOString(),
      channels: {
        inApp: true,
        webhook: [],
        email: null
      }
    };

    this.events.push(entry);
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }

    this.dispatch(entry).catch(() => {});
    return entry;
  }

  async dispatch(entry) {
    if (this.webhooks.length) {
      const results = await Promise.all(this.webhooks.map(url => this.sendWebhook(url, entry)));
      entry.channels.webhook = results;
    }
    if (this.smtp.host && this.email.from && this.email.to.length) {
      entry.channels.email = await this.sendEmail(entry);
    }
  }

  async sendWebhook(url, entry) {
    return new Promise((resolve) => {
      let target;
      try {
        target = new URL(url);
      } catch {
        return resolve({ url, ok: false, error: 'invalid url' });
      }

      const body = safeJson({
        id: entry.id,
        type: entry.type,
        severity: entry.severity,
        message: entry.message,
        data: entry.data,
        createdAt: entry.createdAt
      });
      const ts = Date.now().toString();
      const signature = this.webhookSecret
        ? crypto.createHmac('sha256', this.webhookSecret).update(`${ts}.${body}`).digest('hex')
        : null;

      const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Sakaki-Notifier/0.1',
        'X-Sakaki-Event-Id': entry.id,
        'X-Sakaki-Event-Ts': ts
      };
      if (signature) {
        headers['X-Sakaki-Signature'] = signature;
        headers['X-Sakaki-Signature-Alg'] = 'sha256';
      }

      const req = (target.protocol === 'https:' ? https : http).request({
        method: 'POST',
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: target.pathname + target.search,
        headers,
        timeout: 4000
      }, (res) => {
        res.resume();
        resolve({ url, ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode });
      });

      req.on('error', (err) => {
        resolve({ url, ok: false, error: err.message });
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({ url, ok: false, error: 'timeout' });
      });

      req.write(body);
      req.end();
    });
  }

  async sendEmail(entry) {
    let nodemailer;
    try {
      nodemailer = require('nodemailer');
    } catch {
      return { ok: false, error: 'nodemailer not installed' };
    }

    if (!this._transporter) {
      this._transporter = nodemailer.createTransport({
        host: this.smtp.host,
        port: this.smtp.port,
        secure: this.smtp.secure,
        auth: this.smtp.user ? { user: this.smtp.user, pass: this.smtp.pass } : undefined
      });
    }

    const subject = `[Sakaki] ${entry.type}`;
    const text = [
      `Type: ${entry.type}`,
      `Severity: ${entry.severity}`,
      `Message: ${entry.message}`,
      `Time: ${entry.createdAt}`,
      '',
      `Data: ${safeJson(entry.data)}`
    ].join('\n');

    try {
      const info = await this._transporter.sendMail({
        from: this.email.from,
        to: this.email.to.join(', '),
        subject,
        text
      });
      return { ok: true, messageId: info.messageId || null };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }
}

const notificationCenter = new NotificationCenter();

module.exports = { NotificationCenter, notificationCenter };
