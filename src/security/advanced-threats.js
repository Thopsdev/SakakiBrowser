/**
 * Advanced Threat Protection
 *
 * Countermeasures for AI browser vulnerabilities discovered in 2025
 * - CSRF + memory injection (ChatGPT Atlas)
 * - Hidden text in images (Brave research)
 * - Hidden instructions in pages (Perplexity Comet)
 * - Authentication session abuse
 * - Remote debugging port exploitation
 */

const crypto = require('crypto');

// ==================== 1. CSRF Protection ====================

class CSRFProtection {
  constructor() {
    this.tokens = new Map();
    this.tokenTTL = 3600000; // 1 hour
  }

  // Generate token
  generateToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    this.tokens.set(token, {
      sessionId,
      createdAt: Date.now()
    });
    this._cleanup();
    return token;
  }

  // Validate token
  validateToken(token, sessionId) {
    const data = this.tokens.get(token);
    if (!data) return { valid: false, reason: 'Token not found' };
    if (data.sessionId !== sessionId) return { valid: false, reason: 'Session mismatch' };
    if (Date.now() - data.createdAt > this.tokenTTL) {
      this.tokens.delete(token);
      return { valid: false, reason: 'Token expired' };
    }
    // Invalidate after single use
    this.tokens.delete(token);
    return { valid: true };
  }

  _cleanup() {
    const now = Date.now();
    for (const [token, data] of this.tokens.entries()) {
      if (now - data.createdAt > this.tokenTTL) {
        this.tokens.delete(token);
      }
    }
  }
}

// ==================== 2. Memory Isolation ====================

class MemoryIsolation {
  constructor() {
    // Isolated memory per session
    this.memories = new Map();
    // Memory write log
    this.writeLog = [];
  }

  // Memory write (with validation)
  write(sessionId, key, value, source) {
    // Allow writes only from trusted sources
    const trustedSources = ['user_input', 'system'];

    if (!trustedSources.includes(source)) {
      this.writeLog.push({
        timestamp: Date.now(),
        sessionId,
        key,
        source,
        blocked: true,
        reason: 'Untrusted source'
      });
      return { success: false, reason: 'Untrusted source: ' + source };
    }

    // Check for dangerous patterns
    const dangerous = this._checkDangerousContent(value);
    if (dangerous.found) {
      this.writeLog.push({
        timestamp: Date.now(),
        sessionId,
        key,
        source,
        blocked: true,
        reason: 'Dangerous content: ' + dangerous.patterns.join(', ')
      });
      return { success: false, reason: 'Dangerous content detected' };
    }

    // Get or create session memory
    if (!this.memories.has(sessionId)) {
      this.memories.set(sessionId, new Map());
    }

    this.memories.get(sessionId).set(key, {
      value,
      source,
      writtenAt: Date.now()
    });

    this.writeLog.push({
      timestamp: Date.now(),
      sessionId,
      key,
      source,
      blocked: false
    });

    return { success: true };
  }

  // Memory read
  read(sessionId, key) {
    const session = this.memories.get(sessionId);
    if (!session) return null;
    return session.get(key)?.value || null;
  }

  // Dangerous content check
  _checkDangerousContent(value) {
    if (typeof value !== 'string') return { found: false };

    const patterns = [
      { name: 'hidden_instruction', regex: /instruction[s]?\s*:/i },
      { name: 'system_override', regex: /ignore\s+(previous|all|above)/i },
      { name: 'action_command', regex: /(delete|send|upload|transfer)\s+(all|my|the)/i },
      { name: 'code_execution', regex: /eval\s*\(|Function\s*\(|exec\s*\(/i },
    ];

    const found = [];
    for (const { name, regex } of patterns) {
      if (regex.test(value)) {
        found.push(name);
      }
    }

    return { found: found.length > 0, patterns: found };
  }

  // Clear session memory
  clearSession(sessionId) {
    this.memories.delete(sessionId);
  }

  // Get write log
  getWriteLog(limit = 100) {
    return this.writeLog.slice(-limit);
  }
}

// ==================== 3. Hidden Text in Images Detection ====================

class ImageInjectionDetector {
  constructor() {
    // Dangerous color combinations (hard for humans to see but OCR can read)
    this.suspiciousColorPairs = [
      { fg: 'light blue', bg: 'yellow' },
      { fg: 'white', bg: 'light gray' },
      { fg: 'light gray', bg: 'white' },
      { fg: 'yellow', bg: 'white' },
    ];
  }

  // Scan image (requires: sharp or canvas)
  async scanImage(imageBuffer) {
    const result = {
      scanned: false,
      suspicious: false,
      warnings: []
    };

    try {
      // Simple check: image size and format
      // Full implementation requires image processing library
      result.scanned = true;

      // Heuristic: abnormally large images require attention
      if (imageBuffer.length > 10 * 1024 * 1024) {
        result.warnings.push({
          type: 'large_image',
          message: 'Image larger than 10MB may contain hidden content'
        });
      }

      // TODO: Actual color analysis implementation
      // - Low contrast text detection
      // - OCR result vs visual diff comparison

    } catch (e) {
      result.error = e.message;
    }

    result.suspicious = result.warnings.length > 0;
    return result;
  }

  // Warning before taking screenshots
  getScreenshotWarning() {
    return {
      warning: 'Screenshots may contain hidden text visible only to AI',
      recommendation: 'Avoid using screenshots from untrusted sources for AI processing'
    };
  }
}

// ==================== 4. Page Content Sanitization ====================

class ContentSanitizer {
  constructor() {
    // Hidden text selectors
    this.hiddenSelectors = [
      '[style*="display:none"]',
      '[style*="display: none"]',
      '[style*="visibility:hidden"]',
      '[style*="visibility: hidden"]',
      '[style*="opacity:0"]',
      '[style*="opacity: 0"]',
      '[style*="font-size:0"]',
      '[style*="font-size: 0"]',
      '[style*="color:white"][style*="background:white"]',
      '.spoiler', // Reddit, etc.
      'details:not([open])', // Collapsed
    ];

    // Dangerous attributes
    this.dangerousAttributes = [
      'data-instruction',
      'data-command',
      'data-prompt',
    ];
  }

  // Extract only safe text from page
  async extractSafeText(page) {
    const result = await page.evaluate((selectors, attrs) => {
      const removed = [];

      // Remove hidden elements
      for (const selector of selectors) {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
          removed.push({
            type: 'hidden_element',
            selector,
            text: el.innerText?.slice(0, 100)
          });
          el.remove();
        });
      }

      // Check elements with dangerous attributes
      for (const attr of attrs) {
        const elements = document.querySelectorAll(`[${attr}]`);
        elements.forEach(el => {
          removed.push({
            type: 'dangerous_attribute',
            attribute: attr,
            value: el.getAttribute(attr)?.slice(0, 100)
          });
          el.removeAttribute(attr);
        });
      }

      // Detect instructions in HTML comments
      const html = document.documentElement.outerHTML;
      const commentMatches = html.match(/<!--[\s\S]*?(instruction|command|ignore|system)[\s\S]*?-->/gi);

      return {
        text: document.body.innerText,
        removed,
        suspiciousComments: commentMatches?.length || 0
      };

    }, this.hiddenSelectors, this.dangerousAttributes);

    return result;
  }

  // Remove instructions from text
  sanitizeText(text) {
    if (!text) return { text: '', removed: [] };

    const removed = [];
    let sanitized = text;

    // Remove instruction patterns
    const patterns = [
      { name: 'instruction_block', regex: /\[instruction\][\s\S]*?\[\/instruction\]/gi },
      { name: 'system_prompt', regex: /system\s*prompt\s*:[\s\S]*?(?=\n\n|$)/gi },
      { name: 'hidden_command', regex: /<!--[\s\S]*?-->/g },
      { name: 'invisible_chars', regex: /[\u200B-\u200F\u2028-\u202F\uFEFF]/g },
    ];

    for (const { name, regex } of patterns) {
      const matches = sanitized.match(regex);
      if (matches) {
        removed.push({ type: name, count: matches.length });
        sanitized = sanitized.replace(regex, '');
      }
    }

    return { text: sanitized.trim(), removed };
  }
}

// ==================== 5. Session Isolation ====================

class SessionIsolation {
  constructor() {
    this.sessions = new Map();
  }

  // Create new isolated session
  createSession(options = {}) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    this.sessions.set(sessionId, {
      id: sessionId,
      createdAt: Date.now(),
      // Allowed domains
      allowedDomains: options.allowedDomains || [],
      // Allowed actions
      allowedActions: options.allowedActions || ['navigate', 'read'],
      // Deny access to authentication info
      canAccessAuth: options.canAccessAuth || false,
      // Deny file operations
      canModifyFiles: options.canModifyFiles || false,
      // Deny external sending
      canExternalSend: options.canExternalSend || false,
    });

    return sessionId;
  }

  // Check if action is allowed
  isActionAllowed(sessionId, action, target) {
    const session = this.sessions.get(sessionId);
    if (!session) return { allowed: false, reason: 'Session not found' };

    // Action check
    if (!session.allowedActions.includes(action)) {
      return { allowed: false, reason: `Action '${action}' not permitted` };
    }

    // Domain check (for navigation)
    if (action === 'navigate' && session.allowedDomains.length > 0) {
      try {
        const domain = new URL(target).hostname;
        const allowed = session.allowedDomains.some(d =>
          domain === d || domain.endsWith('.' + d)
        );
        if (!allowed) {
          return { allowed: false, reason: `Domain '${domain}' not in whitelist` };
        }
      } catch {
        return { allowed: false, reason: 'Invalid URL' };
      }
    }

    // Authentication-related actions
    if (['login', 'oauth', 'password'].some(a => action.includes(a)) && !session.canAccessAuth) {
      return { allowed: false, reason: 'Auth actions not permitted' };
    }

    // File operations
    if (['delete', 'upload', 'download'].some(a => action.includes(a)) && !session.canModifyFiles) {
      return { allowed: false, reason: 'File operations not permitted' };
    }

    return { allowed: true };
  }

  // End session
  endSession(sessionId) {
    this.sessions.delete(sessionId);
  }
}

// ==================== 6. Debug Port Protection ====================

class DebugPortProtection {
  constructor() {
    // Dangerous ports
    this.dangerousPorts = [
      9222,  // Chrome DevTools
      9229,  // Node.js debug
      9230,  // Node.js debug (alternative)
      5858,  // Legacy Node.js debug
    ];
  }

  // Sanitize browser launch options
  sanitizeLaunchOptions(options) {
    const sanitized = { ...options };
    const warnings = [];

    // Disable remote debugging
    if (sanitized.args) {
      sanitized.args = sanitized.args.filter(arg => {
        if (arg.includes('--remote-debugging-port') ||
            arg.includes('--remote-debugging-address')) {
          warnings.push({
            type: 'debug_port_blocked',
            arg,
            reason: 'Remote debugging disabled for security'
          });
          return false;
        }
        return true;
      });
    }

    // Explicitly disable debugging
    sanitized.args = sanitized.args || [];
    sanitized.args.push('--disable-remote-debugging');

    return { options: sanitized, warnings };
  }

  // Local port scan (startup check)
  async checkExposedPorts() {
    const exposed = [];
    const net = require('net');

    for (const port of this.dangerousPorts) {
      const isOpen = await new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(1000);
        socket.on('connect', () => {
          socket.destroy();
          resolve(true);
        });
        socket.on('timeout', () => {
          socket.destroy();
          resolve(false);
        });
        socket.on('error', () => {
          resolve(false);
        });
        socket.connect(port, '127.0.0.1');
      });

      if (isOpen) {
        exposed.push({ port, risk: 'high' });
      }
    }

    return {
      safe: exposed.length === 0,
      exposed
    };
  }
}

// ==================== Unified Export ====================

const csrf = new CSRFProtection();
const memory = new MemoryIsolation();
const imageDetector = new ImageInjectionDetector();
const contentSanitizer = new ContentSanitizer();
const sessionIsolation = new SessionIsolation();
const debugProtection = new DebugPortProtection();

module.exports = {
  // Classes
  CSRFProtection,
  MemoryIsolation,
  ImageInjectionDetector,
  ContentSanitizer,
  SessionIsolation,
  DebugPortProtection,

  // Singleton instances
  csrf,
  memory,
  imageDetector,
  contentSanitizer,
  sessionIsolation,
  debugProtection,

  // Convenience functions
  createSecureSession: (options) => sessionIsolation.createSession(options),
  sanitizeBrowserOptions: (options) => debugProtection.sanitizeLaunchOptions(options),
};
