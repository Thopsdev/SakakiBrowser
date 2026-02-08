/**
 * Rate Limiter
 *
 * Limits agent action rate to prevent abuse
 */

// Request history per domain
const requestHistory = new Map();

// Default limits
const DEFAULT_LIMITS = {
  requestsPerMinute: 30,
  requestsPerHour: 300,
  concurrentPages: 5,
  minDelayMs: 1000,  // Minimum interval for same domain
};

// Custom limits per domain
const DOMAIN_LIMITS = new Map([
  ['google.com', { requestsPerMinute: 10, minDelayMs: 3000 }],
  ['twitter.com', { requestsPerMinute: 15, minDelayMs: 2000 }],
  ['github.com', { requestsPerMinute: 20, minDelayMs: 1500 }],
]);

// Current page count
let activePages = 0;

class RateLimiter {
  constructor(options = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...options };
    this.blocked = [];
  }

  // Extract domain
  _getDomain(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return 'unknown';
    }
  }

  // Get/initialize request history
  _getHistory(domain) {
    if (!requestHistory.has(domain)) {
      requestHistory.set(domain, {
        requests: [],
        lastRequest: 0
      });
    }
    return requestHistory.get(domain);
  }

  // Clean old history
  _cleanup(history) {
    const oneHourAgo = Date.now() - 3600000;
    history.requests = history.requests.filter(t => t > oneHourAgo);
  }

  // Check if request is allowed
  canRequest(url) {
    const domain = this._getDomain(url);
    const history = this._getHistory(domain);
    const limits = DOMAIN_LIMITS.get(domain) || this.limits;

    this._cleanup(history);

    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Check requests per minute
    const recentRequests = history.requests.filter(t => t > oneMinuteAgo);
    if (recentRequests.length >= limits.requestsPerMinute) {
      return {
        allowed: false,
        reason: 'Rate limit exceeded (per minute)',
        retryAfter: Math.ceil((recentRequests[0] + 60000 - now) / 1000),
        domain
      };
    }

    // Check requests per hour
    if (history.requests.length >= limits.requestsPerHour) {
      return {
        allowed: false,
        reason: 'Rate limit exceeded (per hour)',
        retryAfter: Math.ceil((history.requests[0] + 3600000 - now) / 1000),
        domain
      };
    }

    // Check minimum interval
    const timeSinceLastRequest = now - history.lastRequest;
    if (timeSinceLastRequest < limits.minDelayMs) {
      return {
        allowed: false,
        reason: 'Too fast',
        retryAfter: Math.ceil((limits.minDelayMs - timeSinceLastRequest) / 1000),
        domain
      };
    }

    // Check concurrent page count
    if (activePages >= this.limits.concurrentPages) {
      return {
        allowed: false,
        reason: 'Too many concurrent pages',
        domain
      };
    }

    return { allowed: true, domain };
  }

  // Record request
  recordRequest(url) {
    const domain = this._getDomain(url);
    const history = this._getHistory(domain);
    const now = Date.now();

    history.requests.push(now);
    history.lastRequest = now;
  }

  // Record page opened
  pageOpened() {
    activePages++;
  }

  // Record page closed
  pageClosed() {
    activePages = Math.max(0, activePages - 1);
  }

  // Calculate appropriate wait time
  getRecommendedDelay(url) {
    const domain = this._getDomain(url);
    const limits = DOMAIN_LIMITS.get(domain) || this.limits;
    const history = this._getHistory(domain);

    const timeSinceLastRequest = Date.now() - history.lastRequest;
    const neededDelay = limits.minDelayMs - timeSinceLastRequest;

    return Math.max(0, neededDelay);
  }

  // Request with auto-throttling
  async throttledRequest(url, requestFn) {
    const check = this.canRequest(url);

    if (!check.allowed) {
      if (check.retryAfter) {
        // Wait and retry
        await new Promise(resolve => setTimeout(resolve, check.retryAfter * 1000));
        return this.throttledRequest(url, requestFn);
      }
      throw new Error(`Rate limited: ${check.reason}`);
    }

    // Recommended wait time
    const delay = this.getRecommendedDelay(url);
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }

    this.recordRequest(url);
    return requestFn();
  }

  // Statistics
  getStats() {
    const stats = {
      activePages,
      domains: {}
    };

    for (const [domain, history] of requestHistory.entries()) {
      const now = Date.now();
      const oneMinuteAgo = now - 60000;

      stats.domains[domain] = {
        requestsLastMinute: history.requests.filter(t => t > oneMinuteAgo).length,
        requestsLastHour: history.requests.length,
        lastRequest: history.lastRequest ? new Date(history.lastRequest).toISOString() : null
      };
    }

    return stats;
  }

  // Reset
  reset() {
    requestHistory.clear();
    activePages = 0;
  }
}

// Singleton instance
const rateLimiter = new RateLimiter();

module.exports = {
  RateLimiter,
  rateLimiter,
  DEFAULT_LIMITS,
  DOMAIN_LIMITS
};
