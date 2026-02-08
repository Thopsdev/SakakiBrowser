/**
 * Threat Intelligence Integration
 *
 * Integration with external threat DBs for real-time information
 *
 * Supported services:
 * - URLhaus (abuse.ch) - Free, no API key required
 * - PhishTank - Free, API key recommended
 * - Google Safe Browsing - Free tier available
 */

const https = require('https');
const http = require('http');

// Cache (in-memory)
const cache = {
  urlhaus: new Map(),    // url -> { malicious: bool, tags: [], timestamp }
  phishtank: new Map(),
  safebrowsing: new Map()
};

const CACHE_TTL = 3600000; // 1 hour

// ==================== URLhaus (abuse.ch) ====================

class URLhausProvider {
  constructor() {
    this.name = 'URLhaus';
    this.baseUrl = 'https://urlhaus-api.abuse.ch/v1';
    this.enabled = true; // No API key required
    this.stats = { queries: 0, hits: 0, errors: 0 };
  }

  async checkUrl(url) {
    // Cache check
    const cached = cache.urlhaus.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached;
    }

    this.stats.queries++;

    try {
      const result = await this._query(url);

      const entry = {
        malicious: result.query_status === 'ok' && result.urls && result.urls.length > 0,
        tags: result.urls?.[0]?.tags || [],
        threat: result.urls?.[0]?.threat || null,
        timestamp: Date.now(),
        provider: this.name
      };

      if (entry.malicious) this.stats.hits++;

      cache.urlhaus.set(url, entry);
      return entry;

    } catch (e) {
      this.stats.errors++;
      return { malicious: false, error: e.message, provider: this.name };
    }
  }

  async _query(url) {
    return new Promise((resolve, reject) => {
      const postData = `url=${encodeURIComponent(url)}`;

      const req = https.request({
        hostname: 'urlhaus-api.abuse.ch',
        path: '/v1/url/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': postData.length
        },
        timeout: 1000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ query_status: 'error', error: 'Parse error' });
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Timeout')));
      req.write(postData);
      req.end();
    });
  }

  // Get recent malware URL list (for batch updates)
  async getRecentMalware(limit = 100) {
    try {
      return new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'urlhaus-api.abuse.ch',
          path: '/v1/urls/recent/limit/' + limit + '/',
          method: 'GET',
          timeout: 10000
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const result = JSON.parse(data);
              resolve(result.urls || []);
            } catch {
              resolve([]);
            }
          });
        });

        req.on('error', reject);
        req.end();
      });
    } catch (e) {
      return [];
    }
  }
}

// ==================== PhishTank ====================

class PhishTankProvider {
  constructor(apiKey = null) {
    this.name = 'PhishTank';
    this.apiKey = apiKey || process.env.PHISHTANK_API_KEY;
    this.enabled = true; // Works without API key but with limits
    this.stats = { queries: 0, hits: 0, errors: 0 };
  }

  async checkUrl(url) {
    const cached = cache.phishtank.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached;
    }

    this.stats.queries++;

    try {
      const result = await this._query(url);

      const entry = {
        malicious: result.results?.in_database === true && result.results?.valid === true,
        verified: result.results?.verified === true,
        timestamp: Date.now(),
        provider: this.name
      };

      if (entry.malicious) this.stats.hits++;

      cache.phishtank.set(url, entry);
      return entry;

    } catch (e) {
      this.stats.errors++;
      return { malicious: false, error: e.message, provider: this.name };
    }
  }

  async _query(url) {
    return new Promise((resolve, reject) => {
      const params = new URLSearchParams({
        url: url,
        format: 'json'
      });
      if (this.apiKey) params.append('app_key', this.apiKey);

      const postData = params.toString();

      const req = https.request({
        hostname: 'checkurl.phishtank.com',
        path: '/checkurl/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': postData.length
        },
        timeout: 1000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ results: { in_database: false } });
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Timeout')));
      req.write(postData);
      req.end();
    });
  }
}

// ==================== Google Safe Browsing ====================

class SafeBrowsingProvider {
  constructor(apiKey = null) {
    this.name = 'Google Safe Browsing';
    this.apiKey = apiKey || process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    this.enabled = !!this.apiKey;
    this.stats = { queries: 0, hits: 0, errors: 0 };
  }

  async checkUrl(url) {
    if (!this.enabled) {
      return { malicious: false, error: 'No API key', provider: this.name };
    }

    const cached = cache.safebrowsing.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached;
    }

    this.stats.queries++;

    try {
      const result = await this._query([url]);

      const entry = {
        malicious: result.matches && result.matches.length > 0,
        threats: result.matches?.map(m => m.threatType) || [],
        timestamp: Date.now(),
        provider: this.name
      };

      if (entry.malicious) this.stats.hits++;

      cache.safebrowsing.set(url, entry);
      return entry;

    } catch (e) {
      this.stats.errors++;
      return { malicious: false, error: e.message, provider: this.name };
    }
  }

  async _query(urls) {
    return new Promise((resolve, reject) => {
      const body = JSON.stringify({
        client: {
          clientId: 'sakaki-browser',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map(url => ({ url }))
        }
      });

      const req = https.request({
        hostname: 'safebrowsing.googleapis.com',
        path: `/v4/threatMatches:find?key=${this.apiKey}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': body.length
        },
        timeout: 1000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({});
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Timeout')));
      req.write(body);
      req.end();
    });
  }
}

// ==================== Unified Manager ====================

class ThreatIntelManager {
  constructor() {
    this.providers = [
      new URLhausProvider(),
      new PhishTankProvider(),
      new SafeBrowsingProvider()
    ];
  }

  async checkUrl(url, options = {}) {
    const timeout = options.timeout || 500; // Default 500ms (optimization)

    // Execute in parallel with timeout
    const withTimeout = (promise, ms) => {
      return Promise.race([
        promise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), ms)
        )
      ]);
    };

    const results = await Promise.all(
      this.providers
        .filter(p => p.enabled)
        .map(p =>
          withTimeout(p.checkUrl(url), timeout)
            .catch(e => ({ error: e.message, provider: p.name, timedOut: e.message === 'Timeout' }))
        )
    );

    const malicious = results.some(r => r.malicious);
    const threats = results.filter(r => r.malicious);

    return {
      url,
      malicious,
      checkedBy: results.length,
      threats,
      allResults: results
    };
  }

  getStats() {
    return this.providers.map(p => ({
      name: p.name,
      enabled: p.enabled,
      ...p.stats
    }));
  }

  getCacheStats() {
    return {
      urlhaus: cache.urlhaus.size,
      phishtank: cache.phishtank.size,
      safebrowsing: cache.safebrowsing.size
    };
  }
}

// Singleton
const manager = new ThreatIntelManager();

module.exports = {
  URLhausProvider,
  PhishTankProvider,
  SafeBrowsingProvider,
  ThreatIntelManager,
  manager,
  checkUrl: (url) => manager.checkUrl(url),
  getStats: () => manager.getStats(),
  getCacheStats: () => manager.getCacheStats()
};
