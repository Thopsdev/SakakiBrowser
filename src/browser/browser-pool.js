/**
 * Browser Pool
 *
 * Pre-launch and reuse browser instances and pages
 * Reduces startup costs and speeds up operations
 */

const puppeteer = require('puppeteer');

class BrowserPool {
  constructor(options = {}) {
    this.poolSize = options.poolSize || 3;
    this.maxPages = options.maxPages || 10;
    this.browsers = [];
    this.availablePages = [];
    this.busyPages = new Set();
    this.initialized = false;

    // Performance settings
    this.launchOptions = {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--no-first-run',
        '--no-zygote',
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-sync',
        '--disable-translate',
        '--metrics-recording-only',
        '--mute-audio',
        '--no-default-browser-check',
        '--safebrowsing-disable-auto-update',
      ],
      ...options.launchOptions
    };

    // Resource blocking settings
    this.blockResources = options.blockResources ?? true;
    this.blockedTypes = options.blockedTypes || [
      'image',
      'stylesheet',
      'font',
      'media'
    ];

    // Statistics
    this.stats = {
      pagesCreated: 0,
      pagesReused: 0,
      totalRequests: 0,
      blockedRequests: 0,
      avgPageLoadTime: 0,
      pageLoadTimes: []
    };
  }

  /**
   * Initialize pool
   */
  async init() {
    if (this.initialized) return;

    console.log(`[BrowserPool] Initializing with ${this.poolSize} browsers...`);

    // Pre-launch browsers
    for (let i = 0; i < this.poolSize; i++) {
      const browser = await puppeteer.launch(this.launchOptions);
      this.browsers.push(browser);

      // Pre-create pages
      const page = await this._createOptimizedPage(browser);
      this.availablePages.push(page);
    }

    this.initialized = true;
    console.log(`[BrowserPool] Ready: ${this.browsers.length} browsers, ${this.availablePages.length} pages`);
  }

  /**
   * Create optimized page
   */
  async _createOptimizedPage(browser) {
    const page = await browser.newPage();
    this.stats.pagesCreated++;

    // Viewport settings
    await page.setViewport({ width: 1280, height: 800 });

    // Resource blocking
    if (this.blockResources) {
      await page.setRequestInterception(true);
      page.on('request', (req) => {
        this.stats.totalRequests++;
        if (this.blockedTypes.includes(req.resourceType())) {
          this.stats.blockedRequests++;
          req.abort();
        } else {
          req.continue();
        }
      });
    }

    // Timeout settings
    page.setDefaultNavigationTimeout(10000);
    page.setDefaultTimeout(5000);

    // Ignore console errors (performance)
    page.on('pageerror', () => {});
    page.on('error', () => {});

    return page;
  }

  /**
   * Get page (from pool or create new)
   */
  async getPage() {
    if (!this.initialized) {
      await this.init();
    }

    // Get from pool
    if (this.availablePages.length > 0) {
      const page = this.availablePages.pop();
      this.busyPages.add(page);
      this.stats.pagesReused++;
      return page;
    }

    // Check limit
    if (this.busyPages.size >= this.maxPages) {
      throw new Error('Max pages limit reached');
    }

    // Create new
    const browser = this.browsers[this.stats.pagesCreated % this.browsers.length];
    const page = await this._createOptimizedPage(browser);
    this.busyPages.add(page);

    return page;
  }

  /**
   * Release page (for reuse)
   */
  async releasePage(page) {
    if (!this.busyPages.has(page)) return;

    this.busyPages.delete(page);

    try {
      // Cleanup
      await page.goto('about:blank', { waitUntil: 'domcontentloaded' });

      // Return to pool for reuse
      this.availablePages.push(page);
    } catch (e) {
      // Close if page is broken
      try { await page.close(); } catch {}
    }
  }

  /**
   * Fast navigation
   */
  async fastNavigate(url, options = {}) {
    const page = await this.getPage();
    const startTime = Date.now();

    try {
      // Minimal wait for speed
      await page.goto(url, {
        waitUntil: options.waitUntil || 'domcontentloaded',
        timeout: options.timeout || 10000
      });

      const loadTime = Date.now() - startTime;
      this._recordLoadTime(loadTime);

      return {
        page,
        loadTime,
        release: () => this.releasePage(page)
      };
    } catch (e) {
      await this.releasePage(page);
      throw e;
    }
  }

  /**
   * Record page load time
   */
  _recordLoadTime(time) {
    this.stats.pageLoadTimes.push(time);
    if (this.stats.pageLoadTimes.length > 100) {
      this.stats.pageLoadTimes.shift();
    }
    this.stats.avgPageLoadTime = Math.round(
      this.stats.pageLoadTimes.reduce((a, b) => a + b, 0) /
      this.stats.pageLoadTimes.length
    );
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      availablePages: this.availablePages.length,
      busyPages: this.busyPages.size,
      browsers: this.browsers.length,
      blockRate: this.stats.totalRequests > 0
        ? Math.round(this.stats.blockedRequests / this.stats.totalRequests * 100)
        : 0
    };
  }

  /**
   * Cleanup
   */
  async close() {
    for (const browser of this.browsers) {
      await browser.close();
    }
    this.browsers = [];
    this.availablePages = [];
    this.busyPages.clear();
    this.initialized = false;
    console.log('[BrowserPool] Closed');
  }
}

// Singleton
const browserPool = new BrowserPool();

module.exports = { BrowserPool, browserPool };
