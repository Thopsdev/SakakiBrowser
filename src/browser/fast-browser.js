/**
 * Fast Browser
 *
 * Fast, stable, secure browser operation API
 * - Speed via browser pool
 * - Stability via semantic search
 * - Security via Vault integration
 */

const { browserPool } = require('./browser-pool');
const { semanticFinder } = require('./semantic-finder');

class FastBrowser {
  constructor(options = {}) {
    this.pool = options.pool || browserPool;
    this.finder = options.finder || semanticFinder;
    this.vaultClient = options.vaultClient || null;

    // Session management
    this.sessions = new Map(); // sessionId -> { page, cookies, localStorage }

    // Statistics
    this.stats = {
      operations: 0,
      successfulOps: 0,
      failedOps: 0,
      avgOperationTime: 0,
      operationTimes: []
    };
  }

  /**
   * Initialize
   */
  async init() {
    await this.pool.init();
    console.log('[FastBrowser] Initialized');
  }

  /**
   * Open page
   */
  async open(url, options = {}) {
    const startTime = Date.now();
    this.stats.operations++;

    try {
      const result = await this.pool.fastNavigate(url, options);
      this._recordOpTime(Date.now() - startTime);
      this.stats.successfulOps++;

      return {
        success: true,
        page: result.page,
        loadTime: result.loadTime,
        release: result.release
      };
    } catch (e) {
      this.stats.failedOps++;
      return { success: false, error: e.message };
    }
  }

  /**
   * Semantic click
   * Example: click("login button") or click("login_button")
   */
  async click(page, target, options = {}) {
    const startTime = Date.now();
    this.stats.operations++;

    try {
      const found = await this.finder.find(page, target);

      if (!found) {
        this.stats.failedOps++;
        return { success: false, error: `Element not found: ${target}` };
      }

      await found.element.click();
      this._recordOpTime(Date.now() - startTime);
      this.stats.successfulOps++;

      // Wait for navigation (optional)
      if (options.waitForNavigation) {
        await page.waitForNavigation({
          waitUntil: 'domcontentloaded',
          timeout: 5000
        }).catch(() => {});
      }

      return {
        success: true,
        strategy: found.strategy,
        selector: found.selector
      };
    } catch (e) {
      this.stats.failedOps++;
      return { success: false, error: e.message };
    }
  }

  /**
   * Semantic type
   * Example: type("email_input", "user@example.com")
   */
  async type(page, target, text, options = {}) {
    const startTime = Date.now();
    this.stats.operations++;

    try {
      const found = await this.finder.find(page, target);

      if (!found) {
        this.stats.failedOps++;
        return { success: false, error: `Element not found: ${target}` };
      }

      // Clear before typing
      if (options.clear !== false) {
        await found.element.click({ clickCount: 3 });
        await page.keyboard.press('Backspace');
      }

      await found.element.type(text, { delay: options.delay || 0 });
      this._recordOpTime(Date.now() - startTime);
      this.stats.successfulOps++;

      return {
        success: true,
        strategy: found.strategy,
        selector: found.selector
      };
    } catch (e) {
      this.stats.failedOps++;
      return { success: false, error: e.message };
    }
  }

  /**
   * Secure input via Vault
   * Secret is retrieved from Vault and typed directly
   */
  async typeFromVault(page, target, secretName, options = {}) {
    if (!this.vaultClient) {
      return { success: false, error: 'Vault client not configured' };
    }

    // This operation is risky - would retrieve value from Vault
    // Instead, browser operations should be done inside Vault process
    console.warn('[FastBrowser] typeFromVault: Secret will temporarily pass through this process');

    // TODO: Implement secure vault-side browser control
    return {
      success: false,
      error: 'Not implemented - requires vault-side browser control for true security'
    };
  }

  /**
   * Get text
   */
  async getText(page, target) {
    const startTime = Date.now();
    this.stats.operations++;

    try {
      const found = await this.finder.find(page, target);

      if (!found) {
        // Try direct selector
        const element = await page.$(target);
        if (element) {
          const text = await page.evaluate(el => el.textContent, element);
          this._recordOpTime(Date.now() - startTime);
          this.stats.successfulOps++;
          return { success: true, text: text.trim() };
        }

        this.stats.failedOps++;
        return { success: false, error: `Element not found: ${target}` };
      }

      const text = await page.evaluate(el => el.textContent, found.element);
      this._recordOpTime(Date.now() - startTime);
      this.stats.successfulOps++;

      return {
        success: true,
        text: text.trim(),
        strategy: found.strategy
      };
    } catch (e) {
      this.stats.failedOps++;
      return { success: false, error: e.message };
    }
  }

  /**
   * Check if element exists
   */
  async exists(page, target) {
    const found = await this.finder.find(page, target);
    return { exists: !!found, strategy: found?.strategy };
  }

  /**
   * Wait for element
   */
  async waitFor(page, target, options = {}) {
    const timeout = options.timeout || 10000;
    const interval = options.interval || 500;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const found = await this.finder.find(page, target);
      if (found) {
        return { success: true, strategy: found.strategy };
      }
      await new Promise(r => setTimeout(r, interval));
    }

    return { success: false, error: 'Timeout waiting for element' };
  }

  /**
   * Login flow (common pattern)
   */
  async login(url, credentials, options = {}) {
    const startTime = Date.now();

    // Open page
    const { page, release, loadTime } = await this.pool.fastNavigate(url);

    try {
      // Enter email/username
      const emailResult = await this.type(page, 'email_input', credentials.email || credentials.username);
      if (!emailResult.success) {
        throw new Error(`Email input failed: ${emailResult.error}`);
      }

      // Enter password
      const passResult = await this.type(page, 'password_input', credentials.password);
      if (!passResult.success) {
        throw new Error(`Password input failed: ${passResult.error}`);
      }

      // Click login button
      const clickResult = await this.click(page, 'login_button', { waitForNavigation: true });
      if (!clickResult.success) {
        throw new Error(`Login click failed: ${clickResult.error}`);
      }

      // Confirm login success (optional)
      await new Promise(r => setTimeout(r, 1000));
      const currentUrl = page.url();

      const totalTime = Date.now() - startTime;

      return {
        success: true,
        url: currentUrl,
        totalTime,
        steps: {
          pageLoad: loadTime,
          emailInput: emailResult.strategy,
          passwordInput: passResult.strategy,
          loginClick: clickResult.strategy
        },
        release
      };
    } catch (e) {
      release();
      return { success: false, error: e.message };
    }
  }

  /**
   * Screenshot
   */
  async screenshot(page, options = {}) {
    try {
      const buffer = await page.screenshot({
        encoding: options.encoding || 'base64',
        type: options.type || 'png',
        fullPage: options.fullPage || false
      });
      return { success: true, data: buffer };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  /**
   * Get DOM (for Vision-free operations)
   */
  async getDOM(page, options = {}) {
    try {
      const html = await page.content();
      return {
        success: true,
        html: options.full ? html : this._simplifyHTML(html),
        url: page.url(),
        title: await page.title()
      };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  /**
   * Simplify HTML (remove unnecessary parts)
   */
  _simplifyHTML(html) {
    return html
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
      .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Record operation time
   */
  _recordOpTime(time) {
    this.stats.operationTimes.push(time);
    if (this.stats.operationTimes.length > 100) {
      this.stats.operationTimes.shift();
    }
    this.stats.avgOperationTime = Math.round(
      this.stats.operationTimes.reduce((a, b) => a + b, 0) /
      this.stats.operationTimes.length
    );
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      browser: this.stats,
      pool: this.pool.getStats(),
      finder: this.finder.getStats()
    };
  }

  /**
   * Close
   */
  async close() {
    await this.pool.close();
  }
}

// Singleton
const fastBrowser = new FastBrowser();

module.exports = { FastBrowser, fastBrowser };
