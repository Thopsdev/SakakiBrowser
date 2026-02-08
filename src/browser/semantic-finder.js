/**
 * Semantic Element Finder
 *
 * Find elements based on meaning, not CSS selectors
 * Self-healing element identification resistant to UI changes
 */

class SemanticFinder {
  constructor() {
    // Element type to typical attribute mapping
    this.elementPatterns = {
      login_button: {
        tags: ['button', 'a', 'input'],
        texts: ['login', 'log in', 'sign in', 'signin'],
        types: ['submit'],
        roles: ['button'],
        ids: ['login', 'signin', 'login-btn', 'signInButton'],
        classes: ['login', 'signin', 'login-btn']
      },
      submit_button: {
        tags: ['button', 'input'],
        texts: ['submit', 'send', 'ok', 'confirm'],
        types: ['submit'],
        roles: ['button']
      },
      email_input: {
        tags: ['input'],
        types: ['email', 'text'],
        names: ['email', 'mail', 'user', 'username', 'login'],
        ids: ['email', 'mail', 'user', 'username'],
        placeholders: ['email', 'mail', 'user']
      },
      password_input: {
        tags: ['input'],
        types: ['password'],
        names: ['password', 'pass', 'pwd'],
        ids: ['password', 'pass', 'pwd'],
        placeholders: ['password']
      },
      search_input: {
        tags: ['input'],
        types: ['search', 'text'],
        names: ['search', 'query', 'q', 's'],
        ids: ['search', 'query', 'searchbox'],
        placeholders: ['search'],
        roles: ['searchbox']
      }
    };

    // Statistics
    this.stats = {
      totalSearches: 0,
      successfulSearches: 0,
      fallbacksUsed: 0,
      strategyHits: {}
    };
  }

  /**
   * Find element on page (multiple strategies)
   */
  async find(page, query, options = {}) {
    this.stats.totalSearches++;

    // 1. Pattern matching
    if (this.elementPatterns[query]) {
      const result = await this._findByPattern(page, query);
      if (result) {
        this._recordHit('pattern');
        return result;
      }
    }

    // 2. Text search
    const byText = await this._findByText(page, query);
    if (byText) {
      this._recordHit('text');
      return byText;
    }

    // 3. Aria Label
    const byAria = await this._findByAriaLabel(page, query);
    if (byAria) {
      this._recordHit('aria');
      return byAria;
    }

    // 4. Placeholder
    const byPlaceholder = await this._findByPlaceholder(page, query);
    if (byPlaceholder) {
      this._recordHit('placeholder');
      return byPlaceholder;
    }

    // 5. Fuzzy matching (fallback)
    this.stats.fallbacksUsed++;
    const byFuzzy = await this._findFuzzy(page, query);
    if (byFuzzy) {
      this._recordHit('fuzzy');
      return byFuzzy;
    }

    // Not found
    return null;
  }

  /**
   * Pattern-based search
   */
  async _findByPattern(page, patternName) {
    const pattern = this.elementPatterns[patternName];
    if (!pattern) return null;

    // Build script
    const result = await page.evaluate((p) => {
      const candidates = [];

      // Filter by tags
      const tags = p.tags || ['*'];
      for (const tag of tags) {
        const elements = document.querySelectorAll(tag);
        for (const el of elements) {
          let score = 0;

          // type attribute
          if (p.types && p.types.includes(el.type)) score += 10;

          // id attribute
          if (p.ids) {
            const id = (el.id || '').toLowerCase();
            if (p.ids.some(i => id.includes(i))) score += 8;
          }

          // class attribute
          if (p.classes) {
            const cls = (el.className || '').toLowerCase();
            if (p.classes.some(c => cls.includes(c))) score += 5;
          }

          // name attribute
          if (p.names) {
            const name = (el.name || '').toLowerCase();
            if (p.names.some(n => name.includes(n))) score += 8;
          }

          // Text content
          if (p.texts) {
            const text = (el.textContent || el.value || '').toLowerCase().trim();
            if (p.texts.some(t => text.includes(t))) score += 10;
          }

          // placeholder
          if (p.placeholders) {
            const ph = (el.placeholder || '').toLowerCase();
            if (p.placeholders.some(t => ph.includes(t))) score += 7;
          }

          // role attribute
          if (p.roles && p.roles.includes(el.getAttribute('role'))) score += 5;

          // Visibility check
          if (score > 0 && el.offsetParent !== null) {
            candidates.push({
              selector: getUniqueSelector(el),
              score,
              tag: el.tagName,
              text: (el.textContent || '').substring(0, 50)
            });
          }
        }
      }

      // Sort by score
      candidates.sort((a, b) => b.score - a.score);
      return candidates[0] || null;

      function getUniqueSelector(el) {
        if (el.id) return `#${el.id}`;
        if (el.name) return `[name="${el.name}"]`;

        let path = [];
        while (el && el.nodeType === 1) {
          let selector = el.tagName.toLowerCase();
          if (el.id) {
            selector = `#${el.id}`;
            path.unshift(selector);
            break;
          }
          let sibling = el;
          let nth = 1;
          while (sibling = sibling.previousElementSibling) {
            if (sibling.tagName === el.tagName) nth++;
          }
          if (nth > 1) selector += `:nth-of-type(${nth})`;
          path.unshift(selector);
          el = el.parentNode;
        }
        return path.join(' > ');
      }
    }, pattern);

    if (result) {
      this.stats.successfulSearches++;
      return {
        found: true,
        selector: result.selector,
        score: result.score,
        strategy: 'pattern',
        element: await page.$(result.selector)
      };
    }

    return null;
  }

  /**
   * Search by text
   */
  async _findByText(page, text) {
    const normalizedText = text.toLowerCase().trim();

    const selector = await page.evaluate((searchText) => {
      const elements = document.querySelectorAll('button, a, input[type="submit"], [role="button"]');

      for (const el of elements) {
        const elText = (el.textContent || el.value || '').toLowerCase().trim();
        if (elText.includes(searchText) && el.offsetParent !== null) {
          // Generate unique selector
          if (el.id) return `#${el.id}`;
          if (el.name) return `[name="${el.name}"]`;

          // XPath fallback
          return null;
        }
      }
      return null;
    }, normalizedText);

    if (selector) {
      this.stats.successfulSearches++;
      return {
        found: true,
        selector,
        strategy: 'text',
        element: await page.$(selector)
      };
    }

    // XPath text search
    try {
      const [element] = await page.$x(`//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '${normalizedText}')]`);
      if (element) {
        this.stats.successfulSearches++;
        return {
          found: true,
          strategy: 'text-xpath',
          element
        };
      }
    } catch (e) {}

    return null;
  }

  /**
   * Search by Aria Label
   */
  async _findByAriaLabel(page, label) {
    const selector = `[aria-label*="${label}" i], [aria-labelledby*="${label}" i]`;
    const element = await page.$(selector);

    if (element) {
      this.stats.successfulSearches++;
      return {
        found: true,
        selector,
        strategy: 'aria',
        element
      };
    }

    return null;
  }

  /**
   * Search by Placeholder
   */
  async _findByPlaceholder(page, text) {
    const selector = `[placeholder*="${text}" i]`;
    const element = await page.$(selector);

    if (element) {
      this.stats.successfulSearches++;
      return {
        found: true,
        selector,
        strategy: 'placeholder',
        element
      };
    }

    return null;
  }

  /**
   * Fuzzy matching (last resort)
   */
  async _findFuzzy(page, query) {
    const words = query.toLowerCase().split(/\s+/);

    const result = await page.evaluate((searchWords) => {
      const allElements = document.querySelectorAll('button, a, input, select, textarea, [role="button"], [onclick]');
      let bestMatch = null;
      let bestScore = 0;

      for (const el of allElements) {
        if (el.offsetParent === null) continue; // Skip hidden

        const text = [
          el.textContent,
          el.value,
          el.placeholder,
          el.getAttribute('aria-label'),
          el.id,
          el.className,
          el.name
        ].filter(Boolean).join(' ').toLowerCase();

        let score = 0;
        for (const word of searchWords) {
          if (text.includes(word)) score += 1;
        }

        if (score > bestScore) {
          bestScore = score;
          bestMatch = {
            tag: el.tagName,
            id: el.id,
            name: el.name,
            text: (el.textContent || '').substring(0, 30)
          };
        }
      }

      if (bestMatch && bestScore > 0) {
        if (bestMatch.id) return `#${bestMatch.id}`;
        if (bestMatch.name) return `[name="${bestMatch.name}"]`;
      }

      return null;
    }, words);

    if (result) {
      this.stats.successfulSearches++;
      return {
        found: true,
        selector: result,
        strategy: 'fuzzy',
        element: await page.$(result)
      };
    }

    return null;
  }

  /**
   * Record hit
   */
  _recordHit(strategy) {
    this.stats.strategyHits[strategy] = (this.stats.strategyHits[strategy] || 0) + 1;
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      ...this.stats,
      successRate: this.stats.totalSearches > 0
        ? Math.round(this.stats.successfulSearches / this.stats.totalSearches * 100)
        : 0
    };
  }

  /**
   * Add custom pattern
   */
  addPattern(name, pattern) {
    this.elementPatterns[name] = pattern;
  }
}

// Singleton
const semanticFinder = new SemanticFinder();

module.exports = { SemanticFinder, semanticFinder };
