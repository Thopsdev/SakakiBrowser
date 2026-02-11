const fs = require('fs');
const os = require('os');
const path = require('path');

const BACKEND_ENV = {
  main: 'SAKAKI_BACKEND',
  vault: 'SAKAKI_VAULT_BACKEND'
};

const BROWSER_ENV = {
  main: 'SAKAKI_BROWSER',
  vault: 'SAKAKI_VAULT_BROWSER'
};

const PATH_ENV = {
  main: 'SAKAKI_BROWSER_PATH',
  vault: 'SAKAKI_VAULT_BROWSER_PATH'
};

const BROWSER_ALIASES = new Map([
  ['google chrome', 'chrome'],
  ['chrome', 'chrome'],
  ['chromium', 'chromium'],
  ['msedge', 'edge'],
  ['edge', 'edge'],
  ['microsoft edge', 'edge'],
  ['brave', 'brave'],
  ['brave browser', 'brave'],
  ['firefox', 'firefox'],
  ['webkit', 'webkit'],
  ['safari', 'webkit']
]);

const BROWSER_TYPES = {
  chrome: 'chromium',
  edge: 'chromium',
  brave: 'chromium',
  chromium: 'chromium',
  firefox: 'firefox',
  webkit: 'webkit'
};

function normalizeBrowserName(raw) {
  if (!raw) return '';
  const normalized = String(raw).toLowerCase().trim();
  if (BROWSER_ALIASES.has(normalized)) return BROWSER_ALIASES.get(normalized);
  return normalized.replace(/\s+/g, '');
}

function resolveBrowserType(name) {
  if (!name) return 'chromium';
  return BROWSER_TYPES[name] || 'chromium';
}

function exists(p) {
  try {
    return !!p && fs.existsSync(p);
  } catch {
    return false;
  }
}

function candidatePaths(browser) {
  const platform = process.platform;
  const home = os.homedir();
  const paths = [];

  if (platform === 'darwin') {
    const appBase = [
      '/Applications',
      path.join(home, 'Applications')
    ];
    if (browser === 'chrome' || browser === 'chromium') {
      appBase.forEach(base => {
        paths.push(path.join(base, 'Google Chrome.app/Contents/MacOS/Google Chrome'));
        paths.push(path.join(base, 'Chromium.app/Contents/MacOS/Chromium'));
      });
    }
    if (browser === 'edge') {
      appBase.forEach(base => paths.push(path.join(base, 'Microsoft Edge.app/Contents/MacOS/Microsoft Edge')));
    }
    if (browser === 'brave') {
      appBase.forEach(base => paths.push(path.join(base, 'Brave Browser.app/Contents/MacOS/Brave Browser')));
    }
  } else if (platform === 'win32') {
    const programFiles = process.env['PROGRAMFILES'] || 'C:\\\\Program Files';
    const programFilesX86 = process.env['PROGRAMFILES(X86)'] || 'C:\\\\Program Files (x86)';
    if (browser === 'chrome' || browser === 'chromium') {
      paths.push(path.join(programFiles, 'Google/Chrome/Application/chrome.exe'));
      paths.push(path.join(programFilesX86, 'Google/Chrome/Application/chrome.exe'));
      paths.push(path.join(programFiles, 'Chromium/Application/chrome.exe'));
      paths.push(path.join(programFilesX86, 'Chromium/Application/chrome.exe'));
    }
    if (browser === 'edge') {
      paths.push(path.join(programFiles, 'Microsoft/Edge/Application/msedge.exe'));
      paths.push(path.join(programFilesX86, 'Microsoft/Edge/Application/msedge.exe'));
    }
    if (browser === 'brave') {
      paths.push(path.join(programFiles, 'BraveSoftware/Brave-Browser/Application/brave.exe'));
      paths.push(path.join(programFilesX86, 'BraveSoftware/Brave-Browser/Application/brave.exe'));
    }
  } else {
    if (browser === 'chrome' || browser === 'chromium') {
      paths.push('/usr/bin/google-chrome');
      paths.push('/usr/bin/google-chrome-stable');
      paths.push('/usr/bin/chromium');
      paths.push('/usr/bin/chromium-browser');
      paths.push('/snap/bin/chromium');
    }
    if (browser === 'edge') {
      paths.push('/usr/bin/microsoft-edge');
      paths.push('/usr/bin/microsoft-edge-stable');
      paths.push('/opt/microsoft/msedge/msedge');
    }
    if (browser === 'brave') {
      paths.push('/usr/bin/brave-browser');
      paths.push('/usr/bin/brave-browser-stable');
      paths.push('/opt/brave.com/brave/brave-browser');
    }
  }

  return paths;
}

function resolveExecutablePath(browserName, explicitPath) {
  if (explicitPath) return explicitPath;
  if (!browserName || browserName === 'chromium') return null;

  const candidates = candidatePaths(browserName);
  for (const candidate of candidates) {
    if (exists(candidate)) return candidate;
  }
  return null;
}

function resolveBackendConfig(scope = 'main', overrides = {}) {
  const backendEnv = overrides.backend || process.env[BACKEND_ENV[scope]] || process.env.SAKAKI_BACKEND || '';
  const browserEnv = overrides.browser || process.env[BROWSER_ENV[scope]] || process.env.SAKAKI_BROWSER || '';
  const browser = normalizeBrowserName(browserEnv);
  const browserType = resolveBrowserType(browser);

  let backend = backendEnv ? String(backendEnv).toLowerCase().trim() : '';
  if (!backend) {
    backend = browserType === 'chromium' ? 'puppeteer' : 'playwright';
  }

  if (backend === 'puppeteer' && browserType !== 'chromium') {
    throw new Error(`Puppeteer backend supports only Chromium. Set SAKAKI_BACKEND=playwright for ${browserType}.`);
  }

  const explicitPath =
    overrides.executablePath ||
    process.env[PATH_ENV[scope]] ||
    process.env.SAKAKI_BROWSER_PATH ||
    (backend === 'playwright'
      ? (process.env.PLAYWRIGHT_EXECUTABLE_PATH || process.env.PUPPETEER_EXECUTABLE_PATH)
      : process.env.PUPPETEER_EXECUTABLE_PATH);

  const executablePath = browserType === 'chromium'
    ? resolveExecutablePath(browser || 'chromium', explicitPath)
    : (explicitPath || null);

  return {
    backend,
    browser: browser || 'chromium',
    browserType,
    executablePath
  };
}

function normalizeHeadlessMode(value, backend) {
  if (backend === 'playwright' && value === 'new') return true;
  return value;
}

function normalizeWaitUntil(value, backend) {
  if (backend === 'playwright' && value === 'networkidle2') return 'networkidle';
  return value;
}

function requirePlaywright() {
  try {
    return require('playwright-core');
  } catch (e) {
    throw new Error('Playwright backend selected but playwright-core is not installed. Run: npm install playwright-core && npx playwright install');
  }
}

async function launchBrowser(config, options) {
  if (config.backend === 'playwright') {
    const playwright = requirePlaywright();
    const type = playwright[config.browserType];
    if (!type) {
      throw new Error(`Playwright does not support browser type: ${config.browserType}`);
    }
    return type.launch({
      headless: normalizeHeadlessMode(options.headless, 'playwright'),
      args: options.args,
      executablePath: config.executablePath || undefined
    });
  }

  const puppeteer = require('puppeteer');
  return puppeteer.launch({
    headless: normalizeHeadlessMode(options.headless, 'puppeteer'),
    executablePath: config.executablePath || undefined,
    args: options.args
  });
}

module.exports = {
  resolveBackendConfig,
  normalizeHeadlessMode,
  normalizeWaitUntil,
  resolveExecutablePath,
  launchBrowser
};
