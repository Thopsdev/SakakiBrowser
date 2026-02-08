/**
 * Antivirus Integration
 *
 * Unified management of multiple AV providers
 */

const fs = require('fs');
const path = require('path');
const { createDefaultManager } = require('./av-providers');

// Provider manager
let manager = null;

// Initialize
async function init() {
  manager = createDefaultManager();
  const enabledCount = await manager.initAll();
  console.log(`[AV] Initialized with ${enabledCount} provider(s)`);
  return enabledCount;
}

// Scan file (all providers)
async function scanFile(filePath) {
  if (!manager) await init();

  if (!fs.existsSync(filePath)) {
    return { error: 'File not found', file: filePath };
  }

  const result = await manager.scanFile(filePath);
  return {
    file: filePath,
    ...result
  };
}

// Scan URL (all providers)
async function scanURL(url) {
  if (!manager) await init();

  const result = await manager.scanUrl(url);
  return {
    url,
    ...result
  };
}

// Scan hash (all providers)
async function scanHash(hash) {
  if (!manager) await init();

  const result = await manager.scanHash(hash);
  return {
    hash,
    ...result
  };
}

// Write content to temp file and scan
async function scanContent(content, filename = 'temp') {
  const tempPath = path.join('/tmp', `sakaki-scan-${Date.now()}-${filename}`);
  fs.writeFileSync(tempPath, content);

  try {
    const result = await scanFile(tempPath);
    return result;
  } finally {
    fs.unlinkSync(tempPath);
  }
}

// Provider statistics
function getStats() {
  if (!manager) return { initialized: false };
  return {
    initialized: true,
    providers: manager.getStats()
  };
}

// List of enabled providers
function getEnabledProviders() {
  if (!manager) return [];
  return manager.getEnabled().map(p => p.name);
}

// For backward compatibility
const SCANNERS = {
  clamav: { available: false },
  virustotal: { available: false, apiKey: process.env.VIRUSTOTAL_API_KEY }
};

module.exports = {
  init,
  scanFile,
  scanURL,
  scanHash,
  scanContent,
  getStats,
  getEnabledProviders,
  SCANNERS // Backward compatibility
};
