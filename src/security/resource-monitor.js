/**
 * Resource Monitor
 *
 * Monitors CPU/memory usage and detects cryptominers, etc.
 */

const os = require('os');

// Thresholds
const THRESHOLDS = {
  cpuSpikePercent: 80,        // Warn if CPU usage exceeds this
  memoryGrowthMB: 100,        // Warn if memory spikes
  networkRequestsPerSec: 50,  // Request frequency
};

// Monitoring state
const monitorState = {
  samples: [],
  alerts: [],
  baselineMemory: null,
  isMonitoring: false,
  interval: null,
};

// Get CPU usage
function getCpuUsage() {
  const cpus = os.cpus();
  let totalIdle = 0;
  let totalTick = 0;

  for (const cpu of cpus) {
    for (const type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  }

  return {
    idle: totalIdle / cpus.length,
    total: totalTick / cpus.length,
    usage: 100 - (100 * totalIdle / totalTick)
  };
}

// Get memory usage
function getMemoryUsage() {
  const used = process.memoryUsage();
  return {
    heapUsedMB: Math.round(used.heapUsed / 1024 / 1024),
    heapTotalMB: Math.round(used.heapTotal / 1024 / 1024),
    rssMB: Math.round(used.rss / 1024 / 1024),
    externalMB: Math.round(used.external / 1024 / 1024),
  };
}

// Record sample
function recordSample() {
  const sample = {
    timestamp: Date.now(),
    cpu: getCpuUsage(),
    memory: getMemoryUsage(),
  };

  monitorState.samples.push(sample);

  // Keep only last 100 samples
  if (monitorState.samples.length > 100) {
    monitorState.samples.shift();
  }

  // Anomaly detection
  checkAnomalies(sample);

  return sample;
}

// Anomaly detection
function checkAnomalies(sample) {
  const alerts = [];

  // CPU spike detection
  if (sample.cpu.usage > THRESHOLDS.cpuSpikePercent) {
    alerts.push({
      type: 'cpu_spike',
      severity: 'high',
      value: sample.cpu.usage,
      threshold: THRESHOLDS.cpuSpikePercent,
      message: `CPU spike detected: ${sample.cpu.usage.toFixed(1)}%`,
      possibleCause: 'Possible cryptominer or infinite loop'
    });
  }

  // Memory spike detection
  if (monitorState.baselineMemory) {
    const growth = sample.memory.heapUsedMB - monitorState.baselineMemory;
    if (growth > THRESHOLDS.memoryGrowthMB) {
      alerts.push({
        type: 'memory_growth',
        severity: 'medium',
        value: growth,
        threshold: THRESHOLDS.memoryGrowthMB,
        message: `Memory growth: +${growth}MB since baseline`,
        possibleCause: 'Possible memory leak or data exfiltration buffer'
      });
    }
  } else {
    monitorState.baselineMemory = sample.memory.heapUsedMB;
  }

  // Record alerts
  for (const alert of alerts) {
    alert.timestamp = sample.timestamp;
    monitorState.alerts.push(alert);
    console.warn(`[ResourceMonitor] WARN ${alert.message}`);
  }

  // Keep only last 50 alerts
  if (monitorState.alerts.length > 50) {
    monitorState.alerts = monitorState.alerts.slice(-50);
  }

  return alerts;
}

// Monitor page resource usage
async function monitorPage(page, callback) {
  const pageMetrics = {
    requests: 0,
    dataTransferred: 0,
    jsHeapSize: 0,
  };

  // Request monitoring
  page.on('request', (request) => {
    pageMetrics.requests++;
  });

  // Response monitoring
  page.on('response', async (response) => {
    try {
      const headers = response.headers();
      const contentLength = parseInt(headers['content-length'] || '0', 10);
      pageMetrics.dataTransferred += contentLength;
    } catch (e) {
      // ignore
    }
  });

  // Get metrics periodically
  const checkInterval = setInterval(async () => {
    try {
      let heapMb = null;
      if (typeof page.metrics === 'function') {
        const metrics = await page.metrics();
        if (metrics && metrics.JSHeapUsedSize) {
          heapMb = Math.round(metrics.JSHeapUsedSize / 1024 / 1024);
        }
      } else if (typeof page.evaluate === 'function') {
        const jsHeap = await page.evaluate(() => {
          if (typeof performance !== 'undefined' && performance.memory) {
            return performance.memory.usedJSHeapSize || 0;
          }
          return 0;
        }).catch(() => 0);
        if (jsHeap) heapMb = Math.round(jsHeap / 1024 / 1024);
      }

      if (heapMb !== null) {
        pageMetrics.jsHeapSize = heapMb;
      }

      if (callback) {
        callback(pageMetrics);
      }

      // Anomaly detection
      if (pageMetrics.jsHeapSize > 500) {
        console.warn(`[ResourceMonitor] Page heap size: ${pageMetrics.jsHeapSize}MB`);
      }
    } catch (e) {
      // Page was closed
      clearInterval(checkInterval);
    }
  }, 5000);

  return {
    getMetrics: () => pageMetrics,
    stop: () => clearInterval(checkInterval)
  };
}

// Start monitoring
function startMonitoring(intervalMs = 5000) {
  if (monitorState.isMonitoring) return;

  monitorState.isMonitoring = true;
  monitorState.baselineMemory = null;
  monitorState.samples = [];
  monitorState.alerts = [];

  monitorState.interval = setInterval(recordSample, intervalMs);
  console.log('[ResourceMonitor] Started monitoring');
}

// Stop monitoring
function stopMonitoring() {
  if (monitorState.interval) {
    clearInterval(monitorState.interval);
    monitorState.interval = null;
  }
  monitorState.isMonitoring = false;
  console.log('[ResourceMonitor] Stopped monitoring');
}

// Get statistics
function getStats() {
  const recentSamples = monitorState.samples.slice(-10);

  const avgCpu = recentSamples.length > 0
    ? recentSamples.reduce((sum, s) => sum + s.cpu.usage, 0) / recentSamples.length
    : 0;

  const currentMemory = getMemoryUsage();

  return {
    isMonitoring: monitorState.isMonitoring,
    samplesCollected: monitorState.samples.length,
    alertsCount: monitorState.alerts.length,
    recentAlerts: monitorState.alerts.slice(-5),
    avgCpuUsage: avgCpu.toFixed(1),
    currentMemory,
    baselineMemoryMB: monitorState.baselineMemory,
  };
}

// Get alerts
function getAlerts(limit = 20) {
  return monitorState.alerts.slice(-limit);
}

module.exports = {
  startMonitoring,
  stopMonitoring,
  recordSample,
  monitorPage,
  getStats,
  getAlerts,
  getCpuUsage,
  getMemoryUsage,
  THRESHOLDS
};
