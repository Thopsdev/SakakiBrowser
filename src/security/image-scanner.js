/**
 * Image Scanner
 *
 * Detects hidden text in images
 * Brave research: Low contrast text (light blue on yellow, etc.)
 */

const sharp = require('sharp');

// Dangerous color combinations (hard for humans to see but OCR can read)
const SUSPICIOUS_COLOR_PAIRS = [
  { fg: [173, 216, 230], bg: [255, 255, 0], name: 'light blue on yellow' },
  { fg: [255, 255, 255], bg: [240, 240, 240], name: 'white on light gray' },
  { fg: [250, 250, 250], bg: [255, 255, 255], name: 'near-white on white' },
  { fg: [255, 255, 200], bg: [255, 255, 255], name: 'light yellow on white' },
];

// Calculate color distance (RGB space)
function colorDistance(c1, c2) {
  return Math.sqrt(
    Math.pow(c1[0] - c2[0], 2) +
    Math.pow(c1[1] - c2[1], 2) +
    Math.pow(c1[2] - c2[2], 2)
  );
}

// Determine if low contrast
function isLowContrast(fg, bg) {
  // Small color distance = low contrast
  const distance = colorDistance(fg, bg);
  return distance < 50; // Threshold
}

/**
 * Scan image to detect possible hidden text
 */
async function scanImage(imageBuffer) {
  const result = {
    scanned: true,
    suspicious: false,
    warnings: [],
    stats: {}
  };

  try {
    const image = sharp(imageBuffer);
    const metadata = await image.metadata();

    result.stats.width = metadata.width;
    result.stats.height = metadata.height;
    result.stats.format = metadata.format;

    // 1. Image size check
    if (metadata.width > 4000 || metadata.height > 4000) {
      result.warnings.push({
        type: 'large_image',
        message: 'Very large image may contain hidden content',
        severity: 'medium'
      });
    }

    // 2. Pixel analysis (sampling)
    const { data, info } = await image
      .raw()
      .toBuffer({ resolveWithObject: true });

    const pixels = data;
    const pixelCount = info.width * info.height;
    const sampleSize = Math.min(10000, pixelCount);
    const step = Math.floor(pixelCount / sampleSize);

    // Color histogram
    const colorCounts = new Map();
    let lowContrastPairs = 0;

    for (let i = 0; i < pixels.length; i += step * info.channels) {
      const r = pixels[i];
      const g = pixels[i + 1];
      const b = pixels[i + 2];

      // Bucket colors (8bit -> 4bit)
      const key = `${Math.floor(r / 16)},${Math.floor(g / 16)},${Math.floor(b / 16)}`;
      colorCounts.set(key, (colorCounts.get(key) || 0) + 1);
    }

    // 3. Detect low contrast regions
    // Check contrast of adjacent pixels
    const checkSize = Math.min(1000, Math.floor(pixels.length / info.channels) - info.width);

    for (let i = 0; i < checkSize; i += step) {
      const idx = i * info.channels;
      const nextIdx = (i + 1) * info.channels;

      if (nextIdx + 2 < pixels.length) {
        const c1 = [pixels[idx], pixels[idx + 1], pixels[idx + 2]];
        const c2 = [pixels[nextIdx], pixels[nextIdx + 1], pixels[nextIdx + 2]];

        // Different but low contrast = possible hidden text
        if (!arraysEqual(c1, c2) && isLowContrast(c1, c2)) {
          lowContrastPairs++;
        }
      }
    }

    result.stats.uniqueColors = colorCounts.size;
    result.stats.lowContrastPairs = lowContrastPairs;

    // 4. Detect suspicious patterns
    if (lowContrastPairs > 50) {
      result.warnings.push({
        type: 'low_contrast_detected',
        message: `Found ${lowContrastPairs} low-contrast pixel pairs`,
        severity: 'high',
        detail: 'May contain hidden text readable by OCR'
      });
      result.suspicious = true;
    }

    // 5. Check for known dangerous color combinations
    for (const pair of SUSPICIOUS_COLOR_PAIRS) {
      const fgKey = `${Math.floor(pair.fg[0] / 16)},${Math.floor(pair.fg[1] / 16)},${Math.floor(pair.fg[2] / 16)}`;
      const bgKey = `${Math.floor(pair.bg[0] / 16)},${Math.floor(pair.bg[1] / 16)},${Math.floor(pair.bg[2] / 16)}`;

      if (colorCounts.has(fgKey) && colorCounts.has(bgKey)) {
        const fgCount = colorCounts.get(fgKey);
        const bgCount = colorCounts.get(bgKey);

        // If both colors exist in sufficient quantity
        if (fgCount > 10 && bgCount > 100) {
          result.warnings.push({
            type: 'suspicious_color_pair',
            message: `Detected ${pair.name} combination`,
            severity: 'high',
            detail: 'Known hidden text attack pattern'
          });
          result.suspicious = true;
        }
      }
    }

  } catch (e) {
    result.scanned = false;
    result.error = e.message;
  }

  return result;
}

function arraysEqual(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Scan Base64 image
 */
async function scanBase64Image(base64String) {
  // Remove data:image/png;base64, prefix
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, '');
  const buffer = Buffer.from(base64Data, 'base64');
  return scanImage(buffer);
}

/**
 * Warning message for screenshots
 */
function getScreenshotWarning() {
  return {
    warning: 'Screenshots may contain hidden text visible only to AI/OCR',
    recommendations: [
      'Avoid using screenshots from untrusted sources',
      'Scan screenshots before processing with AI',
      'Be cautious of pages with unusual color schemes'
    ]
  };
}

/**
 * For testing: generate hidden text image
 */
async function createTestHiddenTextImage(text, width = 400, height = 100) {
  // light blue text on yellow background
  const svg = `
    <svg width="${width}" height="${height}">
      <rect width="100%" height="100%" fill="rgb(255,255,0)"/>
      <text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle"
            font-size="24" fill="rgb(173,216,230)">${text}</text>
    </svg>
  `;

  const buffer = await sharp(Buffer.from(svg))
    .png()
    .toBuffer();

  return buffer;
}

module.exports = {
  scanImage,
  scanBase64Image,
  getScreenshotWarning,
  createTestHiddenTextImage,
  isLowContrast,
  SUSPICIOUS_COLOR_PAIRS
};
