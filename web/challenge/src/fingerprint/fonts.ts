import type { FontsProbe } from '../types';

const FONT_CANDIDATES = [
  'Arial',
  'Arial Black',
  'Arial Narrow',
  'Avenir',
  'Calibri',
  'Cambria',
  'Candara',
  'Century Gothic',
  'Comic Sans MS',
  'Consolas',
  'Courier New',
  'DejaVu Sans',
  'DejaVu Serif',
  'Fira Sans',
  'Franklin Gothic Medium',
  'Georgia',
  'Gill Sans',
  'Helvetica',
  'Helvetica Neue',
  'Impact',
  'Liberation Sans',
  'Liberation Serif',
  'Lucida Console',
  'Menlo',
  'Monaco',
  'Noto Sans',
  'Noto Serif',
  'Optima',
  'Palatino',
  'Roboto',
  'Segoe UI',
  'SF Pro Display',
  'SF Pro Text',
  'Tahoma',
  'Times New Roman',
  'Trebuchet MS',
  'Ubuntu',
  'Verdana',
  'Wingdings',
  'Zapfino',
  'Apple Color Emoji',
  'Segoe UI Emoji',
  'Noto Color Emoji',
  'Symbol',
  'MS Gothic',
  'Meiryo',
  'Yu Gothic',
  'PingFang SC',
  'Hiragino Sans',
  'Droid Sans',
  'Source Sans Pro',
  'System Font'
];

const EXPECTED_BUNDLED: Record<string, string[]> = {
  mac: ['Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'Avenir', 'Gill Sans', 'Apple Color Emoji', 'PingFang SC', 'Hiragino Sans'],
  windows: ['Arial', 'Calibri', 'Cambria', 'Consolas', 'Courier New', 'Georgia', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Verdana'],
  linux: ['DejaVu Sans', 'DejaVu Serif', 'Liberation Sans', 'Liberation Serif', 'Noto Sans', 'Noto Serif', 'Ubuntu']
};

const BASE_FONTS = ['monospace', 'serif', 'sans-serif'];
const TEST_TEXT = 'mmmmmmmmmmlliWQ@#✓😃';

export function collectFonts(): FontsProbe {
  const detected = FONT_CANDIDATES.filter((font) => isFontDetected(font));
  const detectedSet = new Set(detected);
  const expected = EXPECTED_BUNDLED[osFamily()] || [];

  return {
    detected_count: detected.length,
    detected,
    missing_os_bundled: expected.filter((font) => !detectedSet.has(font))
  };
}

function isFontDetected(font: string): boolean {
  return fontSetCheck(font) || canvasMeasureCheck(font);
}

function fontSetCheck(font: string): boolean {
  try {
    return Boolean(document.fonts?.check(`16px "${font}"`));
  } catch {
    return false;
  }
}

function canvasMeasureCheck(font: string): boolean {
  try {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) {
      return false;
    }

    return BASE_FONTS.some((base) => {
      context.font = `72px ${base}`;
      const baseline = context.measureText(TEST_TEXT).width;
      context.font = `72px "${font}", ${base}`;
      return Math.abs(context.measureText(TEST_TEXT).width - baseline) > 0.1;
    });
  } catch {
    return false;
  }
}

function osFamily(): string {
  const platform = navigator.platform.toLowerCase();
  const ua = navigator.userAgent.toLowerCase();
  if (platform.includes('mac') || ua.includes('mac os')) {
    return 'mac';
  }
  if (platform.includes('win') || ua.includes('windows')) {
    return 'windows';
  }
  if (platform.includes('linux') || ua.includes('linux') || ua.includes('x11')) {
    return 'linux';
  }
  return '';
}
