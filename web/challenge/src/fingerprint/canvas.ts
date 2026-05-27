import { sha256Hex, uniqueCount } from '../hash';
import type { CanvasProbe } from '../types';

const WIDTH = 280;
const HEIGHT = 80;

export async function collectCanvas(): Promise<CanvasProbe> {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = WIDTH;
    canvas.height = HEIGHT;
    const context = canvas.getContext('2d', { willReadFrequently: true });

    if (!context) {
      return { hashes: [], variance: 0 };
    }

    const hashes: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      hashes.push(await renderCanvasHash(context));
    }

    return { hashes, variance: canvasVariance(hashes) };
  } catch {
    return { hashes: [], variance: 0 };
  }
}

export async function hashCanvasPixels(pixels: Uint8Array | Uint8ClampedArray): Promise<string> {
  const copy = new Uint8Array(pixels.byteLength);
  copy.set(pixels);
  return sha256Hex(copy);
}

export function canvasVariance(hashes: readonly string[]): number {
  return uniqueCount(hashes);
}

async function renderCanvasHash(context: CanvasRenderingContext2D): Promise<string> {
  context.clearRect(0, 0, WIDTH, HEIGHT);

  const gradient = context.createLinearGradient(0, 0, WIDTH, HEIGHT);
  gradient.addColorStop(0, '#123456');
  gradient.addColorStop(0.5, '#9ad8ff');
  gradient.addColorStop(1, '#f06c64');
  context.fillStyle = gradient;
  context.fillRect(0, 0, WIDTH, HEIGHT);

  context.fillStyle = 'rgba(255, 255, 255, 0.86)';
  context.font = '17px Arial, Helvetica, sans-serif';
  context.fillText('Anti-Scrapling ✓ 😃 𝌆', 12, 30);
  context.font = '13px Georgia, serif';
  context.fillText('fingerprint canvas probe', 16, 56);
  context.strokeStyle = 'rgba(20, 20, 20, 0.72)';
  context.lineWidth = 1.25;
  context.beginPath();
  context.moveTo(7.5, 70.5);
  context.bezierCurveTo(72.25, 12.75, 170.5, 88.5, 270.5, 18.25);
  context.stroke();

  const pixels = context.getImageData(0, 0, WIDTH, HEIGHT).data;
  return hashCanvasPixels(pixels);
}
