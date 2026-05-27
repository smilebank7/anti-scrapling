import { describe, expect, it } from 'vitest';
import { canvasVariance, hashCanvasPixels } from './canvas';

describe('canvas hash helpers', () => {
  it('hashes pixel bytes deterministically', async () => {
    await expect(hashCanvasPixels(new Uint8Array([1, 2, 3]))).resolves.toBe(
      '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81'
    );
  });

  it('reports variance as the unique hash count', () => {
    expect(canvasVariance(['a', 'a', 'b'])).toBe(2);
  });
});
