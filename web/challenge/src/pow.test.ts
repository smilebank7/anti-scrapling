import { describe, expect, it } from 'vitest';
import { leadingZeroBits } from './hash';
import { solvePow, verifyPow } from './pow';

describe('proof-of-work solver', () => {
  it('finds a nonce with the requested leading zero bits quickly', async () => {
    const started = performance.now();
    const solution = await solvePow('unit-test', 4, { max_nonce: 10_000, yield_every: 0 });

    expect(solution.difficulty).toBe(4);
    expect(solution.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifyPow('unit-test', solution.nonce, 4)).toBe(true);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it('counts leading zero bits across bytes', () => {
    expect(leadingZeroBits(new Uint8Array([0, 0x0f]))).toBe(12);
    expect(leadingZeroBits(new Uint8Array([0xff]))).toBe(0);
    expect(leadingZeroBits(new Uint8Array([0]))).toBe(8);
  });
});
