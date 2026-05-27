import { bytesToHex, leadingZeroBits, sha256Bytes, utf8 } from './hash';
import type { PowSolution } from './types';

export interface PowOptions {
  max_nonce?: number;
  yield_every?: number;
}

const DEFAULT_MAX_NONCE = 20_000_000;
const DEFAULT_YIELD_EVERY = 256;

export async function solvePow(
  challenge_id: string,
  difficulty: number,
  options: PowOptions = {}
): Promise<PowSolution> {
  if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > 256) {
    throw new Error('invalid_pow_difficulty');
  }

  const maxNonce = options.max_nonce ?? DEFAULT_MAX_NONCE;
  const yieldEvery = options.yield_every ?? DEFAULT_YIELD_EVERY;
  const started = performance.now();

  for (let nonce = 0; nonce <= maxNonce; nonce += 1) {
    const digest = await sha256Bytes(utf8(`${challenge_id}${nonce}`));

    if (leadingZeroBits(digest) >= difficulty) {
      return {
        nonce,
        hash: bytesToHex(digest),
        difficulty,
        duration_ms: Math.round(performance.now() - started)
      };
    }

    if (yieldEvery > 0 && nonce > 0 && nonce % yieldEvery === 0) {
      await yieldToBrowser();
    }
  }

  throw new Error('pow_nonce_exhausted');
}

export async function verifyPow(challenge_id: string, nonce: number, difficulty: number): Promise<boolean> {
  const digest = await sha256Bytes(utf8(`${challenge_id}${nonce}`));
  return leadingZeroBits(digest) >= difficulty;
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
