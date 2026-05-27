import { startBehaviorCollector } from './behavior';
import { collectFingerprintReport } from './fingerprint';
import { solvePow } from './pow';
import type { ChallengeParams, VerifyPayload } from './types';

const VERIFY_ENDPOINT = '/__as/verify';

void runChallenge();

async function runChallenge(): Promise<void> {
  const params = readChallengeParams();
  const powSolution = await solvePow(params.challenge_id, params.difficulty);
  const fingerprintReport = await collectFingerprintReport();

  startBehaviorCollector({
    session_id: params.challenge_id,
    interval_ms: params.beacon_interval_ms
  });

  const payload: VerifyPayload = {
    pow_solution: powSolution,
    fingerprint_report: fingerprintReport,
    challenge_id: params.challenge_id
  };

  const response = await fetch(VERIFY_ENDPOINT, {
    method: 'POST',
    credentials: 'same-origin',
    redirect: 'follow',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });

  await followVerifyResponse(response);
}

function readChallengeParams(): ChallengeParams {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="__as_challenge"]');
  const fallback = {
    challenge_id: meta?.dataset.challengeId || '',
    difficulty: Number(meta?.dataset.difficulty || 0),
    beacon_interval_ms: Number(meta?.dataset.beaconIntervalMs || 5000)
  };

  if (!meta?.content) {
    return fallback;
  }

  try {
    const parsed = JSON.parse(meta.content) as Partial<ChallengeParams>;
    return {
      challenge_id: String(parsed.challenge_id ?? fallback.challenge_id),
      difficulty: normalizeDifficulty(parsed.difficulty ?? fallback.difficulty),
      beacon_interval_ms: normalizeInterval(parsed.beacon_interval_ms ?? fallback.beacon_interval_ms)
    };
  } catch {
    return fallback;
  }
}

function normalizeDifficulty(value: unknown): number {
  const difficulty = Number(value);
  return Number.isFinite(difficulty) && difficulty >= 0 ? Math.floor(difficulty) : 0;
}

function normalizeInterval(value: unknown): number {
  const interval = Number(value);
  return Number.isFinite(interval) && interval > 0 ? Math.floor(interval) : 5000;
}

async function followVerifyResponse(response: Response): Promise<void> {
  if (response.redirected && response.url) {
    window.location.assign(response.url);
    return;
  }

  const redirectUrl = await redirectFromJson(response);
  if (redirectUrl) {
    window.location.assign(redirectUrl);
    return;
  }

  if (response.ok) {
    window.location.reload();
  }
}

async function redirectFromJson(response: Response): Promise<string> {
  try {
    const data = (await response.clone().json()) as { redirect_url?: string; redirect?: string };
    return data.redirect_url || data.redirect || '';
  } catch {
    return '';
  }
}
