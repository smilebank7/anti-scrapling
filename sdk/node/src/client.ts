import type { Decision, DecisionRequest } from './types.js';

export interface ClientOptions {
  daemonUrl: string;
  timeoutMs?: number;
  failOpen?: boolean;
}

function fallback(failOpen: boolean): Decision {
  return {
    verdict: failOpen ? 'ALLOW' : 'DENY',
    score: failOpen ? 0 : 100,
    signals: [],
    reasons: ['daemon_unavailable'],
    policy_name: '',
    timestamp: 0,
    request_id: '',
  };
}

export class Client {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly failOpen: boolean;

  constructor(opts: ClientOptions) {
    this.url = opts.daemonUrl.replace(/\/$/, '') + '/v1/decide';
    this.timeoutMs = opts.timeoutMs ?? 200;
    this.failOpen = opts.failOpen ?? true;
  }

  async decide(req: DecisionRequest): Promise<Decision> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);

    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
        signal: ctrl.signal,
      });

      clearTimeout(timer);

      if (!res.ok) {
        throw new Error(`daemon ${res.status}`);
      }

      return (await res.json()) as Decision;
    } catch {
      clearTimeout(timer);
      return fallback(this.failOpen);
    }
  }
}
