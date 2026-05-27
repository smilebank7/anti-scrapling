export interface DecisionRequest {
  method: string;
  path: string;
  host: string;
  remote_ip: string;
  headers: Record<string, string>;
  header_order: string[];
  ja3?: string;
  ja4?: string;
  token?: string;
}

export type Verdict = 'ALLOW' | 'CHALLENGE' | 'DENY';

export interface Signal {
  name: string;
  score: number;
  reason: string;
  detail?: Record<string, unknown>;
}

export interface Decision {
  verdict: Verdict;
  score: number;
  signals: Signal[];
  reasons: string[];
  policy_name: string;
  timestamp: number;
  request_id: string;
}
