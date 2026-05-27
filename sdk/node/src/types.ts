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
  Name: string;
  Score: number;
  Reason: string;
  Detail?: Record<string, unknown>;
}

export interface Decision {
  Verdict: Verdict;
  Score: number;
  Signals: Signal[];
  Reasons: string[];
  PolicyName: string;
  Timestamp: number;
  RequestID: string;
}
