import { Client } from './client.js';
import type { ClientOptions } from './client.js';
import type { DecisionRequest } from './types.js';

export interface NestExecutionContext {
  switchToHttp(): {
    getRequest<T = unknown>(): T;
    getResponse<T = unknown>(): T;
  };
  getType(): string;
}

export interface CanActivate {
  canActivate(context: NestExecutionContext): boolean | Promise<boolean>;
}

export interface NestGuardOptions extends ClientOptions {
  challengeUrl?: string;
}

type HttpResponse = {
  redirect(url: string): void;
  status(code: number): { send(body: string): void };
};

type HttpRequest = {
  method?: string;
  path?: string;
  hostname?: string;
  host?: string;
  originalUrl?: string;
  url?: string;
  rawHeaders?: string[];
  socket?: { remoteAddress?: string };
  headers?: Record<string, string | string[] | undefined>;
};

export class AntiScraplingGuard implements CanActivate {
  private readonly client: Client;
  private readonly opts: NestGuardOptions;

  constructor(opts: NestGuardOptions) {
    this.client = new Client(opts);
    this.opts = opts;
  }

  async canActivate(context: NestExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const req = http.getRequest<HttpRequest>();
    const res = http.getResponse<HttpResponse>();

    const rawHeaders = req.rawHeaders ?? [];
    const headers: Record<string, string> = {};
    const headerOrder: string[] = [];

    for (let i = 0; i < rawHeaders.length; i += 2) {
      const name = rawHeaders[i] ?? '';
      const value = rawHeaders[i + 1] ?? '';
      headers[name.toLowerCase()] = value;
      headerOrder.push(name);
    }

    const cookieHeader = (req.headers?.['cookie'] as string | undefined) ?? '';
    const tokenMatch = /(?:^|;\s*)__as_token=([^;]*)/.exec(cookieHeader);

    const dreq: DecisionRequest = {
      method: req.method ?? 'GET',
      path: req.path ?? '/',
      host: req.hostname ?? String(req.host ?? ''),
      remote_ip: req.socket?.remoteAddress ?? '',
      headers,
      header_order: headerOrder,
      token: tokenMatch?.[1] || undefined,
    };

    const decision = await this.client.decide(dreq);

    switch (decision.Verdict) {
      case 'ALLOW':
        return true;
      case 'CHALLENGE': {
        const origin = encodeURIComponent(String(req.originalUrl ?? req.url ?? '/'));
        const target = this.opts.challengeUrl ?? `/__as/challenge?origin=${origin}`;
        res.redirect(target);
        return false;
      }
      case 'DENY':
        res.status(403).send(decision.Reasons.join(', ') || 'Denied');
        return false;
      default:
        return true;
    }
  }
}
