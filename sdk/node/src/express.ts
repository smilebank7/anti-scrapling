import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { Client } from './client.js';
import type { ClientOptions } from './client.js';
import type { DecisionRequest } from './types.js';

export interface ExpressOptions extends ClientOptions {
  challengeUrl?: string;
}

export function antiScrapling(opts: ExpressOptions): RequestHandler {
  const client = new Client(opts);

  return (req: Request, res: Response, next: NextFunction) => {
    void (async () => {
      const headers: Record<string, string> = {};
      const headerOrder: string[] = [];

      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i] ?? '';
        const value = req.rawHeaders[i + 1] ?? '';
        headers[name.toLowerCase()] = value;
        headerOrder.push(name);
      }

      const cookieHeader = (req.headers['cookie'] as string | undefined) ?? '';
      const tokenMatch = /(?:^|;\s*)__as_pass=([^;]*)/.exec(cookieHeader);

      const dreq: DecisionRequest = {
        method: req.method,
        path: req.path,
        host: req.hostname,
        remote_ip: req.socket.remoteAddress ?? '',
        headers,
        header_order: headerOrder,
        token: tokenMatch?.[1] || undefined,
      };

      const decision = await client.decide(dreq);

      switch (decision.verdict) {
        case 'ALLOW':
          next();
          break;
        case 'CHALLENGE': {
          const origin = encodeURIComponent(req.originalUrl);
          const target = opts.challengeUrl ?? `/__as/challenge?origin=${origin}`;
          res.redirect(302, target);
          break;
        }
        case 'DENY':
          res.status(403).type('text/plain').send(decision.reasons.join(', ') || 'Denied');
          break;
        default:
          next();
      }
    })().catch(next);
  };
}
