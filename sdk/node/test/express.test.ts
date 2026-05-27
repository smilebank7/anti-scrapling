import * as http from 'node:http';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { antiScrapling } from '../src/express.js';
import type { Decision } from '../src/types.js';

function makeDecision(verdict: Decision['verdict'], reasons: string[] = []): Decision {
  return {
    verdict: verdict,
    score: verdict === 'DENY' ? 100 : 0,
    signals: [],
    reasons: reasons,
    policy_name: 'test',
    timestamp: 0,
    request_id: 'test',
  };
}

function startDaemon(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ server: http.Server; url: string }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

function stopServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

function verdict(d: Decision): (req: http.IncomingMessage, res: http.ServerResponse) => void {
  return (_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(d));
  };
}

describe('antiScrapling Express middleware', () => {
  it('ALLOW: passes request to next handler', async () => {
    const { server: daemon, url } = await startDaemon(verdict(makeDecision('ALLOW')));
    try {
      const app = express();
      app.use(antiScrapling({ daemonUrl: url }));
      app.get('/', (_req, res) => { res.json({ ok: true }); });

      const res = await request(app).get('/');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true });
    } finally {
      await stopServer(daemon);
    }
  });

  it('DENY: returns 403 with reason text', async () => {
    const { server: daemon, url } = await startDaemon(
      verdict(makeDecision('DENY', ['bot_fingerprint', 'ja3_mismatch'])),
    );
    try {
      const app = express();
      app.use(antiScrapling({ daemonUrl: url }));
      app.get('/', (_req, res) => { res.json({ ok: true }); });

      const res = await request(app).get('/');
      expect(res.status).toBe(403);
      expect(res.text).toContain('bot_fingerprint');
    } finally {
      await stopServer(daemon);
    }
  });

  it('CHALLENGE: redirects to default challenge URL', async () => {
    const { server: daemon, url } = await startDaemon(verdict(makeDecision('CHALLENGE')));
    try {
      const app = express();
      app.use(antiScrapling({ daemonUrl: url }));
      app.get('/protected', (_req, res) => { res.json({ ok: true }); });

      const res = await request(app).get('/protected');
      expect(res.status).toBe(302);
      expect(res.headers['location']).toMatch(/\/__as\/challenge/);
    } finally {
      await stopServer(daemon);
    }
  });

  it('CHALLENGE: uses custom challengeUrl', async () => {
    const { server: daemon, url } = await startDaemon(verdict(makeDecision('CHALLENGE')));
    try {
      const app = express();
      app.use(antiScrapling({ daemonUrl: url, challengeUrl: '/verify' }));
      app.get('/', (_req, res) => { res.json({ ok: true }); });

      const res = await request(app).get('/');
      expect(res.status).toBe(302);
      expect(res.headers['location']).toBe('/verify');
    } finally {
      await stopServer(daemon);
    }
  });

  it('daemon unreachable + failOpen: request passes through', async () => {
    const app = express();
    app.use(antiScrapling({ daemonUrl: 'http://127.0.0.1:1', failOpen: true }));
    app.get('/', (_req, res) => { res.json({ ok: true }); });

    const res = await request(app).get('/');
    expect(res.status).toBe(200);
  });

  it('daemon unreachable + failClosed: request denied', async () => {
    const app = express();
    app.use(antiScrapling({ daemonUrl: 'http://127.0.0.1:1', failOpen: false }));
    app.get('/', (_req, res) => { res.json({ ok: true }); });

    const res = await request(app).get('/');
    expect(res.status).toBe(403);
  });
});
