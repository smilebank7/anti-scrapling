import * as http from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Client } from '../src/client.js';
import type { Decision } from '../src/types.js';

const ALLOW_DECISION: Decision = {
  verdict: 'ALLOW',
  score: 0,
  signals: [],
  reasons: [],
  policy_name: 'default',
  timestamp: 1_000_000_000_000,
  request_id: 'test-req-1',
};

const DENY_DECISION: Decision = {
  verdict: 'DENY',
  score: 100,
  signals: [{ name: 'ja3_mismatch', score: 50, reason: 'JA3 mismatch', detail: {} }],
  reasons: ['bot_fingerprint'],
  policy_name: 'strict',
  timestamp: 1_000_000_000_001,
  request_id: 'test-req-2',
};

function startServer(
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

function jsonResponse(res: http.ServerResponse, body: unknown): void {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

describe('Client.decide', () => {
  it('returns parsed Decision on success', async () => {
    const { server, url } = await startServer((_req, res) => jsonResponse(res, ALLOW_DECISION));
    try {
      const client = new Client({ daemonUrl: url });
      const d = await client.decide({ method: 'GET', path: '/', host: 'example.com', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
      expect(d.verdict).toBe('ALLOW');
      expect(d.score).toBe(0);
      expect(d.request_id).toBe('test-req-1');
    } finally {
      await stopServer(server);
    }
  });

  it('sends correct JSON body to daemon', async () => {
    let body = '';
    const { server, url } = await startServer((req, res) => {
      req.on('data', (c) => { body += c; });
      req.on('end', () => jsonResponse(res, ALLOW_DECISION));
    });
    try {
      const client = new Client({ daemonUrl: url });
      await client.decide({
        method: 'POST', path: '/api/data', host: 'api.example.com',
        remote_ip: '10.0.0.1', headers: { 'user-agent': 'test/1.0' }, header_order: ['User-Agent'],
      });
      const parsed = JSON.parse(body) as Record<string, unknown>;
      expect(parsed['method']).toBe('POST');
      expect(parsed['path']).toBe('/api/data');
      expect(parsed['remote_ip']).toBe('10.0.0.1');
    } finally {
      await stopServer(server);
    }
  });

  it('parses DENY decision with signals', async () => {
    const { server, url } = await startServer((_req, res) => jsonResponse(res, DENY_DECISION));
    try {
      const client = new Client({ daemonUrl: url });
      const d = await client.decide({ method: 'GET', path: '/', host: 'example.com', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
      expect(d.verdict).toBe('DENY');
      expect(d.score).toBe(100);
      expect(d.signals).toHaveLength(1);
      expect(d.signals[0]?.name).toBe('ja3_mismatch');
      expect(d.reasons).toContain('bot_fingerprint');
    } finally {
      await stopServer(server);
    }
  });

  it('failOpen=true returns ALLOW when daemon is unreachable', async () => {
    const client = new Client({ daemonUrl: 'http://127.0.0.1:1', failOpen: true });
    const d = await client.decide({ method: 'GET', path: '/', host: 'x', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
    expect(d.verdict).toBe('ALLOW');
    expect(d.reasons).toContain('daemon_unavailable');
  });

  it('failOpen=false returns DENY when daemon is unreachable', async () => {
    const client = new Client({ daemonUrl: 'http://127.0.0.1:1', failOpen: false });
    const d = await client.decide({ method: 'GET', path: '/', host: 'x', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
    expect(d.verdict).toBe('DENY');
    expect(d.reasons).toContain('daemon_unavailable');
  });

  it('aborts after timeoutMs and respects failOpen', async () => {
    const { server, url } = await startServer((_req, _res) => {});
    try {
      const client = new Client({ daemonUrl: url, timeoutMs: 60, failOpen: true });
      const start = Date.now();
      const d = await client.decide({ method: 'GET', path: '/', host: 'x', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
      expect(Date.now() - start).toBeLessThan(1_000);
      expect(d.verdict).toBe('ALLOW');
      expect(d.reasons).toContain('daemon_unavailable');
    } finally {
      server.closeAllConnections?.();
      await stopServer(server);
    }
  });

  it('treats 4xx as error and applies failOpen', async () => {
    const { server, url } = await startServer((_req, res) => {
      res.writeHead(400);
      res.end('bad request');
    });
    try {
      const client = new Client({ daemonUrl: url, failOpen: true });
      const d = await client.decide({ method: 'GET', path: '/', host: 'x', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
      expect(d.verdict).toBe('ALLOW');
    } finally {
      await stopServer(server);
    }
  });

  it('treats 5xx as error and applies failClosed', async () => {
    const { server, url } = await startServer((_req, res) => {
      res.writeHead(503);
      res.end('unavailable');
    });
    try {
      const client = new Client({ daemonUrl: url, failOpen: false });
      const d = await client.decide({ method: 'GET', path: '/', host: 'x', remote_ip: '1.2.3.4', headers: {}, header_order: [] });
      expect(d.verdict).toBe('DENY');
    } finally {
      await stopServer(server);
    }
  });
});
