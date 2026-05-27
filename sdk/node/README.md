# @anti-scrapling/node

Node.js SDK for the anti-scrapling firewall — Express and NestJS adapters.

## Requirements

- Node.js ≥ 18
- Anti-scrapling daemon accessible at the configured URL

> **Note:** The daemon serves `/v1/decide` on the admin port (`--admin-bind`, default `:9091`). Point `daemonUrl` at `http://<host>:9091`. The SDK gracefully degrades via `failOpen` if the daemon is unreachable.

## Install

```sh
npm install @anti-scrapling/node
```

## Express

```ts
import express from 'express';
import { antiScrapling } from '@anti-scrapling/node/express';

const app = express();

app.use(antiScrapling({
  daemonUrl: 'http://localhost:9091',
  timeoutMs: 200,
  failOpen: true,
}));

app.get('/', (req, res) => res.json({ hello: 'world' }));
app.listen(3000);
```

## NestJS

```ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AntiScraplingGuard } from '@anti-scrapling/node/nestjs';

@Module({
  providers: [
    {
      provide: APP_GUARD,
      useFactory: () => new AntiScraplingGuard({ daemonUrl: 'http://localhost:9091' }),
    },
  ],
})
export class AppModule {}
```

Apply `@Injectable()` from `@nestjs/common` when registering as a DI provider.

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `daemonUrl` | required | Base URL of the anti-scrapling daemon |
| `timeoutMs` | `200` | HTTP call timeout (ms) |
| `failOpen` | `true` | `true` = allow on daemon error; `false` = deny |
| `challengeUrl` | `/__as/challenge?origin=…` | Redirect target for CHALLENGE verdict |

## Verdicts

| Verdict | Behaviour |
|---------|-----------|
| `ALLOW` | Request proceeds |
| `CHALLENGE` | 302 redirect to challenge page |
| `DENY` | 403 with reason text |
