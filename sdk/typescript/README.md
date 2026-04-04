# HVT TypeScript SDK

Zero-dependency frontend/server SDK for HVT.

## Build

From the repo root:

```powershell
node scripts/build_hvt_typescript_sdk.mjs
```

The build copies `src/index.js` and `src/index.d.ts` into `dist/`.

## Usage

```ts
import { HVTClient } from "@hvt/sdk";

const client = new HVTClient({
  baseUrl: "http://localhost:8000",
});

const session = await client.auth.login({
  email: "owner@example.com",
  password: "password123",
});

client.setAccessToken(session.access);

const org = await client.organizations.current();
const users = await client.users.list({ page_size: 25 });
```

## Runtime Auth with API Keys

```ts
const client = new HVTClient({
  baseUrl: "http://localhost:8000",
  apiKey: "hvt_test_xxx",
});

const providers = await client.runtime.socialProviders();
const session = await client.runtime.login({
  email: "customer@example.com",
  password: "password123",
});
```

## Frontend Notes

- JWT takes priority over `X-API-Key` if both are sent. Do not send both at once.
- Cookie auth is supported. The client defaults to `credentials: "include"`.
- API keys are now scope-gated for reads. The UI should not assume any API key can read every control-plane endpoint.
- API keys and webhooks are project-aware. The UI should surface `project`, `project_name`, and `project_slug`.
- Runtime auth requires the `auth:runtime` scope.
- Launch posture is single-organization per user. The dashboard should not present multi-org switching yet.
