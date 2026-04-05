import DocPage, { DocSection } from '../../components/DocPage';
import CodeBlock from '../../components/CodeBlock';
import Callout from '../../components/Callout';

const INSTALL = `npm install hvt-sdk`;

const INIT = `import { HVTApiError, HVTClient } from 'hvt-sdk'

export const hvt = new HVTClient({
  baseUrl: import.meta.env.VITE_API_URL,
  apiKey: import.meta.env.VITE_HVT_API_KEY,
})

// Create once, export it, and import it everywhere else`;

const AUTH_METHODS = `// Team members signing in to HVT
await hvt.auth.login({ email, password })

// End users of your app
await hvt.auth.register({
  email: 'user@example.com',
  password1: 'Strongpass123!',
  password2: 'Strongpass123!'
})
await hvt.auth.runtimeLogin({ email, password })

// Runtime social login
await hvt.auth.runtimeGoogle({ code, callback_url })
await hvt.auth.runtimeGithub({ code, callback_url })

await hvt.auth.refresh()
await hvt.auth.logout()`;

const API_KEY_METHODS = `await hvt.organizations.listApiKeys({ project: projectId })
await hvt.organizations.createApiKey({
  project_id: projectId,
  name: 'Storefront backend',
  scopes: ['auth:runtime', 'users:read'],
  environment: 'live'
})
await hvt.organizations.revokeApiKey(apiKeyId)`;

const WEBHOOK_METHODS = `await hvt.organizations.listWebhooks({ project: projectId })
await hvt.organizations.createWebhook({
  project_id: projectId,
  url: 'https://app.example.com/webhooks/hvt',
  events: ['user.created', 'user.login']
})
await hvt.organizations.updateWebhook(webhookId, {
  project_id: projectId,
  url: 'https://app.example.com/webhooks/hvt',
  events: ['user.created']
})
await hvt.organizations.deleteWebhook(webhookId)`;

const ERROR_HANDLING = `import { HVTApiError } from 'hvt-sdk'

try {
  await hvt.auth.runtimeLogin({
    email: 'user@example.com',
    password: 'wrongpassword',
  })
} catch (err) {
  if (err instanceof HVTApiError) {
    console.log(err.status)   // 401
    console.log(err.message)  // Invalid credentials
    console.log(err.code)     // auth_failed
  }
}`;

export default function SDKGuidePage() {
  return (
    <DocPage
      title="SDK usage"
      subtitle="The HVT TypeScript and JavaScript SDK is the simplest way to talk to the platform from your app. Create one client, reuse it everywhere, and let it handle the request plumbing."
      next={{ href: '/sdk/hvtclient', label: 'HVTClient reference' }}
    >
      <DocSection id="installation" title="1. Installation">
        <p>Install the SDK in the app or service that needs to call HVT.</p>
        <CodeBlock code={INSTALL} language="bash" />
      </DocSection>

      <DocSection id="initialisation" title="2. Create one shared client">
        <p>
          Instantiate the HVT client once, export it, and import that shared instance everywhere else. Do not create a new client inside each component or request handler.
        </p>
        <CodeBlock code={INIT} language="javascript" />
      </DocSection>

      <DocSection id="auth-methods" title="3. Most-used auth methods">
        <p>
          The auth surface includes both dashboard auth for your team and runtime auth for the users of your app. The naming keeps those two jobs separate so you do not accidentally mix them.
        </p>
        <CodeBlock code={AUTH_METHODS} language="javascript" />
      </DocSection>

      <DocSection id="api-key-methods" title="4. API key methods">
        <p>
          API key operations live under <code className="font-code">hvt.organizations</code> because keys are issued inside the current organisation context.
        </p>
        <CodeBlock code={API_KEY_METHODS} language="javascript" />
      </DocSection>

      <DocSection id="webhook-methods" title="5. Webhook methods">
        <p>
          Webhook endpoints also live under <code className="font-code">hvt.organizations</code>. You can list them, create them, update them, and delete them while keeping the project boundary explicit in the payload.
        </p>
        <CodeBlock code={WEBHOOK_METHODS} language="javascript" />
      </DocSection>

      <DocSection id="error-handling" title="6. Error handling">
        <CodeBlock code={ERROR_HANDLING} language="javascript" />
        <div style={{ height: 16 }} />
        <Callout type="info" title="Promise-based API">
          All SDK methods return Promises and throw <strong>HVTApiError</strong> on failure. Always wrap network calls in <strong>try/catch</strong> so you can handle status codes and API error codes cleanly.
        </Callout>
      </DocSection>
    </DocPage>
  );
}

