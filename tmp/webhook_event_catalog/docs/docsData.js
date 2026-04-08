export const EXTERNAL_LINKS = {
  app: 'https://hvts.app',
  github: 'https://github.com/markodera/hvt',
  status: 'https://hvts.app/healthz/',
  schema: import.meta.env.VITE_API_SCHEMA_URL ?? '/schema.yaml',
};

export const SIDEBAR_SECTIONS = [
  {
    label: 'START HERE',
    items: [
      { title: 'What HVT is', path: '/introduction' },
      { title: 'Quickstart', path: '/quickstart' },
      { title: 'How HVT is structured', path: '/concepts' },
    ],
  },
  {
    label: 'MOST COMMON TASKS',
    items: [
      { title: 'Projects and API keys', path: '/guides/projects' },
      { title: 'Authentication flows', path: '/guides/auth' },
      { title: 'Runtime roles and permissions', path: '/guides/runtime-roles' },
      { title: 'SDK usage', path: '/guides/sdk' },
      { title: 'Webhooks', path: '/guides/webhooks' },
      { title: 'Audit logs', path: '/guides/audit-logs' },
    ],
  },
  {
    label: 'REFERENCE',
    items: [{ title: 'API overview and endpoints', path: '/api' }],
  },
  {
    label: 'SDK REFERENCE',
    items: [
      { title: 'HVTClient', path: '/sdk/hvtclient' },
      { title: 'auth methods', path: '/sdk/auth' },
      { title: 'Error handling', path: '/sdk/errors' },
    ],
  },
];

export const PAGE_META = {
  '/introduction': {
    anchors: [
      { id: 'overview', label: 'What HVT does' },
      { id: 'typical-flow', label: 'What teams do first' },
      { id: 'two-planes', label: 'Control plane and runtime' },
      { id: 'when-to-use-hvt', label: 'Self-host or hvts.app' },
    ],
    sample: {
      label: 'One-line model',
      code: 'Organisation -> Project -> API key -> Runtime request -> Token',
    },
  },
  '/quickstart': {
    anchors: [
      { id: 'what-you-will-have', label: 'What you will have at the end' },
      { id: 'create-account', label: 'Create your HVT account' },
      { id: 'create-organisation', label: 'Create an organisation' },
      { id: 'create-project', label: 'Create a project' },
      { id: 'issue-api-key', label: 'Issue an API key' },
      { id: 'install-sdk', label: 'Install the SDK' },
      { id: 'initialise-client', label: 'Connect your app' },
      { id: 'register-user', label: 'Create a user' },
      { id: 'login-user', label: 'Sign that user in' },
    ],
    sample: {
      label: 'Runtime client',
      code: `import { HVTClient } from 'hvt-sdk'

const hvt = new HVTClient({
  baseUrl: 'https://hvts.app',
  apiKey: 'hvt_live_...'
})`,
    },
  },
  '/concepts': {
    anchors: [
      { id: 'organisations', label: 'Organisation' },
      { id: 'projects', label: 'Project' },
      { id: 'api-key-and-token', label: 'API key and token' },
      { id: 'request-flow', label: 'One request through HVT' },
    ],
    sample: {
      label: 'Credential rule',
      code: 'API key = app boundary. Token = user identity inside that boundary.',
    },
  },
  '/guides/auth': {
    anchors: [
      { id: 'control-plane-auth', label: 'Dashboard sign-in' },
      { id: 'runtime-auth', label: 'App user sign-up and sign-in' },
      { id: 'social-auth', label: 'Social sign-in' },
      { id: 'refresh-logout', label: 'Refresh and logout' },
    ],
    sample: {
      label: 'Runtime auth',
      code: `await client.request('/api/v1/auth/runtime/register/', {
  method: 'POST',
  auth: 'apiKey',
  body: {
  email: 'user@example.com',
  password1: 'Strongpass123!',
  password2: 'Strongpass123!'
  }
})

await client.auth.runtimeLogin({
  email: 'user@example.com',
  password: 'Strongpass123!'
})`,
    },
  },
  '/guides/runtime-roles': {
    anchors: [
      { id: 'role-model', label: 'Keep the layers separate' },
      { id: 'define-permissions', label: 'Define permissions first' },
      { id: 'assign-roles', label: 'Choose assignment flow' },
      { id: 'runtime-flow', label: 'Register and sign in runtime users' },
      { id: 'read-access', label: 'Read live app access' },
      { id: 'enforce-access', label: 'Enforce in the app' },
      { id: 'common-pitfalls', label: 'Common mistakes' },
    ],
    sample: {
      label: 'Enforcement rule',
      code: `const canCheckout = permissions.includes('orders.create')

if (!permissions.includes('orders.read.own')) {
  return 403
}`,
    },
  },
  '/guides/projects': {
    anchors: [
      { id: 'project-boundary', label: 'Why projects matter' },
      { id: 'create-project', label: 'Create a project' },
      { id: 'issue-api-key', label: 'Issue a project key' },
      { id: 'social-config', label: 'Project social providers' },
    ],
    sample: {
      label: 'Create API key',
      code: `await client.organizations.createApiKey({
  name: 'Storefront backend',
  environment: 'live',
  project_id: '<project-id>',
  scopes: ['auth:runtime', 'users:read']
})`,
    },
  },
  '/guides/webhooks': {
    anchors: [
      { id: 'create-endpoint', label: 'Create an endpoint' },
      { id: 'deliveries', label: 'Deliveries and retries' },
      { id: 'event-catalogue', label: 'Event catalogue' },
      { id: 'api-key-expiry', label: 'API key expiry' },
      { id: 'signature', label: 'Signature verification' },
    ],
    sample: {
      label: 'Payload',
      code: `{
  "event": "user.created",
  "project_slug": "storefront-prod"
}`,
    },
  },
  '/guides/audit-logs': {
    anchors: [
      { id: 'what-gets-recorded', label: 'What gets recorded' },
      { id: 'filter-log', label: 'Filter the log' },
      { id: 'project-context', label: 'Project context' },
    ],
    sample: {
      label: 'List audit logs',
      code: `await client.organizations.listAuditLogs({
  event_type: 'user.login',
  success: true
})`,
    },
  },
  '/guides/sdk': {
    anchors: [
      { id: 'installation', label: 'Installation' },
      { id: 'initialisation', label: 'Create one shared client' },
      { id: 'auth-methods', label: 'Most-used auth methods' },
      { id: 'api-key-methods', label: 'API key methods' },
      { id: 'webhook-methods', label: 'Webhook methods' },
      { id: 'error-handling', label: 'Error handling' },
    ],
    sample: {
      label: 'Create once',
      code: `export const hvt = new HVTClient({
  baseUrl: import.meta.env.VITE_API_URL,
  apiKey: import.meta.env.VITE_HVT_API_KEY,
})`,
    },
  },
  '/sdk/hvtclient': {
    anchors: [
      { id: 'constructing-the-client', label: 'Constructing the client' },
      { id: 'auth-groups', label: 'Client groups' },
    ],
    sample: {
      label: 'Groups',
      code: 'client.auth\nclient.organizations\nclient.users',
    },
  },
  '/sdk/auth': {
    anchors: [
      { id: 'control-plane-methods', label: 'Control-plane methods' },
      { id: 'runtime-methods', label: 'Runtime methods' },
      { id: 'social-methods', label: 'Social methods' },
    ],
    sample: {
      label: 'Auth surface',
      code: 'login, me, refresh, register, runtimeLogin, runtimeGoogle, runtimeGithub, request(/api/v1/auth/runtime/register/)',
    },
  },
  '/sdk/errors': {
    anchors: [
      { id: 'hvt-api-error', label: 'HVTApiError' },
      { id: 'error-envelope', label: 'Error envelope' },
    ],
    sample: {
      label: 'Fields',
      code: 'status\ncode\ndetail\nbody',
    },
  },
};

export function getPageMeta(pathname) {
  return PAGE_META[pathname] ?? { anchors: [], sample: null };
}
