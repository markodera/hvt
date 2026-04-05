import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
    ArrowRight,
    Building2,
    Check,
    Code2,
    Globe,
    Lock,
    RefreshCw,
    ScrollText,
    Shield,
    Terminal,
    Users,
    Webhook,
    Zap,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

const proofPoints = [
    'Project-scoped API keys and token claims',
    'Per-project social provider configuration',
    'Invite flow, RBAC, audit logs, and webhooks',
];

const fitCards = [
    {
        title: 'You keep the tenant boundary',
        description: 'Organizations handle team ownership. Projects handle app and environment boundaries. Tokens and runtime auth stay in that context.',
    },
    {
        title: 'You do not lose the operational trail',
        description: 'Every meaningful action can be traced through audit logs, webhooks, and explicit project or org context.',
    },
    {
        title: 'You can self-host without dumbing the model down',
        description: 'This is not a login widget pretending to be something bigger. It is auth infrastructure built for a real control plane and runtime plane.',
    },
];

const featureCards = [
    {
        icon: RefreshCw,
        title: 'JWT hardening',
        description: 'Access and refresh flows carry org and project claims so tenant checks survive token decode, not just queryset filters.',
    },
    {
        icon: Building2,
        title: 'Org and project model',
        description: 'Organizations map to teams. Projects map to apps or environments. Keys, social config, and runtime auth can stay aligned to that model.',
    },
    {
        icon: Globe,
        title: 'Project social auth',
        description: 'Google and GitHub can be configured per project, so one broken provider setup does not poison every tenant.',
    },
    {
        icon: Users,
        title: 'Invitations and roles',
        description: 'Owners invite admins and members into the control plane with explicit acceptance flow instead of silent membership side effects.',
    },
    {
        icon: Webhook,
        title: 'Runtime event hooks',
        description: 'Login, registration, API key activity, and user changes can feed downstream systems without inventing a second event pipeline.',
    },
    {
        icon: ScrollText,
        title: 'Operational evidence',
        description: 'Audit events are separated cleanly across org, project, and invitation actions so the logs explain what actually happened.',
    },
];

const launchChecklist = [
    'Create an organization for your team',
    'Create a project for each app or environment',
    'Issue a project API key for your backend',
    'Configure social providers only for that project',
    'Use runtime register, login, refresh, and social endpoints',
    'Observe audit logs and webhook deliveries when something changes',
];

const codeExamples = {
    runtime: `POST /api/v1/auth/runtime/login/
X-API-Key: hvt_test_xxxxxxxxx
Content-Type: application/json

{
  "email": "customer@example.com",
  "password": "Strongpass123!"
}

200 OK
Set-Cookie: auth-token=...
Set-Cookie: refresh-token=...

{
  "user": {
    "email": "customer@example.com",
    "role": "member",
    "project_slug": "storefront-prod"
  }
}`,
    control: `POST /api/v1/organizations/current/projects/
Authorization: Bearer <owner-jwt>
Content-Type: application/json

{
  "name": "Storefront Prod",
  "slug": "storefront-prod",
  "allow_signup": true
}

POST /api/v1/organizations/current/keys/
Authorization: Bearer <owner-jwt>
Content-Type: application/json

{
  "name": "Storefront Backend",
  "environment": "live",
  "project_id": "<project-id>",
  "scopes": ["read:org", "write:users"]
}`,
};

function Hero() {
    return (
        <section className="relative overflow-hidden border-b border-border">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(124,58,237,0.22),transparent_32%),radial-gradient(circle_at_bottom_right,rgba(34,197,94,0.12),transparent_26%)]" />
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] [background-size:32px_32px] opacity-30" />

            <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 lg:py-32">
                <div className="grid gap-14 lg:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)] lg:items-center">
                    <div>
                        <div className="inline-flex items-center gap-2 rounded-full border border-primary/25 bg-primary/10 px-4 py-2 text-sm font-medium text-primary">
                            <Shield className="h-4 w-4" />
                            Open-source auth infrastructure for serious product teams
                        </div>

                        <h1 className="mt-8 max-w-4xl text-4xl font-extrabold leading-[1.02] tracking-tight text-text-primary sm:text-5xl lg:text-7xl">
                            HVT gives developers the auth boundary they actually need.
                        </h1>

                        <p className="mt-6 max-w-2xl text-lg leading-relaxed text-text-secondary sm:text-xl">
                            Build the control plane for your team, run the auth runtime for your apps, and keep tenant isolation explicit all the way down to keys, projects, tokens, social auth, and audit trails.
                        </p>

                        <div className="mt-10 flex flex-col gap-4 sm:flex-row">
                            <Button size="lg" asChild className="px-8 text-base font-semibold">
                                <Link to="/register">
                                    Build with HVT
                                    <ArrowRight className="ml-2 h-4 w-4" />
                                </Link>
                            </Button>
                            <Button size="lg" variant="outline" asChild className="px-8 text-base font-semibold">
                                <a href="https://github.com" target="_blank" rel="noopener noreferrer">
                                    Read the code
                                </a>
                            </Button>
                        </div>

                        <div className="mt-10 grid gap-3 sm:grid-cols-3">
                            {proofPoints.map((point) => (
                                <div key={point} className="rounded-2xl border border-border bg-bg-secondary/80 p-4 text-sm leading-relaxed text-text-secondary shadow-[0_12px_40px_rgba(0,0,0,0.18)]">
                                    <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-full bg-primary/12 text-primary">
                                        <Check className="h-4 w-4" />
                                    </div>
                                    {point}
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="space-y-5">
                        <div className="overflow-hidden rounded-3xl border border-border bg-bg-secondary shadow-[0_28px_80px_rgba(0,0,0,0.28)]">
                            <div className="flex items-center gap-2 border-b border-border bg-bg-tertiary px-5 py-4">
                                <div className="h-3 w-3 rounded-full bg-danger/70" />
                                <div className="h-3 w-3 rounded-full bg-warning/70" />
                                <div className="h-3 w-3 rounded-full bg-success/70" />
                                <span className="ml-3 text-xs font-mono text-text-muted">runtime-auth.log</span>
                            </div>
                            <div className="space-y-4 p-5 font-mono text-sm text-text-secondary">
                                <div>
                                    <p className="text-primary">POST /auth/runtime/login</p>
                                    <p className="mt-1">project: storefront-prod</p>
                                    <p>api_key: hvt_live_a13f9e2c</p>
                                </div>
                                <div className="rounded-2xl border border-border bg-bg-tertiary/60 p-4">
                                    <p className="text-text-primary">issued claims</p>
                                    <p className="mt-2">org_id: org_75b08bf5</p>
                                    <p>project_id: prj_3c0227</p>
                                    <p>role: member</p>
                                </div>
                                <div className="grid gap-3 sm:grid-cols-2">
                                    <div className="rounded-2xl border border-border bg-bg-tertiary/60 p-4">
                                        <p className="text-text-primary">control plane</p>
                                        <p className="mt-2 text-xs">owners, admins, invites, projects, keys</p>
                                    </div>
                                    <div className="rounded-2xl border border-border bg-bg-tertiary/60 p-4">
                                        <p className="text-text-primary">runtime plane</p>
                                        <p className="mt-2 text-xs">signup, login, social auth, refresh, webhooks</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="grid gap-4 sm:grid-cols-2">
                            <div className="rounded-2xl border border-border bg-bg-secondary/85 p-5">
                                <p className="text-xs font-semibold uppercase tracking-[0.24em] text-text-muted">Built for</p>
                                <p className="mt-3 text-lg font-semibold text-text-primary">Multi-tenant SaaS, ecommerce, internal platforms</p>
                            </div>
                            <div className="rounded-2xl border border-primary/25 bg-primary/10 p-5">
                                <p className="text-xs font-semibold uppercase tracking-[0.24em] text-primary">Promise</p>
                                <p className="mt-3 text-lg font-semibold text-text-primary">Developers should know exactly which org, project, key, and user context is active.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}

function WhyHVT() {
    return (
        <section id="why-hvt" className="py-24">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="max-w-3xl">
                    <p className="text-xs font-semibold uppercase tracking-[0.3em] text-primary">Why developers stay</p>
                    <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-text-primary sm:text-5xl">
                        This is for teams that want auth to behave like infrastructure, not a black box.
                    </h2>
                </div>

                <div className="mt-12 grid gap-6 lg:grid-cols-3">
                    {fitCards.map((card) => (
                        <div key={card.title} className="rounded-3xl border border-border bg-bg-secondary p-7 shadow-[0_16px_50px_rgba(0,0,0,0.18)]">
                            <p className="text-lg font-semibold text-text-primary">{card.title}</p>
                            <p className="mt-4 text-sm leading-7 text-text-secondary">{card.description}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}

function SystemModel() {
    return (
        <section id="system" className="border-y border-border bg-bg-secondary py-24">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="text-center">
                    <p className="text-xs font-semibold uppercase tracking-[0.3em] text-primary">System model</p>
                    <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-text-primary sm:text-5xl">
                        Two planes. One platform. Clear boundaries.
                    </h2>
                    <p className="mx-auto mt-5 max-w-3xl text-lg leading-relaxed text-text-secondary">
                        HVT works when the developer control plane and the auth runtime plane are both explicit. That is the difference between a toy auth layer and something your team can launch on.
                    </p>
                </div>

                <div className="mt-14 grid gap-6 lg:grid-cols-[1fr_auto_1fr] lg:items-stretch">
                    <div className="rounded-3xl border border-border bg-bg-primary p-8">
                        <div className="flex items-center gap-3">
                            <Building2 className="h-6 w-6 text-primary" />
                            <h3 className="text-xl font-bold text-text-primary">Developer control plane</h3>
                        </div>
                        <ul className="mt-6 space-y-4 text-sm leading-7 text-text-secondary">
                            <li>Create organizations for teams.</li>
                            <li>Create projects for apps or environments.</li>
                            <li>Issue API keys tied to project context.</li>
                            <li>Invite admins and members with explicit acceptance.</li>
                            <li>Configure social providers per project.</li>
                        </ul>
                    </div>

                    <div className="hidden items-center justify-center lg:flex">
                        <div className="flex h-16 w-16 items-center justify-center rounded-full border border-primary/25 bg-primary/10">
                            <Zap className="h-6 w-6 text-primary" />
                        </div>
                    </div>

                    <div className="rounded-3xl border border-primary/25 bg-primary/10 p-8">
                        <div className="flex items-center gap-3">
                            <Terminal className="h-6 w-6 text-primary" />
                            <h3 className="text-xl font-bold text-text-primary">Auth runtime plane</h3>
                        </div>
                        <ul className="mt-6 space-y-4 text-sm leading-7 text-text-secondary">
                            <li>Register and login end users under the right org and project.</li>
                            <li>Issue access and refresh tokens with tenant claims.</li>
                            <li>Run social auth only where provider config is valid.</li>
                            <li>Emit audit events and webhook deliveries when state changes.</li>
                            <li>Reject cross-tenant requests before data leaks happen.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    );
}

function Features() {
    return (
        <section id="features" className="py-24">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
                    <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.3em] text-primary">What ships with HVT</p>
                        <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-text-primary sm:text-5xl">
                            The pieces developers normally end up rebuilding anyway.
                        </h2>
                        <p className="mt-5 text-lg leading-relaxed text-text-secondary">
                            You should not have to bolt on tenancy, invitations, runtime auth, provider config, logging, and event delivery after choosing an auth layer. HVT is built around those realities from the start.
                        </p>
                    </div>

                    <div className="grid gap-5 md:grid-cols-2">
                        {featureCards.map((feature) => (
                            <div key={feature.title} className="rounded-3xl border border-border bg-bg-secondary p-6 shadow-[0_14px_40px_rgba(0,0,0,0.15)]">
                                <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/10 text-primary">
                                    <feature.icon className="h-5 w-5" />
                                </div>
                                <h3 className="mt-5 text-lg font-semibold text-text-primary">{feature.title}</h3>
                                <p className="mt-3 text-sm leading-7 text-text-secondary">{feature.description}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </section>
    );
}

function IntegrationSection() {
    const [tab, setTab] = useState('runtime');

    return (
        <section id="integration" className="border-y border-border bg-bg-secondary py-24">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="grid gap-10 lg:grid-cols-[0.88fr_1.12fr] lg:items-start">
                    <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.3em] text-primary">How integration feels</p>
                        <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-text-primary sm:text-5xl">
                            The launch path is concrete.
                        </h2>
                        <p className="mt-5 text-lg leading-relaxed text-text-secondary">
                            HVT is easiest to understand when you picture the exact developer path: create org, create project, mint key, configure providers, then point your app at the runtime endpoints.
                        </p>

                        <div className="mt-8 rounded-3xl border border-border bg-bg-primary p-6">
                            <p className="text-sm font-semibold uppercase tracking-[0.22em] text-text-muted">Launch checklist</p>
                            <ul className="mt-5 space-y-4 text-sm leading-7 text-text-secondary">
                                {launchChecklist.map((item) => (
                                    <li key={item} className="flex gap-3">
                                        <span className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary">
                                            <Check className="h-3.5 w-3.5" />
                                        </span>
                                        <span>{item}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>

                    <div className="rounded-3xl border border-border bg-bg-primary shadow-[0_24px_70px_rgba(0,0,0,0.2)]">
                        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border px-6 py-5">
                            <div>
                                <p className="text-lg font-semibold text-text-primary">Developer surface</p>
                                <p className="mt-1 text-sm text-text-secondary">Switch between control-plane setup and runtime auth.</p>
                            </div>
                            <div className="flex gap-2 rounded-full bg-bg-secondary p-1">
                                <button
                                    type="button"
                                    onClick={() => setTab('runtime')}
                                    className={`rounded-full px-4 py-2 text-sm font-medium transition-colors ${tab === 'runtime' ? 'bg-primary text-white' : 'text-text-secondary hover:text-text-primary'}`}
                                >
                                    Runtime auth
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setTab('control')}
                                    className={`rounded-full px-4 py-2 text-sm font-medium transition-colors ${tab === 'control' ? 'bg-primary text-white' : 'text-text-secondary hover:text-text-primary'}`}
                                >
                                    Control plane
                                </button>
                            </div>
                        </div>

                        <div className="border-b border-border px-6 py-4 text-xs uppercase tracking-[0.26em] text-text-muted">
                            {tab === 'runtime' ? 'runtime-auth.http' : 'control-plane.http'}
                        </div>
                        <pre className="overflow-x-auto px-6 py-6 text-sm leading-7 text-text-secondary">
                            <code>{codeExamples[tab]}</code>
                        </pre>
                    </div>
                </div>
            </div>
        </section>
    );
}

function ClosingSection() {
    return (
        <section className="py-24">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="overflow-hidden rounded-[32px] border border-primary/20 bg-[linear-gradient(135deg,rgba(124,58,237,0.18),rgba(11,17,32,0.96)_42%,rgba(11,17,32,0.96))] p-10 shadow-[0_30px_90px_rgba(0,0,0,0.28)] sm:p-14">
                    <div className="grid gap-10 lg:grid-cols-[1fr_auto] lg:items-end">
                        <div>
                            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-white/8 text-primary">
                                <Lock className="h-7 w-7" />
                            </div>
                            <h2 className="mt-8 max-w-3xl text-3xl font-extrabold tracking-tight text-text-primary sm:text-5xl">
                                If you care about tenant boundaries, debugging evidence, and owning your auth stack, you are in the right place.
                            </h2>
                            <p className="mt-5 max-w-2xl text-lg leading-relaxed text-text-secondary">
                                HVT is for developers who want auth to be explicit, testable, and explainable when the product gets real.
                            </p>
                        </div>

                        <div className="flex flex-col gap-4 sm:flex-row lg:flex-col">
                            <Button size="lg" asChild className="px-8 text-base font-semibold">
                                <Link to="/register">
                                    Start building
                                    <ArrowRight className="ml-2 h-4 w-4" />
                                </Link>
                            </Button>
                            <Button size="lg" variant="outline" asChild className="px-8 text-base font-semibold">
                                <a href="https://github.com" target="_blank" rel="noopener noreferrer">
                                    Inspect the repo
                                </a>
                            </Button>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}

export function LandingPage() {
    return (
        <>
            <Hero />
            <WhyHVT />
            <SystemModel />
            <Features />
            <IntegrationSection />
            <ClosingSection />
        </>
    );
}

