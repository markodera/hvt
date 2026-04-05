import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  BookOpen,
  Boxes,
  Building2,
  ExternalLink,
  GitBranchPlus,
  Github,
  KeyRound,
  LockKeyhole,
  Menu,
  ScrollText,
  ShieldCheck,
  Users,
  Webhook,
  X,
} from 'lucide-react';

import { HvtLogoMark, Logo } from '@/components/Logo';
import { API_URL, CHANGELOG_URL, DOCS_URL, GITHUB_URL, SITE_URL, STATUS_URL } from '@/lib/appLinks';



const DOT_GRID_STYLE = {
  backgroundImage:
    'url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2718%27 height=%2718%27 viewBox=%270 0 18 18%27%3E%3Ccircle cx=%279%27 cy=%279%27 r=%271.5%27 fill=%27%2327272a%27 /%3E%3C/svg%3E")',
  backgroundRepeat: 'repeat',
};

const featureStripItems = [
  'Open-source auth',
  'Project-scoped runtime',
  'Google and GitHub login',
  'API keys',
  'Audit history',
  'Webhooks',
];

const chainNodes = ['Organisation', 'Project', 'API key', 'Runtime', 'Audit'];

const controlPlaneNodes = [
  {
    title: 'Organisation',
    description: 'Create the ownership boundary for one company, team, or product.',
  },
  {
    title: 'Projects',
    description: 'Give each app or environment its own signup rules, runtime context, and keys.',
  },
  {
    title: 'API keys',
    description: 'Connect each backend without reusing one shared secret across every app.',
  },
  {
    title: 'Invitations and roles',
    description: 'Invite owners, admins, and members with the right level of access.',
  },
  {
    title: 'Social config',
    description: 'Enable Google or GitHub only on the projects that should expose it.',
  },
];

const runtimeNodes = [
  {
    title: 'Register',
    description: 'Let end users create accounts with email and password.',
  },
  {
    title: 'Login',
    description: 'Sign returning users into the right project with the right rules.',
  },
  {
    title: 'Verification and reset',
    description: 'Handle verification and password reset flows without bolting on another service.',
  },
  {
    title: 'Social login',
    description: 'Offer Google or GitHub when it is enabled for that specific project.',
  },
  {
    title: 'Webhooks',
    description: 'Send account and security events to the rest of your stack.',
  },
  {
    title: 'Audit events',
    description: 'Keep a clear history of sign-ins, invites, key changes, and account activity.',
  },
];

const features = [
  {
    icon: ShieldCheck,
    title: 'Open-source and self-hostable',
    description:
      'Run HVT yourself under AGPL v3 or use the hosted product first. The model stays the same either way.',
  },
  {
    icon: KeyRound,
    title: 'Project-scoped runtime',
    description:
      'Keep apps and environments separated with their own project settings, runtime auth context, and API keys.',
  },
  {
    icon: GitBranchPlus,
    title: 'API keys for each app',
    description:
      'Connect your backend with the right key for the right project instead of sharing one credential everywhere.',
  },
  {
    icon: Users,
    title: 'Google and GitHub per project',
    description:
      'Turn social login on where you need it and keep provider config tied to the right app.',
  },
  {
    icon: Webhook,
    title: 'Team roles and invites',
    description:
      'Invite teammates, control who owns what, and keep staff access separate from customer auth.',
  },
  {
    icon: ScrollText,
    title: 'Audit logs and webhooks',
    description:
      'See what changed and push important events into the rest of your stack when something happens.',
  },
];

function upsertMeta(selector, factory, updater) {
  let element = document.head.querySelector(selector);
  if (!element) {
    element = factory();
    document.head.appendChild(element);
  }
  updater(element);
}

function Kw({ children }) {
  return <span className="text-[#c4b5fd]">{children}</span>;
}

function PathToken({ children }) {
  return <span className="text-white">{children}</span>;
}

function Str({ children }) {
  return <span className="text-[#a78bfa]">{children}</span>;
}

function Prop({ children }) {
  return <span className="text-[#e4e4e7]">{children}</span>;
}

function Num({ children }) {
  return <span className="text-[#ddd6fe]">{children}</span>;
}

function Comment({ children }) {
  return <span className="text-[#71717a]">{children}</span>;
}

function CodeLine({ children }) {
  return <div className="whitespace-pre">{children}</div>;
}

const codeTabs = {
  runtime: {
    label: 'Runtime flow',
    caption:
      'The runtime side stays tied to the organisation, project, and API key you configured.',
    code: (
      <>
        <CodeLine>1. Your app sends users to the right project.</CodeLine>
        <CodeLine>2. A visitor creates an account or signs in.</CodeLine>
        <CodeLine>3. HVT checks that project's auth rules.</CodeLine>
        <CodeLine>4. HVT signs them in and issues the right claims.</CodeLine>
        <CodeLine>5. Verification, reset, and social auth stay in the same flow.</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>Runtime features</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>- Sign up</CodeLine>
        <CodeLine>- Sign in</CodeLine>
        <CodeLine>- Email verification</CodeLine>
        <CodeLine>- Password reset</CodeLine>
        <CodeLine>- Google and GitHub login</CodeLine>
      </>
    ),
  },
  key: {
    label: 'Control plane',
    caption:
      'Your team configures the structure once, then every app and user flow inherits it.',
    code: (
      <>
        <CodeLine>1. Create an organisation.</CodeLine>
        <CodeLine>2. Add a project for each app or environment.</CodeLine>
        <CodeLine>3. Invite teammates with the right role.</CodeLine>
        <CodeLine>4. Configure email login, Google, or GitHub.</CodeLine>
        <CodeLine>5. Issue the API key your backend will use.</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>What your team manages</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>- Organisations and projects</CodeLine>
        <CodeLine>- Staff access</CodeLine>
        <CodeLine>- API keys</CodeLine>
        <CodeLine>- Social login settings</CodeLine>
        <CodeLine>- Signup rules</CodeLine>
      </>
    ),
  },
  webhook: {
    label: 'Events and history',
    caption:
      'HVT keeps a history for your team and can notify the rest of your stack when something changes.',
    code: (
      <>
        <CodeLine>When something changes, HVT records it and can send it out.</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>Examples</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>- New user created</CodeLine>
        <CodeLine>- Password changed</CodeLine>
        <CodeLine>- API key issued or revoked</CodeLine>
        <CodeLine>- Teammate invited</CodeLine>
        <CodeLine>- Login activity recorded</CodeLine>
        <CodeLine></CodeLine>
        <CodeLine>You also get built-in audit history for your team.</CodeLine>
      </>
    ),
  },
};

function Wordmark() {
  return (
    <Link to="/" className="inline-flex items-center gap-3">
      <HvtLogoMark className="h-9 w-9 shrink-0" />
      <div className="leading-none">
        <div className="font-mono text-[1.08rem] font-bold tracking-[-0.03em] text-white">HVT</div>
        <div className="mt-1 text-[11px] text-[#71717a]">hvts.app</div>
      </div>
    </Link>
  );
}

function NavLink({ href, children, mobile = false, onClick }) {
  return (
    <a
      href={href}
      onClick={onClick}
      className={`transition-colors hover:text-white ${mobile ? 'block py-2 text-base text-[#d4d4d8]' : 'text-sm text-[#a1a1aa]'}`}
    >
      {children}
    </a>
  );
}

function ChainDiagram({ compact = false }) {
  return (
    <div
      className={`rounded-[18px] border border-[#27272a] bg-[#111111]/88 ${compact ? 'p-4' : 'p-5'} transition-[border-color,transform,box-shadow] duration-200 hover:border-[rgba(124,58,237,0.6)]`}
      style={{
        animation: compact ? undefined : 'heroFloat 7.5s ease-in-out infinite',
        boxShadow: compact ? undefined : '0 18px 48px rgba(0,0,0,0.28)',
      }}
    >
      <div className="flex flex-wrap items-center gap-2 sm:gap-3">
        {chainNodes.map((node, index) => (
          <div key={node} className="contents">
            <div
              className={`rounded-full border border-[#3f3f46] bg-[#18181b] px-4 py-2 ${compact ? 'text-xs' : 'text-sm'} font-medium text-[#e4e4e7]`}
              style={{
                animation: compact ? undefined : `heroFadeUp 0.7s ease-out ${0.18 + index * 0.08}s both`,
              }}
            >
              {node}
            </div>
            {index < chainNodes.length - 1 ? (
              <div className={`flex items-center ${compact ? 'w-8' : 'w-10 sm:w-14'}`}>
                <div className="relative h-px w-full overflow-hidden rounded-full bg-[#7c3aed]/15">
                  <div
                    className="absolute inset-0 bg-[#7c3aed]/50"
                    style={{ animation: `connectorPulse 2.8s ease-in-out ${index * 0.2}s infinite` }}
                  />
                </div>
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function FeatureStrip() {
  const loopItems = [...featureStripItems, ...featureStripItems];

  return (
    <div
      className="relative overflow-hidden rounded-full border border-[#27272a] bg-[#111111]/88 px-4 py-3"
      style={{
        WebkitMaskImage: 'linear-gradient(to right, transparent, black 8%, black 92%, transparent)',
        maskImage: 'linear-gradient(to right, transparent, black 8%, black 92%, transparent)',
      }}
    >
      <div className="hidden items-center justify-center gap-3 md:flex">
        {featureStripItems.map((item, index) => (
          <div key={item} className="flex items-center gap-3 text-sm text-[#71717a]">
            {index > 0 ? <span className="text-[#3f3f46]">·</span> : null}
            <span>{item}</span>
          </div>
        ))}
      </div>
      <div className="md:hidden">
        <div className="flex min-w-max gap-8" style={{ animation: 'featureMarquee 18s linear infinite' }}>
          {loopItems.map((item, index) => (
            <div key={`${item}-${index}`} className="flex items-center gap-2 text-sm whitespace-nowrap text-[#71717a]">
              <span>{item}</span>
              <span className="text-[#3f3f46]">·</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PlaneNode({ title, description, accent = false }) {
  return (
    <div className={`rounded-lg border px-4 py-4 transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] ${accent ? 'border-[#3f3f46] bg-[#18181b]' : 'border-[#27272a] bg-[#111111]'}`}>
      <div className="text-sm font-semibold text-white">{title}</div>
      <p className="mt-2 text-sm leading-6 text-[#a1a1aa]">{description}</p>
    </div>
  );
}

export default function Landing() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('runtime');
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    document.title = 'HVT | Open-source auth infrastructure for products and teams';

    upsertMeta('meta[name="description"]', () => {
      const meta = document.createElement('meta');
      meta.name = 'description';
      return meta;
    }, (meta) => {
      meta.content = 'HVT is open-source auth infrastructure for organisations, projects, API keys, runtime auth, audit history, and webhooks.';
    });

    upsertMeta('meta[property="og:title"]', () => {
      const meta = document.createElement('meta');
      meta.setAttribute('property', 'og:title');
      return meta;
    }, (meta) => {
      meta.setAttribute('content', 'HVT | Open-source auth infrastructure for products and teams');
    });

    upsertMeta('meta[property="og:description"]', () => {
      const meta = document.createElement('meta');
      meta.setAttribute('property', 'og:description');
      return meta;
    }, (meta) => {
      meta.setAttribute('content', 'Open-source auth infrastructure for organisations, projects, runtime auth, API keys, audit history, and webhooks.');
    });

    upsertMeta('meta[property="og:url"]', () => {
      const meta = document.createElement('meta');
      meta.setAttribute('property', 'og:url');
      return meta;
    }, (meta) => {
      meta.setAttribute('content', `${SITE_URL}/`);
    });

    upsertMeta('meta[name="theme-color"]', () => {
      const meta = document.createElement('meta');
      meta.name = 'theme-color';
      return meta;
    }, (meta) => {
      meta.content = '#0a0a0a';
    });

    let canonical = document.head.querySelector('link[rel="canonical"]');
    if (!canonical) {
      canonical = document.createElement('link');
      canonical.rel = 'canonical';
      document.head.appendChild(canonical);
    }
    canonical.href = `${SITE_URL}/`;
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <style>{`
        @keyframes heroFadeUp {
          0% { opacity: 0; transform: translateY(18px); }
          100% { opacity: 1; transform: translateY(0); }
        }

        @keyframes heroFloat {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-6px); }
        }

        @keyframes heroGlowPulse {
          0%, 100% { opacity: 0.72; transform: scale(1); }
          50% { opacity: 1; transform: scale(1.04); }
        }

        @keyframes featureMarquee {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }

        @keyframes connectorPulse {
          0%, 100% { opacity: 0.16; }
          50% { opacity: 0.4; }
        }
      `}</style>

      <header
        className={`sticky top-0 z-50 border-b transition-all ${
          scrolled ? 'border-[#27272a] bg-[#0a0a0a]/88 backdrop-blur-xl' : 'border-transparent bg-[#0a0a0a]/72 backdrop-blur-md'
        }`}
      >
        <div className="mx-auto grid h-[60px] max-w-7xl grid-cols-[auto_1fr_auto] items-center gap-6 px-4 sm:px-6 lg:px-8">
          <div className="justify-self-start">
            <Wordmark />
          </div>

          <nav className="hidden items-center justify-center gap-8 justify-self-center md:flex">
            <a href="#features" className="text-sm text-[#a1a1aa] transition-colors duration-150 hover:text-white">
              Features
            </a>
            <a href={DOCS_URL} target="_blank" rel="noreferrer" className="text-sm text-[#a1a1aa] transition-colors duration-150 hover:text-white">
              Docs
            </a>
            <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="text-sm text-[#a1a1aa] transition-colors duration-150 hover:text-white">
              GitHub
            </a>
          </nav>

          <div className="hidden items-center gap-3 justify-self-end md:flex">
            <Link to="/login" className="px-2 py-2 text-sm font-medium text-[#d4d4d8] transition-colors duration-150 hover:text-white">
              Sign in
            </Link>
            <Link
              to="/signup"
              className="rounded-full border border-[#3f3f46] bg-[#18181b] px-4 py-2 text-sm font-semibold text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.04),0_10px_24px_rgba(0,0,0,0.26)] transition-[border-color,background-color] duration-150 hover:border-[rgba(124,58,237,0.45)] hover:bg-[#1d1d22]"
            >
              Get started free
            </Link>
          </div>

          <button
            type="button"
            onClick={() => setMenuOpen((value) => !value)}
            className="inline-flex h-10 w-10 items-center justify-center justify-self-end rounded-md border border-[#27272a] bg-[#111111] text-[#d4d4d8] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] hover:text-white md:hidden"
            aria-label="Toggle navigation"
          >
            {menuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>

        {menuOpen && (
          <div className="border-t border-[#27272a] bg-[#0a0a0a]/96 md:hidden">
            <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-4 sm:px-6">
              <NavLink href="#features" mobile onClick={() => setMenuOpen(false)}>Features</NavLink>
              <NavLink href={DOCS_URL} mobile onClick={() => setMenuOpen(false)}>Docs</NavLink>
              <NavLink href={GITHUB_URL} mobile onClick={() => setMenuOpen(false)}>GitHub</NavLink>
              <Link to="/login" onClick={() => setMenuOpen(false)} className="mt-2 rounded-md border border-[#27272a] px-4 py-3 text-center text-sm font-medium text-[#d4d4d8]">
                Sign in
              </Link>
              <Link to="/signup" onClick={() => setMenuOpen(false)} className="rounded-md bg-[#7c3aed] px-4 py-3 text-center text-sm font-semibold text-white">
                Get started free
              </Link>
            </div>
          </div>
        )}
      </header>

      <main id="top">
        <section className="relative overflow-hidden border-b border-[#27272a]">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                'radial-gradient(circle at top center, rgba(124,58,237,0.15), transparent 58%)',
              animation: 'heroGlowPulse 8s ease-in-out infinite',
            }}
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0"
            style={{
              ...DOT_GRID_STYLE,
              WebkitMaskImage:
                'linear-gradient(to bottom, rgba(0,0,0,0.98) 0%, rgba(0,0,0,0.94) 58%, transparent 100%)',
              maskImage:
                'linear-gradient(to bottom, rgba(0,0,0,0.98) 0%, rgba(0,0,0,0.94) 58%, transparent 100%)',
            }}
          />

          <div className="relative mx-auto max-w-7xl px-4 py-28 sm:px-6 lg:px-8 lg:py-32">
            <div className="max-w-5xl">
              <div
                className="inline-flex items-center rounded-full border border-[#27272a] bg-[#111111]/88 px-3 py-1 text-xs font-medium uppercase tracking-[0.18em] text-[#a78bfa]"
                style={{ animation: 'heroFadeUp 0.6s ease-out 0.05s both' }}
              >
                Open-source auth infrastructure for products and teams
              </div>
              <h1
                className="mt-8 max-w-5xl text-4xl font-extrabold leading-tight tracking-[-0.05em] text-white sm:text-5xl lg:text-7xl"
                style={{ animation: 'heroFadeUp 0.7s ease-out 0.12s both' }}
              >
                Open-source auth infrastructure for customer accounts, team access, and runtime auth.
              </h1>
              <p
                className="mt-6 max-w-3xl text-base leading-8 text-[#a1a1aa] sm:text-lg"
                style={{ animation: 'heroFadeUp 0.7s ease-out 0.2s both' }}
              >
                HVT gives you one model for organisation, project, API key, and runtime auth. Start on hvts.app
                now, or self-host later under AGPL v3 without changing how your product is structured.
              </p>

              <div className="mt-8 max-w-3xl" style={{ animation: 'heroFadeUp 0.8s ease-out 0.28s both' }}>
                <ChainDiagram />
              </div>

              <div className="mt-10 flex flex-col gap-3 sm:flex-row" style={{ animation: 'heroFadeUp 0.8s ease-out 0.36s both' }}>
                <Link to="/signup" className="inline-flex items-center justify-center rounded-md bg-[#7c3aed] px-5 py-3 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#6d28d9]">
                  Get started free
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
                <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="inline-flex items-center justify-center rounded-md border border-[#27272a] px-5 py-3 text-sm font-semibold text-[#d4d4d8] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] hover:text-white">
                  View on GitHub
                </a>
              </div>

              <div className="mt-8 max-w-3xl" style={{ animation: 'heroFadeUp 0.8s ease-out 0.44s both' }}>
                <FeatureStrip />
              </div>
            </div>
          </div>
        </section>

        <section className="border-b border-[#27272a]">
          <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="text-sm font-medium text-[#a78bfa]">At a glance</div>
              <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em] text-white sm:text-4xl">
                One model from setup to sign-in.
              </h2>
              <p className="mt-4 text-base leading-8 text-[#a1a1aa]">
                HVT is split into a control plane for your team and a runtime plane for your apps and users. That
                makes the product easier to reason about when you are setting it up and when people are actually
                signing in.
              </p>
            </div>

            <div className="mt-10 rounded-[18px] border border-[#27272a] bg-[#111111] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)]">
              <div className="flex flex-wrap gap-2 border-b border-[#27272a] px-4 py-4 sm:px-6">
                {Object.entries(codeTabs).map(([key, tab]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setActiveTab(key)}
                    className={`rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150 ${activeTab === key ? 'bg-[#7c3aed] text-white' : 'bg-[#18181b] text-[#a1a1aa] hover:text-white'}`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
              <div className="px-4 py-5 sm:px-6">
                <p className="mb-4 text-sm text-[#a1a1aa]">{codeTabs[activeTab].caption}</p>
                <div className="overflow-x-auto rounded-[14px] border border-[#27272a] bg-[#0a0a0a] px-4 py-4 font-mono text-[13px] leading-6 text-[#d4d4d8] sm:px-5">
                  {codeTabs[activeTab].code}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="system" className="scroll-mt-24 border-b border-[#27272a]">
          <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="text-sm font-medium text-[#a78bfa]">How it works</div>
              <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em] text-white sm:text-4xl">One control plane. One runtime plane.</h2>
              <p className="mt-4 text-base leading-8 text-[#a1a1aa]">
                Your team configures organisations, projects, keys, invites, and social login. Your app then uses
                that structure to register users, sign them in, issue tokens, and track what changed.
              </p>
            </div>

            <div className="mt-10 grid gap-6 lg:grid-cols-[minmax(0,1fr)_164px_minmax(0,1fr)] lg:items-stretch">
              <div className="rounded-[18px] border border-[#27272a] bg-[#111111] p-6 transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)]">
                <div className="flex items-center gap-3">
                  <Building2 className="h-5 w-5 text-[#a78bfa]" />
                    <div>
                      <div className="text-xs uppercase tracking-[0.18em] text-[#71717a]">For your team</div>
                    <div className="mt-1 text-lg font-semibold text-white">Configure organisations, projects, keys, and staff access</div>
                  </div>
                </div>
                <div className="mt-6 space-y-3">
                  {controlPlaneNodes.map((node) => (
                    <PlaneNode key={node.title} title={node.title} description={node.description} />
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-center lg:block">
                <div className="flex justify-center lg:hidden">
                  <div className="rounded-full border border-[#3f3f46] bg-[#18181b] px-4 py-2 text-xs font-medium uppercase tracking-[0.18em] text-[#a78bfa]">
                    Shared access rules
                  </div>
                </div>
                <div className="hidden h-full flex-col items-center lg:flex">
                  <div className="min-h-10 w-px flex-1 bg-[#27272a]" />
                  <div className="my-4 whitespace-nowrap rounded-full border border-[#3f3f46] bg-[#18181b] px-4 py-2 text-xs font-medium uppercase tracking-[0.18em] text-[#a78bfa]">
                    Shared access rules
                  </div>
                  <div className="min-h-10 w-px flex-1 bg-[#27272a]" />
                </div>
              </div>

              <div className="rounded-[18px] border border-[#3f3f46] bg-[#18181b] p-6 transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)]">
                <div className="flex items-center gap-3">
                  <Boxes className="h-5 w-5 text-[#a78bfa]" />
                    <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-[#71717a]">For your users</div>
                    <div className="mt-1 text-lg font-semibold text-white">Register users, sign them in, and track what happens</div>
                  </div>
                </div>
                <div className="mt-6 space-y-3">
                  {runtimeNodes.map((node) => (
                    <PlaneNode key={node.title} title={node.title} description={node.description} accent />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="features" className="scroll-mt-24 border-b border-[#27272a]">
          <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="text-sm font-medium text-[#a78bfa]">Why HVT feels different</div>
              <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em] text-white sm:text-4xl">The model is the product, not an add-on.</h2>
              <p className="mt-4 text-base leading-8 text-[#a1a1aa]">
                HVT is built around one explicit chain: organisation, project, API key, runtime auth, audit logs,
                and webhooks. That is the default shape of the product, not an enterprise extra.
              </p>
            </div>
            <div className="mt-10 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {features.map((feature) => {
                const Icon = feature.icon;
                return (
                  <div key={feature.title} className="group rounded-[18px] border border-[#27272a] bg-[#111111] p-6 transition-[border-color,box-shadow,transform] duration-150 hover:border-[rgba(124,58,237,0.6)]">
                    <div className="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-[#18181b] text-[#a78bfa] transition-shadow duration-150 group-hover:shadow-[0_0_18px_rgba(124,58,237,0.24)]">
                      <Icon className="h-5 w-5" />
                    </div>
                    <h3 className="mt-5 text-lg font-semibold text-white">{feature.title}</h3>
                    <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">{feature.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section id="pricing" className="scroll-mt-24 border-b border-[#27272a]">
          <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="text-sm font-medium text-[#a78bfa]">Start here</div>
              <h2 className="mt-4 text-3xl font-bold tracking-[-0.03em] text-white sm:text-4xl">Start hosted. Self-host when you need to.</h2>
              <p className="mt-4 text-base leading-8 text-[#a1a1aa]">
                The hosted and self-hosted paths follow the same product model. You do not need to relearn the stack
                later if you decide to run it yourself.
              </p>
            </div>

            <div className="mt-10 grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
              <div className="flex flex-col rounded-[18px] border border-[#27272a] bg-[#111111] p-6 transition-[border-color,box-shadow] duration-150 hover:border-[rgba(124,58,237,0.6)]">
                <div>
                  <div className="text-xs uppercase tracking-[0.18em] text-[#71717a]">Self-hosted</div>
                  <div className="mt-4 space-y-4 text-sm leading-7 text-[#d4d4d8]">
                    <p>
                      HVT is open-source, so your team can run the auth stack on your own infrastructure when you want full control.
                    </p>
                    <p>
                      That is the right path if you want to own the code, review the stack, or keep deployment inside
                      your own environment.
                    </p>
                  </div>
                </div>
                <div className="mt-auto pt-6 flex flex-col gap-3 sm:flex-row">
                  <Link
                    to="/signup"
                    className="inline-flex items-center justify-center rounded-md bg-[#7c3aed] px-4 py-3 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#6d28d9]"
                  >
                    Get started free
                  </Link>
                  <a
                    href={GITHUB_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center justify-center rounded-md border border-[#27272a] px-4 py-3 text-sm font-semibold text-[#d4d4d8] transition-colors duration-150 hover:border-[rgba(124,58,237,0.6)] hover:text-white"
                  >
                    View on GitHub
                  </a>
                </div>
              </div>

              <div className="relative flex flex-col overflow-hidden rounded-[18px] border border-[rgba(124,58,237,0.4)] bg-[#18181b] p-6 shadow-[0_0_30px_rgba(124,58,237,0.15)] transition-[border-color,box-shadow] duration-150 hover:border-[rgba(124,58,237,0.8)] hover:shadow-[0_0_40px_rgba(124,58,237,0.25)]">
                <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-[#7c3aed] opacity-20 blur-[80px]"></div>
                <div className="relative z-10 flex h-full flex-col">
                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-[#a78bfa] font-semibold">Hosted by HVT</div>
                    <h3 className="mt-4 bg-gradient-to-r from-white to-[#a78bfa] bg-clip-text text-xl font-bold text-transparent">Free to try today</h3>
                    <p className="mt-3 text-sm leading-7 text-[#a1a1aa]">
                      You can create an account, test login flows, invite teammates, and understand the product model
                      before you set up infrastructure.
                    </p>
                    <div className="mt-6 rounded-2xl border border-[rgba(124,58,237,0.2)] bg-[#111111] px-4 py-4 text-sm text-[#d4d4d8]">
                      Hosted pricing is coming soon. Right now, <strong className="text-[#a78bfa]">you can sign up and use HVT for free while you evaluate the product.</strong>
                    </div>
                  </div>
                  <div className="mt-auto pt-6">
                    <Link
                      to="/signup"
                      className="inline-flex w-full items-center justify-center rounded-md bg-[#7c3aed] px-4 py-3 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#6d28d9]"
                    >
                      Create free account
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="bg-[#0a0a0a]">
        <div className="mx-auto grid max-w-7xl gap-10 px-4 py-12 sm:px-6 md:grid-cols-2 xl:grid-cols-[1.1fr_1fr_0.7fr] lg:px-8">
          <div>
            <Logo href="/" />
            <p className="mt-4 max-w-sm text-sm leading-7 text-[#a1a1aa]">
              Open-source auth infrastructure for organisations, projects, runtime auth, audit history, and webhooks.
            </p>
          </div>

          <div className="grid gap-8 sm:grid-cols-2">
            <div>
              <div className="text-xs uppercase tracking-[0.18em] text-[#71717a]">Links</div>
              <div className="mt-4 space-y-3">
                <a href={DOCS_URL} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <BookOpen className="h-4 w-4" /> Docs
                </a>
                <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <Github className="h-4 w-4" /> GitHub
                </a>
                <Link to="/privacy-policy" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <ShieldCheck className="h-4 w-4" /> Privacy Policy
                </Link>
                <Link to="/terms-of-service" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <ScrollText className="h-4 w-4" /> Terms of Service
                </Link>
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.18em] text-[#71717a]">Ops</div>
              <div className="mt-4 space-y-3">
                <a href={CHANGELOG_URL} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <ExternalLink className="h-4 w-4" /> Changelog
                </a>
                <a href={STATUS_URL} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-sm text-[#a1a1aa] transition-colors hover:text-white">
                  <ExternalLink className="h-4 w-4" /> API health
                </a>
              </div>
            </div>
          </div>

          <div className="flex items-start md:col-span-2 xl:col-span-1 xl:justify-end">
            <div className="inline-flex items-center gap-2 rounded-full border border-[#27272a] bg-[#111111] px-3 py-2 text-xs font-medium uppercase tracking-[0.16em] text-[#a1a1aa]">
              <LockKeyhole className="h-3.5 w-3.5 text-[#a78bfa]" /> AGPL v3 Licensed
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}


