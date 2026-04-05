import DocPage, { DocSection } from '../components/DocPage';

function PlainCard({ title, children }) {
  return (
    <div style={{ border: '1px solid #27272a', borderRadius: '10px', background: '#111111', padding: '18px' }}>
      <div style={{ marginBottom: '10px', color: '#ffffff', fontSize: '15px', fontWeight: 600 }}>{title}</div>
      <div className="docs-content">{children}</div>
    </div>
  );
}

export default function IntroductionPage() {
  return (
    <DocPage
      title="What is HVT?"
      subtitle="HVT is the account system behind your product. Your team configures the boundary once, and your app uses that boundary for signup, login, social auth, tokens, audit logs, and webhooks."
      next={{ href: '/quickstart', label: 'Quickstart' }}
    >
      <DocSection id="overview" title="What HVT does">
        <p>
          HVT is open-source authentication infrastructure. Instead of building your own account system from scratch, you create an organisation, create a project for each app or environment, issue an API key for that project, and let HVT handle the auth flow for that app.
        </p>
        <p>
          In practice, that means HVT can register users, sign them in, refresh tokens, run social login, emit audit events, and send webhooks while keeping the organisation and project context attached to every runtime action.
        </p>
        <p>
          If you want the shortest plain-English explanation, it is this: <strong>HVT runs the login system for your app and keeps the business boundary around that app clear.</strong>
        </p>
      </DocSection>

      <DocSection id="typical-flow" title="What teams do first">
        <ol>
          <li>Your team creates an organisation in HVT.</li>
          <li>Your team creates a project for the app or environment you want to protect.</li>
          <li>Your team issues an API key for that project.</li>
          <li>Your app sends signup, login, social auth, or token refresh requests to HVT using that project context.</li>
          <li>HVT returns users and tokens, and records what happened through audit events and webhooks.</li>
        </ol>
      </DocSection>

      <DocSection id="two-planes" title="Control plane and runtime">
        <p>
          HVT is easiest to understand when you split it into two halves.
        </p>
        <div style={{ display: 'grid', gap: '16px', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
          <PlainCard title="Control plane">
            <p>Your team signs in here.</p>
            <p>You create organisations, create projects, issue API keys, invite teammates, and configure social providers.</p>
          </PlainCard>
          <PlainCard title="Runtime plane">
            <p>Your app uses this part.</p>
            <p>Your users sign up, log in, use social auth, refresh tokens, trigger webhooks, and generate audit events through this runtime surface.</p>
          </PlainCard>
        </div>
      </DocSection>

      <DocSection id="when-to-use-hvt" title="Self-host or use hvts.app">
        <div style={{ display: 'grid', gap: '16px', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
          <PlainCard title="Self-host HVT when">
            <p>You want full code ownership, you need to audit how auth works, or you want to run the platform on your own infrastructure.</p>
          </PlainCard>
          <PlainCard title="Use hvts.app when">
            <p>You want the same organisation, project, and runtime model, but you do not want to operate the infrastructure yourself.</p>
          </PlainCard>
        </div>
      </DocSection>
    </DocPage>
  );
}

