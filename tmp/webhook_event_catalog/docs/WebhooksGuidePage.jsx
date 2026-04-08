import DocPage, { DocSection } from '../../components/DocPage';
import CodeBlock from '../../components/CodeBlock';

const CREATE_WEBHOOK = `await client.organizations.createWebhook({
  project_id: '<project-id>',
  url: 'https://app.example.com/webhooks/hvt',
  events: ['user.created', 'org.invitation.accepted', 'api_key.expired'],
  description: 'Storefront auth events'
})`;

const DELIVERIES = `await client.organizations.listWebhookDeliveries('<webhook-id>')`;

const PAYLOAD = `{
  "event": "user.created",
  "delivery_id": "<delivery-uuid>",
  "organization_id": "<org-uuid>",
  "project_id": "<project-uuid>",
  "project_slug": "storefront-prod",
  "data": {
    "user_id": "<user-uuid>",
    "email": "customer@example.com"
  }
}`;

const EVENT_CATALOGUE = `user.created
user.updated
user.deleted
user.login
user.role.changed
api_key.created
api_key.expired
api_key.revoked
org.invitation.created
org.invitation.accepted
org.invitation.revoked
org.invitation.resent
project.created
project.updated
project.deleted
project.social_provider.created
project.social_provider.updated
project.social_provider.deleted`;

const EXPIRY_SWEEP = `python manage.py emit_api_key_expiry_webhooks
# run this on a schedule if you want time-based expiry notifications
# to be emitted even when nobody uses the expired key`;

export default function WebhooksGuidePage() {
  return (
    <DocPage
      title="Webhooks"
      subtitle="HVT webhooks are project-aware and designed to let downstream systems see which runtime boundary emitted the event."
      next={{ href: '/guides/audit-logs', label: 'Audit logs guide' }}
    >
      <DocSection id="create-endpoint" title="Create an endpoint">
        <CodeBlock code={CREATE_WEBHOOK} language="javascript" />
      </DocSection>

      <DocSection id="deliveries" title="Deliveries and retries">
        <p>
          Delivery attempts are available through the webhook delivery list endpoint and include response status, body, attempt count, and the next retry time when a delivery is retrying. The dashboard also shows
          cumulative <strong>delivered</strong>, <strong>failed</strong>, and <strong>consecutive failure</strong> counts per endpoint.
        </p>
        <CodeBlock code={DELIVERIES} language="javascript" />
      </DocSection>

      <DocSection id="event-catalogue" title="Event catalogue">
        <p>
          Webhooks currently cover user lifecycle, API key lifecycle, invitation lifecycle, project lifecycle, and project social provider changes.
        </p>
        <CodeBlock code={EVENT_CATALOGUE} language="text" />
      </DocSection>

      <DocSection id="api-key-expiry" title="API key expiry notifications">
        <p>
          <code className="font-code">api_key.expired</code> is a time-based event. HVT emits it when an expired key is encountered, and you can also sweep for newly expired keys proactively with the management command below.
        </p>
        <CodeBlock code={EXPIRY_SWEEP} language="bash" />
      </DocSection>

      <DocSection id="signature" title="Signature verification">
        <p>
          Deliveries include a signed payload and delivery metadata. Verify the signature header before acting on the payload.
        </p>
        <CodeBlock code={PAYLOAD} language="json" />
      </DocSection>
    </DocPage>
  );
}
