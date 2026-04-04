/** Event types for audit logs */
export const EVENT_TYPES = [
    { value: 'user.login', label: 'User Login' },
    { value: 'user.logout', label: 'User Logout' },
    { value: 'user.register', label: 'User Register' },
    { value: 'user.password_change', label: 'Password Change' },
    { value: 'user.password_reset', label: 'Password Reset' },
    { value: 'user.role_change', label: 'Role Change' },
    { value: 'api_key.create', label: 'API Key Created' },
    { value: 'api_key.revoke', label: 'API Key Revoked' },
    { value: 'webhook.create', label: 'Webhook Created' },
    { value: 'webhook.update', label: 'Webhook Updated' },
    { value: 'webhook.delete', label: 'Webhook Deleted' },
    { value: 'org.update', label: 'Org Updated' },
];

/** Role labels */
export const ROLE_LABELS = {
    owner: 'Owner',
    admin: 'Admin',
    member: 'Member',
};

/** Role options for selects */
export const ROLE_OPTIONS = [
    { value: 'owner', label: 'Owner' },
    { value: 'admin', label: 'Admin' },
    { value: 'member', label: 'Member' },
];

/** Canonical API key scopes */
export const SCOPES = [
    {
        value: 'auth:runtime',
        label: 'Runtime auth',
        helper: 'Required for runtime login and social auth',
    },
    { value: 'organization:read', label: 'Read organisation' },
    { value: 'users:read', label: 'Read users' },
    { value: 'api_keys:read', label: 'Read API keys' },
    { value: 'webhooks:read', label: 'Read webhooks' },
    { value: 'audit_logs:read', label: 'Read audit logs' },
];

/** API key environments */
export const ENVIRONMENTS = [
    { value: 'test', label: 'Test' },
    { value: 'live', label: 'Live' },
];

/** Webhook delivery statuses */
export const DELIVERY_STATUSES = {
    delivered: { label: 'Delivered', color: 'success' },
    failed: { label: 'Failed', color: 'danger' },
    pending: { label: 'Pending', color: 'warning' },
    retrying: { label: 'Retrying', color: 'warning' },
};

/** Sidebar navigation items */
export const NAV_ITEMS = [
    { label: 'Dashboard', path: '/dashboard', icon: 'LayoutDashboard' },
    { label: 'Users', path: '/dashboard/users', icon: 'Users', roles: ['owner', 'admin'] },
    { label: 'API Keys', path: '/dashboard/api-keys', icon: 'Key', roles: ['owner'] },
    { label: 'Webhooks', path: '/dashboard/webhooks', icon: 'Webhook', roles: ['owner', 'admin'] },
    { label: 'Audit Logs', path: '/dashboard/audit-logs', icon: 'ScrollText', roles: ['owner', 'admin'] },
    { label: 'Settings', path: '/dashboard/settings', icon: 'Settings', roles: ['owner'] },
];
