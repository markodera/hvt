export type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | Array<string | number | boolean>;

export type QueryParams = Record<string, QueryValue>;
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type AuthMode = "auto" | "none" | "bearer" | "apiKey";

export interface RequestOptions {
  method?: HttpMethod;
  auth?: AuthMode;
  query?: QueryParams;
  headers?: Record<string, string>;
  body?: unknown;
  signal?: AbortSignal;
  credentials?: RequestCredentials;
}

export interface HVTClientOptions {
  baseUrl?: string;
  apiKey?: string | null;
  accessToken?: string | null;
  fetch?: typeof fetch;
  credentials?: RequestCredentials;
  defaultHeaders?: Record<string, string>;
  autoRefresh?: boolean;
  authFailureEventName?: string | null;
}

export interface HVTErrorEnvelope {
  error: string;
  code: string;
  detail: unknown;
  status: number;
}

export declare const API_KEY_CANONICAL_SCOPES: readonly [
  "organization:read",
  "users:read",
  "api_keys:read",
  "webhooks:read",
  "audit_logs:read",
  "auth:runtime"
];

export declare class HVTApiError extends Error {
  status: number;
  code: string;
  detail: unknown;
  body: unknown;
  constructor(message: string, options?: {
    status?: number;
    code?: string;
    detail?: unknown;
    body?: unknown;
  });
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface JWTResponse {
  access: string;
  refresh?: string;
  user?: User;
}

export interface SocialProviderDescriptor {
  provider: string;
  client_id: string;
  authorization_url: string;
  scope: string[];
  callback_url?: string;
  redirect_uris?: string[];
  project_id?: string;
  project_slug?: string;
}

export interface RuntimeSocialProviderList {
  project_id: string | null;
  project_slug: string;
  providers: SocialProviderDescriptor[];
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  allow_signup: boolean;
  owner: string | null;
  user_count: number;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  is_default: boolean;
  is_active: boolean;
  allow_signup: boolean;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  full_name: string;
  organization: string | null;
  project: string | null;
  project_slug: string | null;
  role: string;
  role_display: string;
  is_project_scoped: boolean;
  is_active: boolean;
  is_test: boolean;
  created_at: string;
}

export interface OrganizationMember extends User {
  can_promote?: boolean;
  can_demote?: boolean;
}

export interface LoginInput {
  email: string;
  password: string;
}

export interface RegisterInput {
  email: string;
  password1: string;
  password2: string;
  first_name?: string;
  last_name?: string;
}

export interface PasswordResetInput {
  email: string;
}

export interface PasswordChangeInput {
  new_password1: string;
  new_password2: string;
}

export interface RuntimeSocialLoginInput {
  code?: string;
  access_token?: string;
  callback_url?: string;
  [key: string]: unknown;
}

export interface CreateProjectInput {
  name: string;
  slug: string;
  allow_signup?: boolean;
  is_active?: boolean;
}

export interface UpdateProjectInput {
  name?: string;
  slug?: string;
  allow_signup?: boolean;
  is_active?: boolean;
}

export interface SocialProviderConfig {
  id: string;
  project: string;
  provider: string;
  client_id: string;
  has_client_secret: boolean;
  client_secret_last4: string;
  redirect_uris: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateSocialProviderConfigInput {
  provider: string;
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  is_active?: boolean;
}

export interface UpdateSocialProviderConfigInput {
  client_id?: string;
  client_secret?: string;
  redirect_uris?: string[];
  is_active?: boolean;
}

export interface ApiKeyCreateInput {
  name: string;
  environment?: "test" | "live";
  scopes: string[];
  expires_at?: string | null;
  project_id?: string;
}

export interface ApiKeyCreateResponse {
  id: string;
  name: string;
  environment: "test" | "live";
  scopes: string[];
  expires_at: string | null;
  project: string | null;
  project_name: string | null;
  project_slug: string | null;
  key: string;
  created_at: string;
}

export interface ApiKeySummary {
  id: string;
  name: string;
  prefix: string;
  environment: "test" | "live";
  environment_display: string;
  project: string | null;
  project_name: string | null;
  project_slug: string | null;
  scopes: string[];
  is_active: boolean;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface Webhook {
  id: string;
  project: string;
  project_name: string;
  project_slug: string;
  url: string;
  events: string[];
  secret: string;
  description: string;
  is_active: boolean;
  created_at: string;
  last_triggered_at: string | null;
  success_count: number;
  failure_count: number;
  consecutive_failures: number;
}

export interface CreateWebhookInput {
  project_id?: string;
  url: string;
  events: string[];
  description?: string;
  is_active?: boolean;
}

export interface UpdateWebhookInput {
  project_id?: string;
  url?: string;
  events?: string[];
  description?: string;
  is_active?: boolean;
}

export interface WebhookDelivery {
  id: string;
  event_type: string;
  payload: Record<string, unknown>;
  status: string;
  response_status_code: number | null;
  response_body: string | null;
  error_message: string | null;
  attempt_count: number;
  max_attempts: number;
  next_retry_at: string | null;
  created_at: string;
  delivered_at: string | null;
}

export interface AuditLog {
  id: string;
  event_type: string;
  event_data: Record<string, unknown>;
  actor_email: string | null;
  actor_api_key_name: string | null;
  target_type: string | null;
  target_object_id: string | null;
  organization: string;
  project: string | null;
  ip_address: string | null;
  user_agent: string;
  success: boolean;
  error_message: string | null;
  created_at: string;
}

export interface PermissionMatrixResponse {
  role: string;
  permissions: Record<string, boolean>;
  matrix: Record<string, Record<string, boolean>>;
}

export interface Invitation {
  id: string;
  email: string;
  role: string;
  status: string;
  accept_url: string;
  invited_by_email: string | null;
  accepted_by_email: string | null;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface InvitationCreateInput {
  email: string;
  role: string;
  expires_at?: string;
}

export interface InvitationLookup {
  email: string;
  role: string;
  status: string;
  organization_name: string;
  organization_slug: string;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface UserCreateInput {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  organization?: string;
  role?: string;
}

export interface UserUpdateInput {
  first_name?: string;
  last_name?: string;
  role?: string;
  is_active?: boolean;
}

export declare class HVTClient {
  baseUrl: string;
  apiKey: string | null;
  accessToken: string | null;
  fetch: typeof fetch;
  credentials: RequestCredentials;
  defaultHeaders: Record<string, string>;
  autoRefresh: boolean;
  authFailureEventName: string | null;
  auth: AuthAPI;
  organizations: OrganizationsAPI;
  users: UsersAPI;
  constructor(options?: HVTClientOptions);
  withApiKey(apiKey: string): HVTClient;
  withAccessToken(accessToken: string): HVTClient;
  setApiKey(apiKey: string | null): this;
  setAccessToken(accessToken: string | null): this;
  refreshAccessToken(payload?: Record<string, unknown>, options?: RequestOptions): Promise<JWTResponse>;
  request<T = unknown>(path: string, options?: RequestOptions): Promise<T>;
}

export declare class AuthAPI {
  constructor(client: HVTClient);
  login(payload: LoginInput, options?: RequestOptions): Promise<JWTResponse>;
  logout(options?: RequestOptions): Promise<{ detail: string }>;
  me(options?: RequestOptions): Promise<User>;
  updateMe(payload: UserUpdateInput, options?: RequestOptions): Promise<User>;
  refresh(payload?: Record<string, unknown>, options?: RequestOptions): Promise<JWTResponse>;
  register(payload: RegisterInput, options?: RequestOptions): Promise<unknown>;
  passwordReset(payload: PasswordResetInput, options?: RequestOptions): Promise<{ detail: string }>;
  passwordChange(payload: PasswordChangeInput, options?: RequestOptions): Promise<{ detail: string }>;
  listSocialProviders(options?: RequestOptions): Promise<{ providers: SocialProviderDescriptor[] }>;
  socialGoogle(payload: RuntimeSocialLoginInput, options?: RequestOptions): Promise<unknown>;
  socialGithub(payload: RuntimeSocialLoginInput, options?: RequestOptions): Promise<unknown>;
  runtimeLogin(payload: LoginInput, options?: RequestOptions): Promise<JWTResponse>;
  listRuntimeSocialProviders(options?: RequestOptions): Promise<RuntimeSocialProviderList>;
  runtimeGoogle(payload: RuntimeSocialLoginInput, options?: RequestOptions): Promise<unknown>;
  runtimeGithub(payload: RuntimeSocialLoginInput, options?: RequestOptions): Promise<unknown>;
}

export declare class OrganizationsAPI {
  constructor(client: HVTClient);
  create(payload: { name: string; slug?: string }, options?: RequestOptions): Promise<Organization>;
  current(options?: RequestOptions): Promise<Organization>;
  updateCurrent(payload: Partial<Organization>, options?: RequestOptions): Promise<Organization>;
  listProjects(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<Project>>;
  createProject(payload: CreateProjectInput, options?: RequestOptions): Promise<Project>;
  updateProject(projectId: string, payload: UpdateProjectInput, options?: RequestOptions): Promise<Project>;
  deleteProject(projectId: string, options?: RequestOptions): Promise<void>;
  listProjectSocialProviders(projectId: string, options?: RequestOptions): Promise<PaginatedResponse<SocialProviderConfig>>;
  createProjectSocialProvider(projectId: string, payload: CreateSocialProviderConfigInput, options?: RequestOptions): Promise<SocialProviderConfig>;
  updateProjectSocialProvider(projectId: string, socialProviderId: string, payload: UpdateSocialProviderConfigInput, options?: RequestOptions): Promise<SocialProviderConfig>;
  deleteProjectSocialProvider(projectId: string, socialProviderId: string, options?: RequestOptions): Promise<void>;
  listMembers(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<OrganizationMember>>;
  listApiKeys(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<ApiKeySummary>>;
  createApiKey(payload: ApiKeyCreateInput, options?: RequestOptions): Promise<ApiKeyCreateResponse>;
  getApiKey(apiKeyId: string, options?: RequestOptions): Promise<ApiKeySummary>;
  revokeApiKey(apiKeyId: string, options?: RequestOptions): Promise<{ detail: string }>;
  listWebhooks(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<Webhook>>;
  createWebhook(payload: CreateWebhookInput, options?: RequestOptions): Promise<Webhook>;
  getWebhook(webhookId: string, options?: RequestOptions): Promise<Webhook>;
  updateWebhook(webhookId: string, payload: UpdateWebhookInput, options?: RequestOptions): Promise<Webhook>;
  deleteWebhook(webhookId: string, options?: RequestOptions): Promise<void>;
  listWebhookDeliveries(webhookId: string, query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<WebhookDelivery>>;
  listAuditLogs(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<AuditLog>>;
  getAuditLog(auditLogId: string, options?: RequestOptions): Promise<AuditLog>;
  permissions(options?: RequestOptions): Promise<PermissionMatrixResponse>;
  listInvitations(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<Invitation>>;
  createInvitation(payload: InvitationCreateInput, options?: RequestOptions): Promise<Invitation>;
  resendInvitation(invitationId: string, options?: RequestOptions): Promise<Invitation>;
  revokeInvitation(invitationId: string, options?: RequestOptions): Promise<void>;
  lookupInvitation(token: string, options?: RequestOptions): Promise<InvitationLookup>;
  acceptInvitation(token: string, options?: RequestOptions): Promise<Invitation>;
}

export declare class UsersAPI {
  constructor(client: HVTClient);
  list(query?: QueryParams, options?: RequestOptions): Promise<PaginatedResponse<User>>;
  create(payload: UserCreateInput, options?: RequestOptions): Promise<User>;
  get(userId: string, options?: RequestOptions): Promise<User>;
  update(userId: string, payload: UserUpdateInput, options?: RequestOptions): Promise<User>;
  delete(userId: string, options?: RequestOptions): Promise<void>;
  updateRole(userId: string, role: string | { role: string }, options?: RequestOptions): Promise<User>;
}
