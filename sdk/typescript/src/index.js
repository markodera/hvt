const DEFAULT_BASE_URL = "http://127.0.0.1:8000";
const AUTH_REFRESH_PATH = "/api/v1/auth/token/refresh/";
const DEFAULT_AUTH_FAILURE_EVENT_NAME = "auth:logout";

export const API_KEY_CANONICAL_SCOPES = [
  "organization:read",
  "users:read",
  "api_keys:read",
  "webhooks:read",
  "audit_logs:read",
  "auth:runtime",
];

export class HVTApiError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "HVTApiError";
    this.status = options.status ?? 0;
    this.code = options.code ?? "unknown_error";
    this.detail = options.detail ?? null;
    this.body = options.body ?? null;
  }
}

function normalizeBaseUrl(baseUrl) {
  const normalized = String(baseUrl || DEFAULT_BASE_URL).trim();
  return normalized.endsWith("/") ? normalized : `${normalized}/`;
}

function buildUrl(baseUrl, path, query) {
  const url = new URL(String(path || "").replace(/^\//, ""), normalizeBaseUrl(baseUrl));
  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") {
        continue;
      }
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") {
            url.searchParams.append(key, String(item));
          }
        }
        continue;
      }
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

function normalizePathname(pathname) {
  if (!pathname || pathname === "/") {
    return "/";
  }
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

function resolvePathname(baseUrl, path) {
  try {
    return normalizePathname(new URL(String(path || ""), normalizeBaseUrl(baseUrl)).pathname);
  } catch {
    return normalizePathname(String(path || "").split("?")[0] || "/");
  }
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

async function parseResponseBody(response) {
  if (response.status === 204) {
    return undefined;
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();
  return text.length ? text : undefined;
}

function createApiError(response, parsedBody) {
  const message =
    parsedBody && typeof parsedBody === "object" && "error" in parsedBody
      ? parsedBody.error
      : response.statusText || "Request failed";

  return new HVTApiError(message, {
    status: response.status,
    code:
      parsedBody && typeof parsedBody === "object" && "code" in parsedBody
        ? parsedBody.code
        : `http_${response.status}`,
    detail:
      parsedBody && typeof parsedBody === "object" && "detail" in parsedBody
        ? parsedBody.detail
        : parsedBody,
    body: parsedBody,
  });
}

function resolveAuthHeaders(client, authMode) {
  const headers = {};

  if (authMode === "none") {
    return headers;
  }

  if (authMode === "bearer") {
    if (client.accessToken) {
      headers.Authorization = `Bearer ${client.accessToken}`;
    }
    return headers;
  }

  if (authMode === "apiKey") {
    if (client.apiKey) {
      headers["X-API-Key"] = client.apiKey;
    }
    return headers;
  }

  if (client.accessToken) {
    headers.Authorization = `Bearer ${client.accessToken}`;
  } else if (client.apiKey) {
    headers["X-API-Key"] = client.apiKey;
  }

  return headers;
}

export class AuthAPI {
  constructor(client) {
    this.client = client;
  }

  login(payload, options) {
    return this.client.request("/api/v1/auth/login/", {
      method: "POST",
      body: payload,
      auth: "none",
      ...options,
    });
  }

  logout(options) {
    return this.client.request("/api/v1/auth/logout/", {
      method: "POST",
      ...options,
    });
  }

  me(options) {
    return this.client.request("/api/v1/auth/me/", {
      method: "GET",
      ...options,
    });
  }

  updateMe(payload, options) {
    return this.client.request("/api/v1/auth/me/", {
      method: "PATCH",
      body: payload,
      ...options,
    });
  }

  refresh(payload = {}, options) {
    return this.client.refreshAccessToken(payload, options);
  }

  register(payload, options) {
    return this.client.request("/api/v1/auth/runtime/register/", {
      method: "POST",
      body: payload,
      auth: "apiKey",
      ...options,
    });
  }

  passwordReset(payload, options) {
    return this.client.request("/api/v1/auth/password/reset/", {
      method: "POST",
      body: payload,
      auth: "none",
      ...options,
    });
  }

  passwordChange(payload, options) {
    return this.client.request("/api/v1/auth/password/change/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  listSocialProviders(options) {
    return this.client.request("/api/v1/auth/social/providers/", {
      method: "GET",
      auth: "none",
      ...options,
    });
  }

  socialGoogle(payload, options) {
    return this.client.request("/api/v1/auth/social/google/", {
      method: "POST",
      body: payload,
      auth: "none",
      ...options,
    });
  }

  socialGithub(payload, options) {
    return this.client.request("/api/v1/auth/social/github/", {
      method: "POST",
      body: payload,
      auth: "none",
      ...options,
    });
  }

  runtimeLogin(payload, options) {
    return this.client.request("/api/v1/auth/runtime/login/", {
      method: "POST",
      body: payload,
      auth: "apiKey",
      ...options,
    });
  }

  listRuntimeSocialProviders(options) {
    return this.client.request("/api/v1/auth/runtime/social/providers/", {
      method: "GET",
      auth: "apiKey",
      ...options,
    });
  }

  runtimeGoogle(payload, options) {
    return this.client.request("/api/v1/auth/runtime/social/google/", {
      method: "POST",
      body: payload,
      auth: "apiKey",
      ...options,
    });
  }

  runtimeGithub(payload, options) {
    return this.client.request("/api/v1/auth/runtime/social/github/", {
      method: "POST",
      body: payload,
      auth: "apiKey",
      ...options,
    });
  }
}

export class OrganizationsAPI {
  constructor(client) {
    this.client = client;
  }

  create(payload, options) {
    return this.client.request("/api/v1/organizations/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  current(options) {
    return this.client.request("/api/v1/organizations/current/", {
      method: "GET",
      ...options,
    });
  }

  updateCurrent(payload, options) {
    return this.client.request("/api/v1/organizations/current/", {
      method: "PATCH",
      body: payload,
      ...options,
    });
  }

  listProjects(query, options) {
    return this.client.request("/api/v1/organizations/current/projects/", {
      method: "GET",
      query,
      ...options,
    });
  }

  createProject(payload, options) {
    return this.client.request("/api/v1/organizations/current/projects/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  updateProject(projectId, payload, options) {
    return this.client.request(`/api/v1/organizations/current/projects/${projectId}/`, {
      method: "PATCH",
      body: payload,
      ...options,
    });
  }

  deleteProject(projectId, options) {
    return this.client.request(`/api/v1/organizations/current/projects/${projectId}/`, {
      method: "DELETE",
      ...options,
    });
  }

  listProjectSocialProviders(projectId, options) {
    return this.client.request(
      `/api/v1/organizations/current/projects/${projectId}/social-providers/`,
      {
        method: "GET",
        ...options,
      }
    );
  }

  createProjectSocialProvider(projectId, payload, options) {
    return this.client.request(
      `/api/v1/organizations/current/projects/${projectId}/social-providers/`,
      {
        method: "POST",
        body: payload,
        ...options,
      }
    );
  }

  updateProjectSocialProvider(projectId, socialProviderId, payload, options) {
    return this.client.request(
      `/api/v1/organizations/current/projects/${projectId}/social-providers/${socialProviderId}/`,
      {
        method: "PATCH",
        body: payload,
        ...options,
      }
    );
  }

  deleteProjectSocialProvider(projectId, socialProviderId, options) {
    return this.client.request(
      `/api/v1/organizations/current/projects/${projectId}/social-providers/${socialProviderId}/`,
      {
        method: "DELETE",
        ...options,
      }
    );
  }

  listMembers(query, options) {
    return this.client.request("/api/v1/organizations/current/members/", {
      method: "GET",
      query,
      ...options,
    });
  }

  listApiKeys(query, options) {
    return this.client.request("/api/v1/organizations/current/keys/", {
      method: "GET",
      query,
      ...options,
    });
  }

  createApiKey(payload, options) {
    return this.client.request("/api/v1/organizations/current/keys/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  getApiKey(apiKeyId, options) {
    return this.client.request(`/api/v1/organizations/current/keys/${apiKeyId}/`, {
      method: "GET",
      ...options,
    });
  }

  revokeApiKey(apiKeyId, options) {
    return this.client.request(
      `/api/v1/organizations/current/keys/${apiKeyId}/revoke/`,
      {
        method: "PATCH",
        ...options,
      }
    );
  }

  listWebhooks(query, options) {
    return this.client.request("/api/v1/organizations/current/webhooks/", {
      method: "GET",
      query,
      ...options,
    });
  }

  createWebhook(payload, options) {
    return this.client.request("/api/v1/organizations/current/webhooks/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  getWebhook(webhookId, options) {
    return this.client.request(`/api/v1/organizations/current/webhooks/${webhookId}/`, {
      method: "GET",
      ...options,
    });
  }

  updateWebhook(webhookId, payload, options) {
    return this.client.request(`/api/v1/organizations/current/webhooks/${webhookId}/`, {
      method: "PATCH",
      body: payload,
      ...options,
    });
  }

  deleteWebhook(webhookId, options) {
    return this.client.request(`/api/v1/organizations/current/webhooks/${webhookId}/`, {
      method: "DELETE",
      ...options,
    });
  }

  listWebhookDeliveries(webhookId, query, options) {
    return this.client.request(
      `/api/v1/organizations/current/webhooks/${webhookId}/deliveries/`,
      {
        method: "GET",
        query,
        ...options,
      }
    );
  }

  listAuditLogs(query, options) {
    return this.client.request("/api/v1/organizations/current/audit-logs/", {
      method: "GET",
      query,
      ...options,
    });
  }

  getAuditLog(auditLogId, options) {
    return this.client.request(`/api/v1/organizations/current/audit-logs/${auditLogId}/`, {
      method: "GET",
      ...options,
    });
  }

  permissions(options) {
    return this.client.request("/api/v1/organizations/current/permissions/", {
      method: "GET",
      ...options,
    });
  }

  listInvitations(query, options) {
    return this.client.request("/api/v1/organizations/current/invitations/", {
      method: "GET",
      query,
      ...options,
    });
  }

  createInvitation(payload, options) {
    return this.client.request("/api/v1/organizations/current/invitations/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  resendInvitation(invitationId, options) {
    return this.client.request(
      `/api/v1/organizations/current/invitations/${invitationId}/resend/`,
      {
        method: "POST",
        ...options,
      }
    );
  }

  revokeInvitation(invitationId, options) {
    return this.client.request(`/api/v1/organizations/current/invitations/${invitationId}/`, {
      method: "DELETE",
      ...options,
    });
  }

  lookupInvitation(token, options) {
    return this.client.request("/api/v1/organizations/invitations/lookup/", {
      method: "GET",
      query: { token },
      auth: "none",
      ...options,
    });
  }

  acceptInvitation(token, options) {
    return this.client.request("/api/v1/organizations/invitations/accept/", {
      method: "POST",
      body: { token },
      ...options,
    });
  }
}

export class UsersAPI {
  constructor(client) {
    this.client = client;
  }

  list(query, options) {
    return this.client.request("/api/v1/users/", {
      method: "GET",
      query,
      ...options,
    });
  }

  create(payload, options) {
    return this.client.request("/api/v1/users/", {
      method: "POST",
      body: payload,
      ...options,
    });
  }

  get(userId, options) {
    return this.client.request(`/api/v1/users/${userId}/`, {
      method: "GET",
      ...options,
    });
  }

  update(userId, payload, options) {
    return this.client.request(`/api/v1/users/${userId}/`, {
      method: "PATCH",
      body: payload,
      ...options,
    });
  }

  delete(userId, options) {
    return this.client.request(`/api/v1/users/${userId}/`, {
      method: "DELETE",
      ...options,
    });
  }

  updateRole(userId, role, options) {
    return this.client.request(`/api/v1/users/${userId}/role/`, {
      method: "PATCH",
      body: isPlainObject(role) ? role : { role },
      ...options,
    });
  }
}

export class HVTClient {
  constructor(options = {}) {
    const fetchImpl =
      options.fetch ||
      (typeof globalThis !== "undefined" ? globalThis.fetch : undefined);

    if (typeof fetchImpl !== "function") {
      throw new Error("A fetch implementation is required.");
    }

    this.baseUrl = normalizeBaseUrl(options.baseUrl || DEFAULT_BASE_URL);
    this.fetch = fetchImpl;
    this.apiKey = options.apiKey || null;
    this.accessToken = options.accessToken || null;
    this.credentials = options.credentials || "include";
    this.defaultHeaders = { ...(options.defaultHeaders || {}) };
    this.autoRefresh = options.autoRefresh !== false;
    this.authFailureEventName =
      options.authFailureEventName === undefined
        ? DEFAULT_AUTH_FAILURE_EVENT_NAME
        : options.authFailureEventName;
    this.refreshPromise = null;

    this.auth = new AuthAPI(this);
    this.organizations = new OrganizationsAPI(this);
    this.users = new UsersAPI(this);
  }

  withApiKey(apiKey) {
    return new HVTClient({
      baseUrl: this.baseUrl,
      fetch: this.fetch,
      apiKey,
      accessToken: null,
      credentials: this.credentials,
      defaultHeaders: this.defaultHeaders,
      autoRefresh: this.autoRefresh,
      authFailureEventName: this.authFailureEventName,
    });
  }

  withAccessToken(accessToken) {
    return new HVTClient({
      baseUrl: this.baseUrl,
      fetch: this.fetch,
      apiKey: null,
      accessToken,
      credentials: this.credentials,
      defaultHeaders: this.defaultHeaders,
      autoRefresh: this.autoRefresh,
      authFailureEventName: this.authFailureEventName,
    });
  }

  setApiKey(apiKey) {
    this.apiKey = apiKey || null;
    return this;
  }

  setAccessToken(accessToken) {
    this.accessToken = accessToken || null;
    return this;
  }

  refreshAccessToken(payload = {}, options = {}) {
    const isDefaultRefreshPayload =
      !payload ||
      (isPlainObject(payload) && Object.keys(payload).length === 0);
    const usesSharedRefreshFlow =
      isDefaultRefreshPayload &&
      !options.signal &&
      !options.headers &&
      !options.credentials;

    if (!usesSharedRefreshFlow) {
      return this._executeRefreshRequest(payload, options);
    }

    return this._getOrCreateRefreshPromise();
  }

  _shouldAttemptAutoRefresh(path, auth) {
    if (!this.autoRefresh) {
      return false;
    }
    if (auth === "none" || auth === "apiKey") {
      return false;
    }
    return resolvePathname(this.baseUrl, path) !== normalizePathname(AUTH_REFRESH_PATH);
  }

  _getOrCreateRefreshPromise() {
    if (!this.refreshPromise) {
      this.refreshPromise = this._executeRefreshRequest().finally(() => {
        this.refreshPromise = null;
      });
    }
    return this.refreshPromise;
  }

  async _executeRefreshRequest(payload = {}, options = {}) {
    try {
      const refreshed = await this.request(AUTH_REFRESH_PATH, {
        method: "POST",
        body: payload,
        ...options,
      });
      const accessToken =
        refreshed && typeof refreshed === "object" && "access" in refreshed
          ? refreshed.access
          : null;
      this.setAccessToken(typeof accessToken === "string" ? accessToken : null);
      return refreshed;
    } catch (error) {
      this._handleAuthFailure();
      throw error;
    }
  }

  _handleAuthFailure() {
    this.setAccessToken(null);
    if (
      !this.authFailureEventName ||
      typeof window === "undefined" ||
      typeof window.dispatchEvent !== "function" ||
      typeof Event !== "function"
    ) {
      return;
    }

    try {
      window.dispatchEvent(new Event(this.authFailureEventName));
    } catch {
      // Ignore dispatch failures outside normal browser environments.
    }
  }

  async request(path, options = {}) {
    return this._request(path, options, false);
  }

  async _request(path, options = {}, hasRetriedAfterRefresh = false) {
    const method = options.method || "GET";
    const auth = options.auth || "auto";
    const url = buildUrl(this.baseUrl, path, options.query);

    const headers = {
      ...this.defaultHeaders,
      ...resolveAuthHeaders(this, auth),
      ...(options.headers || {}),
    };

    let body = options.body;
    if (body !== undefined && body !== null) {
      const isFormData = typeof FormData !== "undefined" && body instanceof FormData;
      const isSearchParams =
        typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams;

      if (!isFormData && !isSearchParams && typeof body !== "string") {
        if (!headers["Content-Type"] && !headers["content-type"]) {
          headers["Content-Type"] = "application/json";
        }
        body = JSON.stringify(body);
      }
    }

    const response = await this.fetch(url, {
      method,
      headers,
      body,
      signal: options.signal,
      credentials: options.credentials || this.credentials,
    });

    const parsedBody = await parseResponseBody(response);

    if (
      response.status === 401 &&
      !hasRetriedAfterRefresh &&
      this._shouldAttemptAutoRefresh(path, auth)
    ) {
      try {
        await this._getOrCreateRefreshPromise();
        return this._request(path, options, true);
      } catch {
        throw createApiError(response, parsedBody);
      }
    }

    if (!response.ok) {
      throw createApiError(response, parsedBody);
    }

    return parsedBody;
  }
}
