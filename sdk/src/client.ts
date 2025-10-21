import {
  AcceptShareRequest,           // kept for compatibility (not used directly)
  AcceptShareResponse,          // kept for compatibility (not used directly)
  EncryptionHooks,
  FetchLike,
  LockmateClientConfig,
  LoginRequest,
  LoginResponse,
  PaginatedResponse,            // not used by current backend but kept
  GeneratedPassword,
  RegisterRequest,
  ShareInviteRequest,           // kept for compatibility (not used directly)
  ShareRecord,                  // kept for compatibility (not used directly)
  ShareUpdateRequest,           // kept for compatibility (not used directly)
  PasswordGenerationOptions,
  PasswordStrengthReport,
  VaultCreateRequest,           // not used by current backend
  VaultItemDraft,               // not used (server encrypts via X-Vault-Key instead)
  VaultItemRecord,              // server uses VaultItemView shape (see below)
  VaultSummary,                 // not used by current backend
  VaultUpdateRequest,           // not used by current backend
  AuthTokens,
  UserProfile,
  EncryptedVaultItemPayload,    // not used by current backend
  SecurityHealthSummary
} from "./types";

// --- Types that mirror your Rust API JSON envelopes (minimal) ---

type ApiEnvelope<T> = {
  status: "success" | "fail" | "error";
  results?: number;
  message?: string;
  data?: T;
};

export type VaultItemRequest = {
  folder_id?: string | null;
  title: string;
  username?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
};

// This matches VaultItemView produced in vault_items.rs (id, folder_id, timestamps, + decrypted fields).
export type VaultItemView = {
  id: string;
  user_id: string;
  folder_id?: string | null;
  ciphertext?: string; // not needed, but harmless if present
  nonce?: string;      // not needed, but harmless if present
  created_at: string;  // RFC3339
  updated_at: string;  // RFC3339

  // decrypted payload
  title: string;
  username?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
};

// Share-related shapes (summaries, invitations, etc.) — simplified
export type ShareInvitation = {
  id: string;
  share_id: string;
  owner_id?: string;
  item_id?: string;
  recipient_id?: string;
  key_payload: unknown;
  created_at: string;
  expires_at?: string;
  responded_at?: string | null;
  status?: string;
};

export type ShareRecipientsResponse = {
  share_id: string | null;
  recipients: ShareInvitation[];
};

const GLOBAL_FETCH: FetchLike | undefined =
    typeof fetch === "function" ? fetch.bind(globalThis) : undefined;

export class LockmateError extends Error {
  public readonly status: number;
  public readonly details: unknown;

  constructor(message: string, status: number, details: unknown) {
    super(message);
    this.name = "LockmateError";
    this.status = status;
    this.details = details;
  }
}

export class LockmateClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly encryption?: EncryptionHooks; // kept for compatibility; server uses X-Vault-Key
  private token?: string;
  private defaultVaultKey?: string; // optional default to avoid passing on every call

  constructor(config: LockmateClientConfig & { defaultVaultKey?: string }) {
    if (!config.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.fetchImpl =
        config.fetchImpl ??
        GLOBAL_FETCH ??
        (() => {
          throw new Error(
              "No fetch implementation available. Provide fetchImpl in the client configuration."
          );
        })();
    this.encryption = config.encryption;
    this.token = config.token;
    this.defaultVaultKey = config.defaultVaultKey;
  }

  /** Returns the active bearer token, if any. */
  getToken(): string | undefined {
    return this.token;
  }
  /** Manually sets the bearer token for subsequent requests. */
  setToken(token: string | undefined): void {
    this.token = token;
  }
  /** Clears the stored bearer token. */
  clearToken(): void {
    this.token = undefined;
  }
  /** Optionally set a default vault key (used for vault item & security calls). */
  setDefaultVaultKey(vaultKey?: string): void {
    this.defaultVaultKey = vaultKey;
  }

  // ---------- Health ----------

  async healthcheck(): Promise<{ status: string; message: string }> {
    const res = await this.request<ApiEnvelope<{ status: string; message: string }>>(
        "v1/healthcheck/"
    );
    // healthcheck returns {status, message} directly (no "data"), but wrap tolerant:
    return res.data ?? (res as unknown as { status: string; message: string });
  }

  // ---------- Auth ----------

  async register(body: RegisterRequest): Promise<UserProfile> {
    const res = await this.request<UserProfile>("v1/auth/register", {
      method: "POST",
      body
    });
    return res;
  }

  async login(body: LoginRequest): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>("v1/auth/login", {
      method: "POST",
      body
    });
    this.token = response.token;
    return response;
  }

  async refresh(refreshToken: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>("v1/auth/token/refresh", {
      method: "POST",
      body: { refresh_token: refreshToken }
    });
    this.token = tokens.token;
    return tokens;
  }

  async logout(refreshToken: string): Promise<void> {
    await this.request<void>("v1/auth/logout", {
      method: "POST",
      body: { refresh_token: refreshToken }
    });
    this.clearToken();
  }

  // NOTE: Backend has no explicit /auth/session; skipping getSession()

  // ---------- Vault Items (all require JWT; most require X-Vault-Key) ----------

  private requireVaultKey(vaultKey?: string): string {
    const key = vaultKey ?? this.defaultVaultKey;
    if (!key || !key.trim()) throw new Error("A vaultKey is required (pass as argument or set defaultVaultKey).");
    return key;
  }

  async listVaultItems(vaultKey?: string): Promise<VaultItemView[]> {
    const key = this.requireVaultKey(vaultKey);
    const env = await this.request<ApiEnvelope<VaultItemView[]>>("v1/vault/items", {
      headers: { "X-Vault-Key": key }
    });
    return env.data ?? [];
  }

  async createVaultItem(body: VaultItemRequest, vaultKey?: string): Promise<VaultItemView> {
    const key = this.requireVaultKey(vaultKey);
    const env = await this.request<ApiEnvelope<VaultItemView>>("v1/vault/items", {
      method: "POST",
      headers: { "X-Vault-Key": key },
      body
    });
    if (!env.data) throw new Error("Unexpected response shape: missing data");
    return env.data;
  }

  async getVaultItem(itemId: string, vaultKey?: string): Promise<VaultItemView> {
    const key = this.requireVaultKey(vaultKey);
    const env = await this.request<ApiEnvelope<VaultItemView>>(
        `v1/vault/items/${encodeURIComponent(itemId)}/`,
        { headers: { "X-Vault-Key": key } }
    );
    if (!env.data) throw new Error("Unexpected response shape: missing data");
    return env.data;
  }

  /**
   * Update requires If-Match: RFC3339 timestamp equal to current item's updated_at.
   */
  async updateVaultItem(
      itemId: string,
      body: VaultItemRequest,
      ifMatchRfc3339: string,
      vaultKey?: string
  ): Promise<VaultItemView> {
    const key = this.requireVaultKey(vaultKey);
    const env = await this.request<ApiEnvelope<VaultItemView>>(
        `v1/vault/items/${encodeURIComponent(itemId)}/`,
        {
          method: "PUT",
          headers: {
            "X-Vault-Key": key,
            "If-Match": ifMatchRfc3339
          },
          body
        }
    );
    if (!env.data) throw new Error("Unexpected response shape: missing data");
    return env.data;
  }

  /**
   * Delete requires If-Match: RFC3339 timestamp equal to current item's updated_at.
   * No vault key header required by backend for delete.
   */
  async deleteVaultItem(itemId: string, ifMatchRfc3339: string): Promise<void> {
    await this.request<void>(`v1/vault/items/${encodeURIComponent(itemId)}/`, {
      method: "DELETE",
      headers: {
        "If-Match": ifMatchRfc3339
      }
    });
  }

  // ---------- Shares / Invitations ----------

  async createShareInvitations(itemId: string, invitations: { recipient_id: number; key_payload: unknown }[]) {
    const env = await this.request<ApiEnvelope<{ share_id: string; invitations: ShareInvitation[] }>>(
        `v1/shares/${encodeURIComponent(itemId)}/invitations/`,
        { method: "POST", body: { invitations } }
    );
    return env.data!;
  }

  async listShareRecipients(itemId: string): Promise<ShareRecipientsResponse> {
    const env = await this.request<ApiEnvelope<ShareRecipientsResponse>>(
        `v1/shares/${encodeURIComponent(itemId)}/recipients/`
    );
    return env.data ?? { share_id: null, recipients: [] };
  }

  async revokeRecipient(shareId: string, recipientId: string) {
    const env = await this.request<ApiEnvelope<ShareInvitation[]>>(
        `v1/shares/${encodeURIComponent(shareId)}/recipients/${encodeURIComponent(recipientId)}/revoke/`,
        { method: "POST" }
    );
    return env.data ?? [];
  }

  async revokeShare(shareId: string) {
    const env = await this.request<ApiEnvelope<unknown>>(
        `v1/shares/${encodeURIComponent(shareId)}/revoke/`,
        { method: "POST" }
    );
    return env.data;
  }

  async listPendingInvitations(): Promise<ShareInvitation[]> {
    const env = await this.request<ApiEnvelope<ShareInvitation[]>>(`v1/invitations/`);
    return env.data ?? [];
  }

  async acceptInvitation(invitationId: string) {
    const env = await this.request<ApiEnvelope<ShareInvitation>>(
        `v1/invitations/${encodeURIComponent(invitationId)}/accept/`,
        { method: "POST" }
    );
    return env.data!;
  }

  async declineInvitation(invitationId: string) {
    const env = await this.request<ApiEnvelope<ShareInvitation>>(
        `v1/invitations/${encodeURIComponent(invitationId)}/decline/`,
        { method: "POST" }
    );
    return env.data!;
  }

  async listSharedItems(): Promise<
      {
        invitation_id: string;
        share_id: string;
        owner_id: string;
        item_id: string;
        key_payload: unknown;
        accepted_at?: string | null;
      }[]
  > {
    const env = await this.request<ApiEnvelope<any[]>>(`v1/me/shared-items/`);
    return env.data ?? [];
  }

  // ---------- Tools (Password) ----------

  async generatePassword(options?: PasswordGenerationOptions): Promise<GeneratedPassword> {
    // Backend expects Passphrase options; map the common fields if present,
    // otherwise just POST what you have; server has defaults.
    const env = await this.request<any>(`v1/tools/password/generate`, {
      method: "POST",
      body: options ?? {}
    });
    // API returns { password, strength }
    return {
      password: env.password,
      strength: env.strength
    } as GeneratedPassword;
  }

  async evaluatePasswordStrength(password: string): Promise<PasswordStrengthReport> {
    const env = await this.request<PasswordStrengthReport>(`v1/tools/password/strength`, {
      method: "POST",
      body: { password }
    });
    return env;
  }

  // ---------- Security ----------

  async getSecurityHealth(): Promise<SecurityHealthSummary> {
    const env = await this.request<ApiEnvelope<SecurityHealthSummary>>(`v1/security/health`);
    if (!env.data) throw new Error("Unexpected response shape: missing data");
    return env.data;
  }

  async runSecurityHealthCheck(vaultKey?: string): Promise<SecurityHealthSummary> {
    const key = this.requireVaultKey(vaultKey);
    const [status, env] = await this.requestWithStatus<ApiEnvelope<SecurityHealthSummary>>(
        `v1/security/check`,
        { method: "POST", headers: { "X-Vault-Key": key } }
    );
    // Backend responds 202 ACCEPTED with full summary in body.
    if (!env.data) throw new Error("Unexpected response shape: missing data");
    return env.data;
  }

  // ---------- Admin (audit) ----------

  async listAuditLogs(params?: { user_id?: string; action?: string; limit?: number }) {
    const qs = new URLSearchParams();
    if (params?.user_id) qs.set("user_id", params.user_id);
    if (params?.action) qs.set("action", params.action);
    if (typeof params?.limit === "number") qs.set("limit", String(params.limit));
    const env = await this.request<ApiEnvelope<any[]>>(
        `v1/admin/audit/logs/${qs.toString() ? `?${qs.toString()}` : ""}`
    );
    return env;
  }

  // ---------- Internal request helpers ----------

  private async request<T>(
      path: string,
      init: Omit<RequestInit, "body"> & { body?: unknown } = {}
  ): Promise<T> {
    const normalizedPath = path.replace(/^\/+/, "");
    const url = new URL(normalizedPath, this.baseUrl).toString();

    const headers = new Headers(init.headers ?? {});
    if (init.body !== undefined && !(init.body instanceof FormData)) {
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    }
    if (this.token) headers.set("Authorization", `Bearer ${this.token}`);

    const requestInit: RequestInit = {
      ...init,
      headers,
      body: this.normalizeBody(init.body)
    };

    const response = await this.fetchImpl(url, requestInit);
    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      let details: unknown = undefined;
      if (contentType?.includes("application/json")) {
        try { details = await response.json(); } catch { details = await response.text(); }
      } else {
        details = await response.text();
      }
      throw new LockmateError(
          `Request to ${normalizedPath} failed with status ${response.status}`,
          response.status,
          details
      );
    }

    if (response.status === 204) return undefined as T;

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      return (await response.json()) as T;
    }

    // healthcheck returns JSON, but just in case…
    return (await response.text()) as unknown as T;
  }

  private async requestWithStatus<T>(
      path: string,
      init: Omit<RequestInit, "body"> & { body?: unknown } = {}
  ): Promise<[status: number, json: T]> {
    const normalizedPath = path.replace(/^\/+/, "");
    const url = new URL(normalizedPath, this.baseUrl).toString();

    const headers = new Headers(init.headers ?? {});
    if (init.body !== undefined && !(init.body instanceof FormData)) {
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    }
    if (this.token) headers.set("Authorization", `Bearer ${this.token}`);

    const requestInit: RequestInit = {
      ...init,
      headers,
      body: this.normalizeBody(init.body)
    };

    const res = await this.fetchImpl(url, requestInit);
    const status = res.status;
    const contentType = res.headers.get("content-type") ?? "";
    if (!res.ok) {
      let details: unknown = undefined;
      if (contentType.includes("application/json")) {
        try { details = await res.json(); } catch { details = await res.text(); }
      } else {
        details = await res.text();
      }
      throw new LockmateError(
          `Request to ${normalizedPath} failed with status ${status}`,
          status,
          details
      );
    }
    let body: any = undefined;
    if (status !== 204) {
      if (contentType.includes("application/json")) body = await res.json();
      else body = await res.text();
    }
    return [status, body as T];
  }

  private normalizeBody(body: unknown): BodyInit | undefined {
    if (body === undefined || body === null) return undefined;
    if (
        typeof body === "string" ||
        body instanceof ArrayBuffer ||
        body instanceof Blob ||
        body instanceof FormData ||
        body instanceof URLSearchParams ||
        ArrayBuffer.isView(body)
    ) {
      return body as BodyInit;
    }
    return JSON.stringify(body);
  }
}

// --- (Base64 helpers retained for compatibility with your original file, though unused) ---

function encodeBase64(value: string): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(value);
  if (typeof btoa === "function") {
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary);
  }
  const globalBuffer = (globalThis as Record<string, unknown>).Buffer as
      | { from(input: Uint8Array, encoding?: string): { toString(encoding: string): string } }
      | undefined;
  if (globalBuffer) return globalBuffer.from(bytes).toString("base64");
  return bytesToBase64(bytes);
}

function decodeBase64(value: string): string {
  const globalBuffer = (globalThis as Record<string, unknown>).Buffer as
      | { from(input: string, encoding: string): { toString(encoding: string): string } }
      | undefined;
  if (globalBuffer) return globalBuffer.from(value, "base64").toString("utf-8");
  const decoder = new TextDecoder();
  const binary = typeof atob === "function" ? atob(value) : atobPolyfill(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return decoder.decode(bytes);
}

function bytesToBase64(bytes: Uint8Array): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i: number;
  for (i = 0; i < bytes.length - 2; i += 3) {
    result += chars[bytes[i] >> 2];
    result += chars[((bytes[i] & 0x03) << 4) | (bytes[i + 1] >> 4)];
    result += chars[((bytes[i + 1] & 0x0f) << 2) | (bytes[i + 2] >> 6)];
    result += chars[bytes[i + 2] & 0x3f];
  }
  if (i < bytes.length) {
    result += chars[bytes[i] >> 2];
    if (i === bytes.length - 1) {
      result += chars[(bytes[i] & 0x03) << 4] + "==";
    } else {
      result += chars[((bytes[i] & 0x03) << 4) | (bytes[i + 1] >> 4)];
      result += chars[(bytes[i + 1] & 0x0f) << 2] + "=";
    }
  }
  return result;
}

function atobPolyfill(value: string): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let str = value.replace(/=+$/, "");
  if (str.length % 4 === 1) throw new Error("Invalid base64 string");
  let output = "", bc = 0, bs = 0, buffer: number, idx = 0;
  for (; (buffer = str.charCodeAt(idx++)); ) {
    buffer = chars.indexOf(String.fromCharCode(buffer));
    if (buffer === -1) continue;
    bs = bc % 4 ? bs * 64 + buffer : buffer;
    if (bc++ % 4) output += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6)));
  }
  return output;
}
