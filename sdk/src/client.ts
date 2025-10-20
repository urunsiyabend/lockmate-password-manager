import {
  AcceptShareRequest,
  AcceptShareResponse,
  EncryptionHooks,
  FetchLike,
  LockmateClientConfig,
  LoginRequest,
  LoginResponse,
  PaginatedResponse,
  GeneratedPassword,
  RegisterRequest,
  ShareInviteRequest,
  ShareRecord,
  ShareUpdateRequest,
  PasswordGenerationOptions,
  PasswordStrengthReport,
  VaultCreateRequest,
  VaultItemDraft,
  VaultItemRecord,
  VaultSummary,
  VaultUpdateRequest,
  AuthTokens,
  UserProfile,
  EncryptedVaultItemPayload,
  SecurityHealthSummary
} from "./types";

const GLOBAL_FETCH: FetchLike | undefined = typeof fetch === "function" ? fetch.bind(globalThis) : undefined;

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
  private readonly encryption?: EncryptionHooks;
  private token?: string;

  constructor(config: LockmateClientConfig) {
    if (!config.baseUrl) {
      throw new Error("baseUrl is required");
    }

    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.fetchImpl = config.fetchImpl ?? GLOBAL_FETCH ?? (() => {
      throw new Error("No fetch implementation available. Provide fetchImpl in the client configuration.");
    })();
    this.encryption = config.encryption;
    this.token = config.token;
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

  async register(body: RegisterRequest): Promise<UserProfile> {
    return this.request<UserProfile>("/auth/register", {
      method: "POST",
      body
    });
  }

  async login(body: LoginRequest): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>("/auth/login", {
      method: "POST",
      body
    });
    this.token = response.token;
    return response;
  }

  async refresh(refreshToken: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>("/auth/token/refresh", {
      method: "POST",
      body: { refresh_token: refreshToken }
    });
    this.token = tokens.token;
    return tokens;
  }

  async logout(refreshToken: string): Promise<void> {
    await this.request<void>("/auth/logout", {
      method: "POST",
      body: { refresh_token: refreshToken }
    });
    this.clearToken();
  }

  async getSession(): Promise<UserProfile> {
    return this.request<UserProfile>("/auth/session");
  }

  async listVaults(params?: { cursor?: string; limit?: number }): Promise<PaginatedResponse<VaultSummary>> {
    const query = new URLSearchParams();
    if (params?.cursor) query.set("cursor", params.cursor);
    if (params?.limit) query.set("limit", params.limit.toString());

    const path = `/vaults${query.toString() ? `?${query.toString()}` : ""}`;
    return this.request<PaginatedResponse<VaultSummary>>(path);
  }

  async createVault(body: VaultCreateRequest): Promise<VaultSummary> {
    return this.request<VaultSummary>("/vaults", {
      method: "POST",
      body
    });
  }

  async getVault(vaultId: string): Promise<VaultSummary> {
    return this.request<VaultSummary>(`/vaults/${vaultId}`);
  }

  async updateVault(vaultId: string, body: VaultUpdateRequest): Promise<VaultSummary> {
    return this.request<VaultSummary>(`/vaults/${vaultId}`, {
      method: "PATCH",
      body
    });
  }

  async deleteVault(vaultId: string): Promise<void> {
    await this.request<void>(`/vaults/${vaultId}`, {
      method: "DELETE"
    });
  }

  async listVaultItems(vaultId: string, params?: { cursor?: string; limit?: number; tag?: string }): Promise<PaginatedResponse<VaultItemRecord>> {
    const query = new URLSearchParams();
    if (params?.cursor) query.set("cursor", params.cursor);
    if (params?.limit) query.set("limit", params.limit.toString());
    if (params?.tag) query.set("tag", params.tag);

    const path = `/vaults/${vaultId}/items${query.toString() ? `?${query.toString()}` : ""}`;
    const response = await this.request<PaginatedResponse<VaultItemRecord>>(path);
    const decrypted = await Promise.all(
      response.data.map((item) => this.decryptItem(item))
    );
    return { ...response, data: decrypted };
  }

  async createVaultItem(vaultId: string, draft: VaultItemDraft): Promise<VaultItemRecord> {
    const payload = await this.encryptItem(draft);
    const record = await this.request<VaultItemRecord>(`/vaults/${vaultId}/items`, {
      method: "POST",
      body: payload
    });
    return this.decryptItem(record);
  }

  async getVaultItem(vaultId: string, itemId: string): Promise<VaultItemRecord> {
    const record = await this.request<VaultItemRecord>(`/vaults/${vaultId}/items/${itemId}`);
    return this.decryptItem(record);
  }

  async updateVaultItem(vaultId: string, itemId: string, draft: VaultItemDraft): Promise<VaultItemRecord> {
    const payload = await this.encryptItem(draft);
    const record = await this.request<VaultItemRecord>(`/vaults/${vaultId}/items/${itemId}`, {
      method: "PATCH",
      body: payload
    });
    return this.decryptItem(record);
  }

  async deleteVaultItem(vaultId: string, itemId: string): Promise<void> {
    await this.request<void>(`/vaults/${vaultId}/items/${itemId}`, {
      method: "DELETE"
    });
  }

  async inviteToVault(vaultId: string, invite: ShareInviteRequest): Promise<ShareRecord> {
    return this.request<ShareRecord>(`/vaults/${vaultId}/shares`, {
      method: "POST",
      body: invite
    });
  }

  async listVaultShares(vaultId: string): Promise<ShareRecord[]> {
    return this.request<ShareRecord[]>(`/vaults/${vaultId}/shares`);
  }

  async updateVaultShare(vaultId: string, shareId: string, update: ShareUpdateRequest): Promise<ShareRecord> {
    return this.request<ShareRecord>(`/vaults/${vaultId}/shares/${shareId}`, {
      method: "PATCH",
      body: update
    });
  }

  async deleteVaultShare(vaultId: string, shareId: string): Promise<void> {
    await this.request<void>(`/vaults/${vaultId}/shares/${shareId}`, {
      method: "DELETE"
    });
  }

  async acceptShare(shareId: string, body: AcceptShareRequest): Promise<AcceptShareResponse> {
    return this.request<AcceptShareResponse>(`/shares/${shareId}/accept`, {
      method: "POST",
      body
    });
  }

  async generatePassword(options?: PasswordGenerationOptions): Promise<GeneratedPassword> {
    return this.request<GeneratedPassword>("/tools/password/generate", {
      method: "POST",
      body: options ?? {}
    });
  }

  async evaluatePasswordStrength(password: string): Promise<PasswordStrengthReport> {
    return this.request<PasswordStrengthReport>("/tools/password/strength", {
      method: "POST",
      body: { password }
    });
  }

  async getSecurityHealth(): Promise<SecurityHealthSummary> {
    const response = await this.request<{ status: string; data: SecurityHealthSummary }>(
      "/security/health"
    );
    return response.data;
  }

  async runSecurityHealthCheck(vaultKey: string): Promise<SecurityHealthSummary> {
    if (!vaultKey || vaultKey.trim().length === 0) {
      throw new Error("vaultKey is required to perform a security health check");
    }

    const response = await this.request<{ status: string; data: SecurityHealthSummary }>(
      "/security/check",
      {
        method: "POST",
        headers: {
          "X-Vault-Key": vaultKey
        }
      }
    );

    return response.data;
  }

  private async encryptItem(draft: VaultItemDraft): Promise<EncryptedVaultItemPayload> {
    if (this.encryption?.encryptItem) {
      return this.encryption.encryptItem(draft);
    }

    return {
      label: draft.label,
      tags: draft.tags,
      checksum: draft.checksum,
      ciphertext: encodeBase64(JSON.stringify(draft.secret))
    };
  }

  private async decryptItem(record: VaultItemRecord): Promise<VaultItemRecord> {
    if (this.encryption?.decryptItem) {
      return this.encryption.decryptItem(record);
    }

    try {
      const plaintext = decodeBase64(record.ciphertext);
      const secret = JSON.parse(plaintext);
      return { ...record, secret };
    } catch {
      return record;
    }
  }

  private async request<T>(
    path: string,
    init: Omit<RequestInit, "body"> & { body?: unknown } = {}
  ): Promise<T> {
    const url = new URL(path, this.baseUrl).toString();
    const headers = new Headers(init.headers ?? {});

    if (init.body !== undefined && !(init.body instanceof FormData)) {
      if (!headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
    }

    if (this.token) {
      headers.set("Authorization", `Bearer ${this.token}`);
    }

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
        try {
          details = await response.json();
        } catch {
          details = await response.text();
        }
      } else {
        details = await response.text();
      }
      throw new LockmateError(`Request to ${path} failed with status ${response.status}`, response.status, details);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      return (await response.json()) as T;
    }

    return (await response.text()) as unknown as T;
  }

  private normalizeBody(body: unknown): BodyInit | undefined {
    if (body === undefined || body === null) {
      return undefined;
    }

    if (typeof body === "string" || body instanceof ArrayBuffer || body instanceof Blob || body instanceof FormData || body instanceof URLSearchParams || ArrayBuffer.isView(body)) {
      return body as BodyInit;
    }

    return JSON.stringify(body);
  }
}

function encodeBase64(value: string): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(value);

  if (typeof btoa === "function") {
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  const globalBuffer = (globalThis as Record<string, unknown>).Buffer as
    | { from(input: Uint8Array, encoding?: string): { toString(encoding: string): string } }
    | undefined;
  if (globalBuffer) {
    return globalBuffer.from(bytes).toString("base64");
  }

  return bytesToBase64(bytes);
}

function decodeBase64(value: string): string {
  const globalBuffer = (globalThis as Record<string, unknown>).Buffer as
    | { from(input: string, encoding: string): { toString(encoding: string): string } }
    | undefined;
  if (globalBuffer) {
    return globalBuffer.from(value, "base64").toString("utf-8");
  }

  const decoder = new TextDecoder();
  const binary = typeof atob === "function" ? atob(value) : atobPolyfill(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
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
      result += chars[(bytes[i] & 0x03) << 4];
      result += "==";
    } else {
      result += chars[((bytes[i] & 0x03) << 4) | (bytes[i + 1] >> 4)];
      result += chars[(bytes[i + 1] & 0x0f) << 2];
      result += "=";
    }
  }

  return result;
}

function atobPolyfill(value: string): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let str = value.replace(/=+$/, "");
  let output = "";
  if (str.length % 4 === 1) {
    throw new Error("Invalid base64 string");
  }
  let bc = 0;
  let bs = 0;
  let buffer: number;
  let idx = 0;
  for (; (buffer = str.charCodeAt(idx++)); ) {
    buffer = chars.indexOf(String.fromCharCode(buffer));
    if (buffer === -1) {
      continue;
    }
    bs = bc % 4 ? bs * 64 + buffer : buffer;
    if (bc++ % 4) {
      output += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6)));
    }
  }
  return output;
}
