export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export interface LockmateClientConfig {
    /** Base URL for the API, e.g. https://api.lockmate.io */
    baseUrl: string;
    /** Custom fetch implementation. Defaults to the global fetch if available. */
    fetchImpl?: FetchLike;
    /** Optional encryption hooks for processing vault item payloads. */
    encryption?: EncryptionHooks;
    /** Existing bearer token to seed the client with. */
    token?: string;
}
export interface EncryptionHooks {
    /**
     * Transforms a plaintext item draft into the encrypted payload persisted by the API.
     * If omitted, the SDK will JSON.stringify the `secret` field and treat it as opaque ciphertext.
     */
    encryptItem?(input: VaultItemDraft): Promise<EncryptedVaultItemPayload> | EncryptedVaultItemPayload;
    /**
     * Allows callers to decrypt ciphertext fields before returning them to the application.
     * If omitted, ciphertext fields are left untouched.
     */
    decryptItem?(payload: VaultItemRecord): Promise<VaultItemRecord> | VaultItemRecord;
}
export interface AuthTokens {
    token: string;
    refreshToken: string;
    expiresAt: string;
}
export interface UserProfile {
    id: string;
    email: string;
    username: string;
    created_at?: string;
}
export interface RegisterRequest {
    email: string;
    username: string;
    password: string;
    master_password_hint?: string;
}
export interface LoginRequest {
    username: string;
    password: string;
}
export interface LoginResponse extends AuthTokens {
    user: UserProfile;
    key_salt?: string;
}
export interface VaultSummary {
    id: string;
    name: string;
    description?: string;
    owner_id: string;
    created_at: string;
    updated_at: string;
    item_count?: number;
}
export interface VaultCreateRequest {
    name: string;
    description?: string;
}
export interface VaultUpdateRequest {
    name?: string;
    description?: string;
}
export interface VaultItemDraft {
    label: string;
    secret: VaultSecret;
    tags?: string[];
    checksum?: string;
}
export interface VaultSecret {
    username?: string;
    password?: string;
    uri?: string;
    notes?: string;
    fields?: Record<string, string>;
}
export interface EncryptedVaultItemPayload {
    label: string;
    ciphertext: string;
    tags?: string[];
    checksum?: string;
}
export interface VaultItemRecord extends EncryptedVaultItemPayload {
    id: string;
    vault_id: string;
    created_at: string;
    updated_at: string;
    /**
     * Optional decrypted secret returned by custom hooks for convenience.
     */
    secret?: VaultSecret;
}
export interface PaginatedResponse<T> {
    data: T[];
    next_cursor: string | null;
}
export type ShareRole = "owner" | "admin" | "editor" | "viewer";
export interface ShareInviteRequest {
    email: string;
    role: ShareRole;
    message?: string;
}
export interface ShareRecord {
    id: string;
    vault_id: string;
    inviter_id: string;
    invitee_email: string;
    role: ShareRole;
    status: "pending" | "active" | "revoked" | "expired";
    created_at: string;
    updated_at?: string;
}
export interface ShareUpdateRequest {
    role?: ShareRole;
    status?: "pending" | "active" | "revoked" | "expired";
}
export interface AcceptShareRequest {
    invite_token: string;
    public_key: string;
}
export interface AcceptShareResponse {
    membership_id: string;
    vault_id: string;
    role: ShareRole;
    status: "active";
    created_at: string;
}
//# sourceMappingURL=types.d.ts.map