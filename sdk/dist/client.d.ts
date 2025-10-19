import { AcceptShareRequest, AcceptShareResponse, LockmateClientConfig, LoginRequest, LoginResponse, PaginatedResponse, RegisterRequest, ShareInviteRequest, ShareRecord, ShareUpdateRequest, VaultCreateRequest, VaultItemDraft, VaultItemRecord, VaultSummary, VaultUpdateRequest, AuthTokens, UserProfile } from "./types";
export declare class LockmateError extends Error {
    readonly status: number;
    readonly details: unknown;
    constructor(message: string, status: number, details: unknown);
}
export declare class LockmateClient {
    private readonly baseUrl;
    private readonly fetchImpl;
    private readonly encryption?;
    private token?;
    constructor(config: LockmateClientConfig);
    /** Returns the active bearer token, if any. */
    getToken(): string | undefined;
    /** Manually sets the bearer token for subsequent requests. */
    setToken(token: string | undefined): void;
    /** Clears the stored bearer token. */
    clearToken(): void;
    register(body: RegisterRequest): Promise<UserProfile>;
    login(body: LoginRequest): Promise<LoginResponse>;
    refresh(refreshToken: string): Promise<AuthTokens>;
    logout(refreshToken: string): Promise<void>;
    getSession(): Promise<UserProfile>;
    listVaults(params?: {
        cursor?: string;
        limit?: number;
    }): Promise<PaginatedResponse<VaultSummary>>;
    createVault(body: VaultCreateRequest): Promise<VaultSummary>;
    getVault(vaultId: string): Promise<VaultSummary>;
    updateVault(vaultId: string, body: VaultUpdateRequest): Promise<VaultSummary>;
    deleteVault(vaultId: string): Promise<void>;
    listVaultItems(vaultId: string, params?: {
        cursor?: string;
        limit?: number;
        tag?: string;
    }): Promise<PaginatedResponse<VaultItemRecord>>;
    createVaultItem(vaultId: string, draft: VaultItemDraft): Promise<VaultItemRecord>;
    getVaultItem(vaultId: string, itemId: string): Promise<VaultItemRecord>;
    updateVaultItem(vaultId: string, itemId: string, draft: VaultItemDraft): Promise<VaultItemRecord>;
    deleteVaultItem(vaultId: string, itemId: string): Promise<void>;
    inviteToVault(vaultId: string, invite: ShareInviteRequest): Promise<ShareRecord>;
    listVaultShares(vaultId: string): Promise<ShareRecord[]>;
    updateVaultShare(vaultId: string, shareId: string, update: ShareUpdateRequest): Promise<ShareRecord>;
    deleteVaultShare(vaultId: string, shareId: string): Promise<void>;
    acceptShare(shareId: string, body: AcceptShareRequest): Promise<AcceptShareResponse>;
    private encryptItem;
    private decryptItem;
    private request;
    private normalizeBody;
}
//# sourceMappingURL=client.d.ts.map