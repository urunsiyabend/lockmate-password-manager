import { LockmateClient, UserProfile, RegisterRequest, VaultItemDraft, VaultItemRecord } from "@lockmate/sdk";
import {
  PropsWithChildren,
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState
} from "react";
import {
  decryptVaultItemRecord,
  deriveMasterKeyFromPassword,
  encryptVaultItemDraft,
  exportKeyToBase64
} from "../lib/encryption.ts";

type AppAuthTokens = {
  token: string;
  refreshToken?: string;
  expiresAt?: string;
};

interface AuthState {
  user?: UserProfile;
  tokens?: AppAuthTokens;
  keySalt?: string;
  vaultKey?: string;
}

export interface AuthContextValue extends AuthState {
  client: LockmateClient;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (input: RegisterRequest) => Promise<UserProfile>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function resolveApiBaseUrl(): string {
  const fallback = "http://localhost:3000/api/v1";
  const value = import.meta.env.VITE_API_BASE_URL;
  if (typeof value === "string" && value.trim().length > 0) {
    return value.replace(/\/$/, "");
  }
  return fallback;
}

/** Safely unwraps API responses that may be enveloped as { status, data } */
function unwrap<T>(resp: any): T {
  return (resp && typeof resp === "object" && "data" in resp ? resp.data : resp) as T;
}

export function AuthProvider({ children }: PropsWithChildren): JSX.Element {
  const [state, setState] = useState<AuthState>({});
  const masterKeyRef = useRef<CryptoKey | undefined>(undefined);
  const baseUrl = resolveApiBaseUrl();

  const client = useMemo(
      () =>
          new LockmateClient({
            baseUrl,
            encryption: {
              encryptItem: async (draft: VaultItemDraft) => {
                const key = masterKeyRef.current;
                if (!key) {
                  throw new Error(
                      "Missing encryption key. Please sign in again to unlock encryption."
                  );
                }
                return encryptVaultItemDraft(draft, key);
              },
              decryptItem: async (record: VaultItemRecord) => {
                const key = masterKeyRef.current;
                if (!key) {
                  // Return the record unchanged if we can't decrypt in this session
                  return record;
                }
                try {
                  const secret = await decryptVaultItemRecord(record, key);
                  return { ...record, secret };
                } catch (error) {
                  console.warn("Unable to decrypt vault item", error);
                  return record;
                }
              }
            }
          }),
      [baseUrl]
  );

  const login = useCallback(
      async (username: string, password: string) => {
        // Your backend returns: { status, data: { token, user, key_salt? ... } }
        const raw = await client.login({ username, password });
        const data = unwrap<{
          token: string;
          user: UserProfile;
          key_salt?: string;
          refreshToken?: string;
          refresh_token?: string;
          expiresAt?: string;
        }>(raw);

        const token = data.token;
        if (!token) {
          throw new Error("Login response missing token");
        }

        client.setToken(token);

        let masterKey: CryptoKey | undefined;
        let vaultKey: string | undefined;
        if (data.key_salt) {
          masterKey = await deriveMasterKeyFromPassword(password, data.key_salt);
          vaultKey = await exportKeyToBase64(masterKey);
        }
        masterKeyRef.current = masterKey;

        const tokens: AppAuthTokens = {
          token,
          refreshToken: data.refreshToken ?? data.refresh_token ?? undefined,
          expiresAt: data.expiresAt ?? undefined
        };

        setState({
          user: data.user,
          keySalt: data.key_salt,
          vaultKey,
          tokens
        });
      },
      [client]
  );

  const register = useCallback(
      async (input: RegisterRequest) => {
        const profile = await client.register(input);
        return unwrap<UserProfile>(profile);
      },
      [client]
  );

  const logout = useCallback(async () => {
    const refreshToken = state.tokens?.refreshToken;
    if (refreshToken) {
      try {
        await client.logout(refreshToken);
      } catch (error) {
        console.warn("Failed to revoke refresh token", error);
      }
    }
    masterKeyRef.current = undefined;
    client.clearToken();
    setState({});
  }, [client, state.tokens?.refreshToken]);

  const value: AuthContextValue = useMemo(
      () => ({
        client,
        user: state.user,
        tokens: state.tokens,
        keySalt: state.keySalt,
        vaultKey: state.vaultKey,
        isAuthenticated: Boolean(state.tokens?.token),
        login,
        register,
        logout
      }),
      [client, state.user, state.tokens, state.keySalt, state.vaultKey, login, register, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
