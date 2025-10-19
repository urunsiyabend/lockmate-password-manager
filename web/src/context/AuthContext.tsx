import { LockmateClient, AuthTokens, UserProfile } from "@lockmate/sdk";
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
  encryptVaultItemDraft
} from "../lib/encryption.ts";

interface AuthState {
  user?: UserProfile;
  tokens?: AuthTokens;
  keySalt?: string;
}

interface AuthContextValue extends AuthState {
  client: LockmateClient;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
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

export function AuthProvider({ children }: PropsWithChildren): JSX.Element {
  const [state, setState] = useState<AuthState>({});
  const masterKeyRef = useRef<CryptoKey | undefined>(undefined);
  const baseUrl = resolveApiBaseUrl();

  const client = useMemo(
    () =>
      new LockmateClient({
        baseUrl,
        encryption: {
          encryptItem: async (draft) => {
            const key = masterKeyRef.current;
            if (!key) {
              throw new Error(
                "Missing encryption key. Please sign in again to unlock encryption."
              );
            }
            return encryptVaultItemDraft(draft, key);
          },
          decryptItem: async (record) => {
            const key = masterKeyRef.current;
            if (!key) {
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
      const response = await client.login({ username, password });
      client.setToken(response.token);

      let masterKey: CryptoKey | undefined;
      if (response.key_salt) {
        masterKey = await deriveMasterKeyFromPassword(password, response.key_salt);
      }
      masterKeyRef.current = masterKey;

      setState({
        user: response.user,
        keySalt: response.key_salt,
        tokens: {
          token: response.token,
          refreshToken: response.refreshToken,
          expiresAt: response.expiresAt
        }
      });
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

  const value: AuthContextValue = {
    client,
    user: state.user,
    tokens: state.tokens,
    keySalt: state.keySalt,
    isAuthenticated: Boolean(state.tokens?.token),
    login,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
