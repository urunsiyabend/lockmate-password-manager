import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext.tsx";
import { useVaultKey } from "../hooks/useVaultKey";
import { Link } from "react-router-dom";
import { useState } from "react";

type VaultItemView = {
    id: string;
    title: string;
    username?: string | null;
    url?: string | null;
    notes?: string | null;
    created_at: string; // RFC3339
    updated_at: string; // RFC3339
    folder_id?: string | null;
    user_id: string;
};

type CreateFormState = {
    title: string;
    username?: string;
    password?: string;
    url?: string;
    notes?: string;
};

export default function VaultListPage(): JSX.Element {
    const { client } = useAuth();
    const { vaultKey, setVaultKey } = useVaultKey();
    const queryClient = useQueryClient();

    const [showCreate, setShowCreate] = useState(false);
    const [form, setForm] = useState<CreateFormState>({ title: "" });

    const { data, isLoading, isError, error } = useQuery({
        queryKey: ["vault-items", vaultKey],
        enabled: Boolean(vaultKey), // only run when we have a key
        queryFn: async () => {
            const items = await client.listVaultItems(vaultKey);
            return items as VaultItemView[];
        }
    });

    const createMutation = useMutation({
        mutationFn: async (payload: CreateFormState) => {
            if (!vaultKey) throw new Error("Vault key missing");
            return client.createVaultItem(
                {
                    title: payload.title.trim(),
                    username: payload.username?.trim() || undefined,
                    password: payload.password || undefined,
                    url: payload.url?.trim() || undefined,
                    notes: payload.notes?.trim() || undefined
                },
                vaultKey
            );
        },
        onSuccess: async () => {
            // Refresh list
            await queryClient.invalidateQueries({ queryKey: ["vault-items", vaultKey] });
            // Reset and hide form
            setForm({ title: "" });
            setShowCreate(false);
        }
    });

    return (
        <section className="panel">
            <header className="panel-header">
                <h1>Vault Items</h1>
                <p>Browse your stored secrets. Set your vault key to decrypt them.</p>

                {vaultKey && (
                    <div className="actions">
                        {!showCreate ? (
                            <button
                                className="btn btn-primary"
                                onClick={() => setShowCreate(true)}
                            >
                                + Create item
                            </button>
                        ) : (
                            <button
                                className="btn"
                                onClick={() => setShowCreate(false)}
                                disabled={createMutation.isPending}
                            >
                                Cancel
                            </button>
                        )}
                    </div>
                )}
            </header>

            {!vaultKey && <VaultKeyForm onSave={(key) => setVaultKey(key)} />}

            {vaultKey && showCreate && (
                <CreateItemForm
                    value={form}
                    onChange={setForm}
                    onSubmit={() => createMutation.mutate(form)}
                    isSubmitting={createMutation.isPending}
                    errorText={createMutation.error ? (createMutation.error as Error).message : undefined}
                />
            )}

            {vaultKey && isLoading && <p>Loading items…</p>}
            {vaultKey && isError && <p className="error-text">{(error as Error).message}</p>}

            {vaultKey && !isLoading && !isError && (
                <ul className="vault-list">
                    {data?.length ? (
                        data.map((item) => (
                            <li key={item.id} className="vault-list-item">
                                <Link to={`/items/${item.id}`}>
                                    <h2>{item.title}</h2>
                                    {item.url && <p>{item.url}</p>}
                                    <dl>
                                        <div>
                                            <dt>User</dt>
                                            <dd>{item.username ?? "—"}</dd>
                                        </div>
                                        <div>
                                            <dt>Updated</dt>
                                            <dd>{new Date(item.updated_at).toLocaleString()}</dd>
                                        </div>
                                    </dl>
                                </Link>
                            </li>
                        ))
                    ) : (
                        <li className="vault-list-empty">No items yet.</li>
                    )}
                </ul>
            )}
        </section>
    );
}

function VaultKeyForm({ onSave }: { onSave: (key: string) => void }) {
    const [value, setValue] = React.useState("");
    const [error, setError] = React.useState<string | null>(null);

    function isValidBase64Key(k: string): boolean {
        try {
            // decode base64 (browser-safe)
            const bin = atob(k);
            return bin.length === 32; // must be 32 bytes = 256 bits
        } catch {
            return false;
        }
    }

    function generateKey(): string {
        const b = new Uint8Array(32);
        crypto.getRandomValues(b);
        let s = "";
        for (const x of b) s += String.fromCharCode(x);
        return btoa(s); // standard base64
    }

    return (
        <form
            className="vault-key-form"
            onSubmit={(e) => {
                e.preventDefault();
                if (!isValidBase64Key(value)) {
                    setError("Vault key must be base64 of exactly 32 bytes (256-bit).");
                    return;
                }
                setError(null);
                onSave(value.trim());
            }}
        >
            <label htmlFor="vaultKey">Vault Key</label>
            <div style={{ display: "flex", gap: 8 }}>
                <input
                    id="vaultKey"
                    name="vaultKey"
                    type="password"
                    placeholder="Paste 44-char base64 key (ends with = or ==)"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    required
                    style={{ flex: 1 }}
                />
                <button
                    type="button"
                    className="btn"
                    onClick={() => {
                        const k = generateKey();
                        setValue(k);
                        setError(null);
                    }}
                    title="Generate a new 256-bit key"
                >
                    Generate
                </button>
            </div>
            {error && <p className="error-text" style={{ marginTop: 6 }}>{error}</p>}
            <button type="submit" className="btn btn-primary" style={{ marginTop: 8 }}>
                Save
            </button>
        </form>
    );
}


function CreateItemForm({
                            value,
                            onChange,
                            onSubmit,
                            isSubmitting,
                            errorText
                        }: {
    value: CreateFormState;
    onChange: (v: CreateFormState) => void;
    onSubmit: () => void;
    isSubmitting: boolean;
    errorText?: string;
}) {
    return (
        <form
            className="card create-item-form"
            onSubmit={(e) => {
                e.preventDefault();
                if (!value.title.trim()) return;
                onSubmit();
            }}
        >
            <h2>Create vault item</h2>

            <div className="grid">
                <label>
                    <span>Title *</span>
                    <input
                        type="text"
                        value={value.title}
                        onChange={(e) => onChange({ ...value, title: e.target.value })}
                        required
                    />
                </label>

                <label>
                    <span>Username</span>
                    <input
                        type="text"
                        value={value.username ?? ""}
                        onChange={(e) => onChange({ ...value, username: e.target.value })}
                    />
                </label>

                <label>
                    <span>Password</span>
                    <input
                        type="password"
                        value={value.password ?? ""}
                        onChange={(e) => onChange({ ...value, password: e.target.value })}
                    />
                </label>

                <label>
                    <span>URL</span>
                    <input
                        type="url"
                        value={value.url ?? ""}
                        onChange={(e) => onChange({ ...value, url: e.target.value })}
                        placeholder="https://example.com"
                    />
                </label>

                <label className="full">
                    <span>Notes</span>
                    <textarea
                        rows={3}
                        value={value.notes ?? ""}
                        onChange={(e) => onChange({ ...value, notes: e.target.value })}
                    />
                </label>
            </div>

            {errorText && <p className="error-text" style={{ marginTop: 8 }}>{errorText}</p>}

            <div className="actions" style={{ marginTop: 12 }}>
                <button type="submit" className="btn btn-primary" disabled={isSubmitting || !value.title.trim()}>
                    {isSubmitting ? "Creating…" : "Create item"}
                </button>
            </div>
        </form>
    );
}
