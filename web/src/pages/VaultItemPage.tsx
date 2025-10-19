import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";

function SecretField({ label, value }: { label: string; value?: string }): JSX.Element | null {
  if (!value) {
    return null;
  }
  return (
    <div className="secret-field">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export default function VaultItemPage(): JSX.Element {
  const { vaultId, itemId } = useParams();
  const { client } = useAuth();

  const {
    data: item,
    isLoading,
    isError,
    error
  } = useQuery({
    queryKey: ["vaultItem", vaultId, itemId],
    queryFn: async () => {
      if (!vaultId || !itemId) {
        throw new Error("Missing identifiers for the vault item.");
      }
      return client.getVaultItem(vaultId, itemId);
    },
    enabled: Boolean(vaultId && itemId)
  });

  if (!vaultId || !itemId) {
    return <p className="error-text">A vault and item identifier are required.</p>;
  }

  return (
    <section className="panel">
      <header className="panel-header">
        <div>
          <h1>{item ? item.label : "Loading item…"}</h1>
          <p>Secrets are decrypted locally before rendering below.</p>
        </div>
        <Link to={`/vaults/${vaultId}`} className="back-link">
          ← Back to vault
        </Link>
      </header>
      {isLoading && <p>Loading item…</p>}
      {isError && <p className="error-text">{(error as Error).message}</p>}
      {!isLoading && !isError && item && (
        <div className="item-detail">
          <dl>
            <div>
              <dt>Created</dt>
              <dd>{new Date(item.created_at).toLocaleString()}</dd>
            </div>
            <div>
              <dt>Updated</dt>
              <dd>{new Date(item.updated_at).toLocaleString()}</dd>
            </div>
            {item.tags?.length ? (
              <div>
                <dt>Tags</dt>
                <dd>{item.tags.join(", ")}</dd>
              </div>
            ) : null}
            <div>
              <dt>Checksum</dt>
              <dd>{item.checksum ?? "—"}</dd>
            </div>
          </dl>
          <div className="secret-block">
            <h2>Decrypted secret</h2>
            {item.secret ? (
              <dl>
                <SecretField label="Username" value={item.secret.username} />
                <SecretField label="Password" value={item.secret.password} />
                <SecretField label="URI" value={item.secret.uri} />
                <SecretField label="Notes" value={item.secret.notes} />
                {item.secret.fields &&
                  Object.entries(item.secret.fields).map(([key, value]) => (
                    <SecretField key={key} label={key} value={value} />
                  ))}
              </dl>
            ) : (
              <p className="error-text">
                Unable to decrypt this secret with the active session. Please sign in again.
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
