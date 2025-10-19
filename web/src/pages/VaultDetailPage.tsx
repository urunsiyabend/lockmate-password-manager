import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";

export default function VaultDetailPage(): JSX.Element {
  const { vaultId } = useParams();
  const { client } = useAuth();

  const {
    data: vault,
    isLoading: isVaultLoading,
    isError: vaultError,
    error: vaultErrorValue
  } = useQuery({
    queryKey: ["vault", vaultId],
    queryFn: () => client.getVault(vaultId ?? ""),
    enabled: Boolean(vaultId)
  });

  const {
    data: items,
    isLoading: areItemsLoading,
    isError: itemsError,
    error: itemsErrorValue
  } = useQuery({
    queryKey: ["vaultItems", vaultId],
    queryFn: async () => {
      if (!vaultId) {
        return [];
      }
      const response = await client.listVaultItems(vaultId);
      return response.data;
    },
    enabled: Boolean(vaultId)
  });

  if (!vaultId) {
    return <p className="error-text">A vault identifier is required.</p>;
  }

  return (
    <section className="panel">
      <header className="panel-header">
        <h1>{vault ? vault.name : "Loading vault…"}</h1>
        {vault && vault.description && <p>{vault.description}</p>}
      </header>
      {isVaultLoading && <p>Loading vault metadata…</p>}
      {vaultError && <p className="error-text">{(vaultErrorValue as Error).message}</p>}

      <div className="items-section">
        <div className="items-header">
          <h2>Items</h2>
          <p>All vault items are decrypted locally after retrieval.</p>
        </div>
        {areItemsLoading && <p>Loading items…</p>}
        {itemsError && <p className="error-text">{(itemsErrorValue as Error).message}</p>}
        {!areItemsLoading && !itemsError && (
          <ul className="item-list">
            {items?.length ? (
              items.map((item) => (
                <li key={item.id}>
                  <Link to={`/vaults/${vaultId}/items/${item.id}`}>
                    <span className="item-label">{item.label}</span>
                    <span className="item-meta">
                      Updated {new Date(item.updated_at).toLocaleString()}
                    </span>
                  </Link>
                </li>
              ))
            ) : (
              <li className="item-list-empty">No items stored in this vault.</li>
            )}
          </ul>
        )}
      </div>
    </section>
  );
}
