import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";
import { VaultSummary } from "@lockmate/sdk";

export default function VaultListPage(): JSX.Element {
  const { client } = useAuth();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["vaults"],
    queryFn: async () => {
      const response = await client.listVaults();
      return response.data;
    }
  });

  return (
    <section className="panel">
      <header className="panel-header">
        <h1>Vaults</h1>
        <p>Choose a vault to explore its stored secrets.</p>
      </header>
      {isLoading && <p>Loading vaults…</p>}
      {isError && <p className="error-text">{(error as Error).message}</p>}
      {!isLoading && !isError && (
        <ul className="vault-list">
          {data?.length ? (
            data.map((vault: VaultSummary) => (
              <li key={vault.id} className="vault-list-item">
                <Link to={`/vaults/${vault.id}`}>
                  <h2>{vault.name}</h2>
                  {vault.description && <p>{vault.description}</p>}
                  <dl>
                    <div>
                      <dt>Items</dt>
                      <dd>{vault.item_count ?? "—"}</dd>
                    </div>
                    <div>
                      <dt>Updated</dt>
                      <dd>{new Date(vault.updated_at).toLocaleString()}</dd>
                    </div>
                  </dl>
                </Link>
              </li>
            ))
          ) : (
            <li className="vault-list-empty">No vaults available yet.</li>
          )}
        </ul>
      )}
    </section>
  );
}
