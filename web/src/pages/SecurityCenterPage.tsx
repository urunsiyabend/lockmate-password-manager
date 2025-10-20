import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { SecurityHealthFinding, SecurityHealthMetadata } from "@lockmate/sdk";
import { useMemo } from "react";
import { useAuth } from "../context/AuthContext.tsx";

type AffectedItem = NonNullable<SecurityHealthMetadata["affected_items"]>[number];

type Severity = SecurityHealthFinding["severity"];

const severityLabels: Record<Severity, string> = {
  low: "Low",
  medium: "Medium",
  high: "High"
};

const severityClassNames: Record<Severity, string> = {
  low: "health-finding--low",
  medium: "health-finding--medium",
  high: "health-finding--high"
};

function extractAffectedItems(finding: SecurityHealthFinding): AffectedItem[] {
  const metadata = finding.metadata;
  if (!metadata || !Array.isArray(metadata.affected_items)) {
    return [];
  }
  return metadata.affected_items.filter((item): item is AffectedItem => Boolean(item?.id));
}

function renderAffectedItems(items: AffectedItem[]): JSX.Element | null {
  if (!items.length) {
    return null;
  }

  return (
    <ul className="affected-items">
      {items.map((item) => (
        <li key={item.id}>
          <strong>{item.title ?? "Untitled item"}</strong>
          {item.username && <span> — {item.username}</span>}
          {item.url && (
            <span>
              {" "}
              · {item.url}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

export default function SecurityCenterPage(): JSX.Element {
  const { client, vaultKey } = useAuth();
  const queryClient = useQueryClient();

  const {
    data,
    isLoading,
    isError,
    error
  } = useQuery({
    queryKey: ["security-health"],
    queryFn: () => client.getSecurityHealth()
  });

  const findings = data?.findings ?? [];
  const generatedAt = useMemo(() => {
    if (!data?.generated_at) {
      return null;
    }
    return new Date(data.generated_at).toLocaleString();
  }, [data?.generated_at]);

  const mutation = useMutation({
    mutationFn: async () => {
      if (!vaultKey) {
        throw new Error(
          "Missing vault key. Sign out and back in to derive the encryption key before running the check."
        );
      }
      return client.runSecurityHealthCheck(vaultKey);
    },
    onSuccess: (summary) => {
      queryClient.setQueryData(["security-health"], summary);
    }
  });

  return (
    <section className="panel">
      <header className="panel-header security-header">
        <div>
          <h1>Security Center</h1>
          <p>
            Review potential risks across your vault and follow the remediation tips to keep your credentials safe.
          </p>
          {generatedAt && (
            <p className="generated-at">Report generated on {generatedAt}</p>
          )}
        </div>
        <button
          type="button"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="primary"
        >
          {mutation.isPending ? "Scanning…" : "Run health check"}
        </button>
      </header>

      {isLoading && <p>Loading security findings…</p>}
      {isError && <p className="error-text">{(error as Error).message}</p>}
      {mutation.isError && (
        <p className="error-text">{(mutation.error as Error).message}</p>
      )}

      {!isLoading && !isError && findings.length === 0 && (
        <div className="health-empty">
          <h2>No risks detected 🎉</h2>
          <p>
            All checked passwords appear unique and uncompromised. Run another scan after updating vault items to keep things
            current.
          </p>
        </div>
      )}

      {!isLoading && !isError && findings.length > 0 && (
        <ul className="health-findings">
          {findings.map((finding) => (
            <li key={finding.id} className={`health-finding ${severityClassNames[finding.severity]}`}>
              <header>
                <span className="severity-badge">{severityLabels[finding.severity]}</span>
                <h2>{finding.title}</h2>
              </header>
              <p>{finding.description}</p>
              <p className="remediation">
                <strong>Remediation:</strong> {finding.remediation}
              </p>
              {finding.metadata?.breach_count && (
                <p className="metadata-note">Detected in {finding.metadata.breach_count} known breaches.</p>
              )}
              {finding.metadata?.item_count && (
                <p className="metadata-note">Impacts {finding.metadata.item_count} items.</p>
              )}
              {renderAffectedItems(extractAffectedItems(finding))}
              <footer>
                <small>Recorded on {new Date(finding.created_at).toLocaleString()}</small>
              </footer>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
