import { useMutation, useQuery } from "@tanstack/react-query";
import type { PasswordGenerationOptions, PasswordStrengthReport } from "@lockmate/sdk";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
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

const DEFAULT_OPTIONS: PasswordGenerationOptions = {
  word_count: 4,
  separator: "-",
  capitalize: true,
  include_number: true,
  number_digits: 2,
  include_symbol: false,
  symbol_set: "!@#$%^&*"
};

const STRENGTH_LABELS: Record<PasswordStrengthReport["score"], string> = {
  very_weak: "Very weak",
  weak: "Weak",
  moderate: "Moderate",
  strong: "Strong",
  very_strong: "Very strong"
};

function resolveErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return fallback;
}

function formatStrengthLabel(score: PasswordStrengthReport["score"]): string {
  return STRENGTH_LABELS[score] ?? score;
}

function formatCrackTime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "Instant";
  }
  const units = [
    { label: "years", value: 31_557_600 },
    { label: "days", value: 86_400 },
    { label: "hours", value: 3_600 },
    { label: "minutes", value: 60 },
    { label: "seconds", value: 1 }
  ];
  for (const unit of units) {
    if (seconds >= unit.value * 2) {
      const amount = Math.floor(seconds / unit.value);
      return `${amount} ${unit.label}`;
    }
  }
  return `${seconds.toFixed(2)} seconds`;
}

export default function VaultItemPage(): JSX.Element {
  const { vaultId, itemId } = useParams();
  const { client } = useAuth();
  const [generatorOptions, setGeneratorOptions] = useState<PasswordGenerationOptions>(DEFAULT_OPTIONS);
  const [passwordInput, setPasswordInput] = useState("");
  const [strengthReport, setStrengthReport] = useState<PasswordStrengthReport | undefined>(undefined);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
  const copyTimeoutRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) {
        window.clearTimeout(copyTimeoutRef.current);
      }
    };
  }, []);

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

  const generateMutation = useMutation({
    mutationFn: async (options: PasswordGenerationOptions) => client.generatePassword(options)
  });

  const strengthMutation = useMutation({
    mutationFn: async (value: string) => client.evaluatePasswordStrength(value)
  });

  const generating = generateMutation.isPending;
  const evaluating = strengthMutation.isPending;

  const handleGenerate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const result = await generateMutation.mutateAsync(generatorOptions);
      setGeneratedPassword(result.password);
      setPasswordInput(result.password);
      setStrengthReport(result.strength);
      setCopyFeedback(null);
    } catch (err) {
      console.error("Failed to generate passphrase", err);
    }
  };

  const handleStrengthCheck = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const result = await strengthMutation.mutateAsync(passwordInput);
      setStrengthReport(result);
      setCopyFeedback(null);
    } catch (err) {
      console.error("Failed to evaluate password strength", err);
    }
  };

  const handleCopy = async () => {
    if (!generatedPassword) {
      return;
    }
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(generatedPassword);
        setCopyFeedback("Copied to clipboard!");
        if (copyTimeoutRef.current) {
          window.clearTimeout(copyTimeoutRef.current);
        }
        copyTimeoutRef.current = window.setTimeout(() => setCopyFeedback(null), 2000);
      } else {
        setCopyFeedback("Clipboard unavailable");
      }
    } catch (err) {
      console.warn("Unable to copy password", err);
      setCopyFeedback("Clipboard unavailable");
    }
  };

  const complexityFlags = useMemo(() => {
    if (!strengthReport) {
      return [] as Array<{ label: string; ok: boolean }>;
    }
    return [
      { label: "Lowercase", ok: Boolean(strengthReport.complexity.has_lowercase) },
      { label: "Uppercase", ok: Boolean(strengthReport.complexity.has_uppercase) },
      { label: "Numbers", ok: Boolean(strengthReport.complexity.has_numbers) },
      { label: "Symbols", ok: Boolean(strengthReport.complexity.has_symbols) }
    ];
  }, [strengthReport]);

  if (!vaultId || !itemId) {
    return <p className="error-text">A vault and item identifier are required.</p>;
  }

  const generatorErrorMessage = generateMutation.isError
    ? resolveErrorMessage(generateMutation.error, "Unable to generate a passphrase.")
    : null;
  const strengthErrorMessage = strengthMutation.isError
    ? resolveErrorMessage(strengthMutation.error, "Unable to evaluate password strength.")
    : null;

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
          <div className="tool-block">
            <div>
              <h2>Password tools</h2>
              <p>
                Generate a unique passphrase and review its strength before storing or sharing credentials.
              </p>
            </div>
            <form className="generator-form" onSubmit={handleGenerate}>
              <div className="generator-grid">
                <label className="field">
                  <span>Words</span>
                  <input
                    type="number"
                    min={2}
                    max={16}
                    value={generatorOptions.word_count ?? 4}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        word_count: Number.parseInt(event.target.value, 10) || 0
                      }))
                    }
                  />
                </label>
                <label className="field">
                  <span>Digits</span>
                  <input
                    type="number"
                    min={1}
                    max={8}
                    value={generatorOptions.number_digits ?? 2}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        number_digits: Number.parseInt(event.target.value, 10) || 1
                      }))
                    }
                  />
                </label>
                <label className="field">
                  <span>Separator</span>
                  <input
                    type="text"
                    maxLength={3}
                    value={generatorOptions.separator ?? "-"}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        separator: event.target.value
                      }))
                    }
                  />
                </label>
                <label className="field">
                  <span>Symbol pool</span>
                  <input
                    type="text"
                    value={generatorOptions.symbol_set ?? "!@#$%^&*"}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        symbol_set: event.target.value
                      }))
                    }
                    disabled={!generatorOptions.include_symbol}
                  />
                </label>
              </div>
              <div className="generator-toggles">
                <label className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={Boolean(generatorOptions.capitalize)}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        capitalize: event.target.checked
                      }))
                    }
                  />
                  <span>Capitalize words</span>
                </label>
                <label className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={Boolean(generatorOptions.include_number)}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        include_number: event.target.checked
                      }))
                    }
                  />
                  <span>Append digits</span>
                </label>
                <label className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={Boolean(generatorOptions.include_symbol)}
                    onChange={(event) =>
                      setGeneratorOptions((prev) => ({
                        ...prev,
                        include_symbol: event.target.checked
                      }))
                    }
                  />
                  <span>Append symbol</span>
                </label>
              </div>
              <div className="generator-actions">
                <button type="submit" disabled={generating}>
                  {generating ? "Generating…" : "Generate passphrase"}
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={handleCopy}
                  disabled={!generatedPassword}
                >
                  Copy to clipboard
                </button>
                {copyFeedback && <span className="hint-text">{copyFeedback}</span>}
              </div>
              {generatedPassword && (
                <div className="generated-output">
                  <code>{generatedPassword}</code>
                </div>
              )}
              {generatorErrorMessage && <p className="error-text">{generatorErrorMessage}</p>}
            </form>
            <form className="strength-form" onSubmit={handleStrengthCheck}>
              <label className="field">
                <span>Check a password</span>
                <input
                  type="text"
                  value={passwordInput}
                  onChange={(event) => setPasswordInput(event.target.value)}
                  placeholder="Enter a password or paste one here"
                />
              </label>
              <div className="generator-actions">
                <button type="submit" disabled={evaluating}>
                  {evaluating ? "Evaluating…" : "Evaluate strength"}
                </button>
              </div>
              {strengthErrorMessage && <p className="error-text">{strengthErrorMessage}</p>}
            </form>
            {strengthReport && (
              <div className="strength-block">
                <div className="strength-header">
                  <span className={`strength-badge ${strengthReport.score}`}>
                    {formatStrengthLabel(strengthReport.score)}
                  </span>
                  <span className="strength-metric">{strengthReport.entropy_bits.toFixed(2)} bits of entropy</span>
                </div>
                <dl>
                  <div>
                    <dt>Length</dt>
                    <dd>{strengthReport.length} characters</dd>
                  </div>
                  <div>
                    <dt>Character set size</dt>
                    <dd>{strengthReport.charset_size}</dd>
                  </div>
                  <div>
                    <dt>Offline crack time</dt>
                    <dd>{formatCrackTime(strengthReport.crack_time_seconds)}</dd>
                  </div>
                </dl>
                <div>
                  <h3>Composition</h3>
                  <ul className="complexity-list">
                    {complexityFlags.map((flag) => (
                      <li
                        key={flag.label}
                        className={`complexity-item ${flag.ok ? "ok" : "missing"}`}
                      >
                        {flag.ok ? "✔" : "○"} {flag.label}
                      </li>
                    ))}
                  </ul>
                </div>
                {strengthReport.suggestions.length ? (
                  <div>
                    <h3>Suggestions</h3>
                    <ul className="suggestion-list">
                      {strengthReport.suggestions.map((suggestion) => (
                        <li key={suggestion}>{suggestion}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
