import { LockmateError } from "@lockmate/sdk";
import { FormEvent, useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";

function extractErrorMessage(error: unknown): string {
  if (error instanceof LockmateError) {
    const details = error.details as { message?: string } | undefined;
    if (details?.message) {
      return details.message;
    }
    return "Authentication failed. Please verify your credentials.";
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unexpected error occurred.";
}

export default function LoginPage(): JSX.Element {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const state = location.state as { registered?: boolean; username?: string } | undefined;
    if (state?.registered) {
      setSuccessMessage("Your account has been created. You can sign in now.");
      if (state.username) {
        setUsername(state.username);
      }
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location, navigate]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      await login(username.trim(), password);
      navigate("/vaults");
    } catch (error) {
      setErrorMessage(extractErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Lockmate Web</h1>
        <p className="auth-subtitle">
          Sign in to load your vaults. Secrets are decrypted locally in your browser using
          your master password.
        </p>
        {successMessage && <p className="success-text">{successMessage}</p>}
        <form onSubmit={handleSubmit} className="auth-form">
          <label className="field">
            <span>Username</span>
            <input
              type="text"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </label>
          {errorMessage && <p className="error-text">{errorMessage}</p>}
          <button type="submit" className="primary" disabled={isSubmitting}>
            {isSubmitting ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="auth-helper">
          Don’t have an account? <Link to="/register">Create one</Link>.
        </p>
      </div>
    </div>
  );
}
