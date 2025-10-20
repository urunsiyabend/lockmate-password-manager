import { LockmateError } from "@lockmate/sdk";
import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";

function extractErrorMessage(error: unknown): string {
  if (error instanceof LockmateError) {
    const details = error.details as { message?: string } | undefined;
    if (details?.message) {
      return details.message;
    }
    return "Registration failed. Please check your details and try again.";
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unexpected error occurred.";
}

export default function RegisterPage(): JSX.Element {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [masterPasswordHint, setMasterPasswordHint] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorMessage(null);

    if (password !== confirmPassword) {
      setErrorMessage("Passwords do not match");
      return;
    }

    setIsSubmitting(true);

    try {
      await register({
        email: email.trim(),
        username: username.trim(),
        password,
        master_password_hint: masterPasswordHint.trim() || undefined
      });
      navigate("/login", {
        replace: true,
        state: { registered: true, username: username.trim() }
      });
    } catch (error) {
      setErrorMessage(extractErrorMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Create your Lockmate account</h1>
        <p className="auth-subtitle">
          Lockmate encrypts your secrets locally before syncing. Only you can decrypt them with your master password.
        </p>
        <form onSubmit={handleSubmit} className="auth-form">
          <label className="field">
            <span>Email</span>
            <input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </label>
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
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              minLength={8}
            />
          </label>
          <label className="field">
            <span>Confirm password</span>
            <input
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
              minLength={8}
            />
          </label>
          <label className="field">
            <span>Master password hint (optional)</span>
            <input
              type="text"
              value={masterPasswordHint}
              onChange={(event) => setMasterPasswordHint(event.target.value)}
              placeholder="Only you should understand this hint"
            />
          </label>
          {errorMessage && <p className="error-text">{errorMessage}</p>}
          <button type="submit" className="primary" disabled={isSubmitting}>
            {isSubmitting ? "Creating account…" : "Create account"}
          </button>
        </form>
        <p className="auth-helper">
          Already have an account? <Link to="/login">Sign in</Link>.
        </p>
      </div>
    </div>
  );
}
