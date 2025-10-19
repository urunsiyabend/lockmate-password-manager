import { PropsWithChildren, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.tsx";

export default function AppLayout({ children }: PropsWithChildren): JSX.Element {
  const { user, logout } = useAuth();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      setIsLoggingOut(true);
      await logout();
      navigate("/login");
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link to="/vaults" className="brand">
          Lockmate Web
        </Link>
        <div className="user-controls">
          {user && <span className="user-name">Signed in as {user.username}</span>}
          <button type="button" onClick={handleLogout} disabled={isLoggingOut}>
            {isLoggingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </header>
      <main className="app-content">{children}</main>
    </div>
  );
}
