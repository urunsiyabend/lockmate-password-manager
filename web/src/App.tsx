import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import { useAuth } from "./context/AuthContext.tsx";
import AppLayout from "./components/AppLayout.tsx";
import LoginPage from "./pages/LoginPage.tsx";
import RegisterPage from "./pages/RegisterPage.tsx";
import VaultDetailPage from "./pages/VaultDetailPage.tsx";
import VaultItemPage from "./pages/VaultItemPage.tsx";
import VaultListPage from "./pages/VaultListPage.tsx";
import SecurityCenterPage from "./pages/SecurityCenterPage.tsx";

function RequireAuth(): JSX.Element {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

function LayoutOutlet(): JSX.Element {
  return (
    <AppLayout>
      <Outlet />
    </AppLayout>
  );
}

// App.tsx
export default function App(): JSX.Element {
    const { isAuthenticated } = useAuth();

    return (
        <Routes>
            <Route path="login" element={isAuthenticated ? <Navigate to="/vaults" replace /> : <LoginPage />} />
            <Route path="register" element={isAuthenticated ? <Navigate to="/vaults" replace /> : <RegisterPage />} />


            {/* Protected area */}
            <Route element={<RequireAuth />}>
                <Route element={<LayoutOutlet />}>
                    <Route path="security" element={<SecurityCenterPage />} />
                    <Route path="vaults" element={<VaultListPage />} />
                    <Route path="vaults/:vaultId" element={<VaultDetailPage />} />
                    <Route path="vaults/:vaultId/items/:itemId" element={<VaultItemPage />} />
                </Route>
            </Route>

            <Route
                path="*"
                element={<Navigate to={isAuthenticated ? "/vaults" : "/login"} replace />}
            />
        </Routes>
    );
}
