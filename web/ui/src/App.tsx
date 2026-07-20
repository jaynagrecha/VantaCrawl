import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import VerifyPage from "./pages/VerifyPage";
import DashboardPage from "./pages/DashboardPage";
import NewScanPage from "./pages/NewScanPage";
import JobPage from "./pages/JobPage";

function Shell({ user, onLogout, children }: { user: User; onLogout: () => void; children: React.ReactNode }) {
  return (
    <div className="shell">
      <header className="topnav">
        <div className="brand">
          Vanta<span>Crawl</span>
        </div>
        <div className="nav-actions">
          <span className="muted mono" style={{ fontSize: ".82rem" }}>
            {user.email}
            {user.is_admin ? " · admin" : ""}
          </span>
          <a className="btn" href="/">
            Jobs
          </a>
          <a className="btn primary" href="/scans/new">
            New scan
          </a>
          <button className="btn" type="button" onClick={onLogout}>
            Log out
          </button>
        </div>
      </header>
      {children}
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="auth-wrap">
        <div className="muted">Loading VantaCrawl…</div>
      </div>
    );
  }

  const logout = () => {
    setToken(null);
    setUser(null);
  };

  return (
    <Routes>
      <Route
        path="/login"
        element={user ? <Navigate to="/" replace /> : <LoginPage onAuth={setUser} />}
      />
      <Route
        path="/register"
        element={user ? <Navigate to="/" replace /> : <RegisterPage />}
      />
      <Route
        path="/verify"
        element={user ? <Navigate to="/" replace /> : <VerifyPage onAuth={setUser} />}
      />
      <Route
        path="/"
        element={
          user ? (
            <Shell user={user} onLogout={logout}>
              <DashboardPage />
            </Shell>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/scans/new"
        element={
          user ? (
            <Shell user={user} onLogout={logout}>
              <NewScanPage />
            </Shell>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route
        path="/jobs/:id"
        element={
          user ? (
            <Shell user={user} onLogout={logout}>
              <JobPage />
            </Shell>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route path="*" element={<Navigate to={user ? "/" : "/login"} replace />} />
    </Routes>
  );
}
