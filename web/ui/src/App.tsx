import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import VerifyPage from "./pages/VerifyPage";
import DashboardPage from "./pages/DashboardPage";
import NewScanPage from "./pages/NewScanPage";
import JobPage from "./pages/JobPage";
import ToolsPage from "./pages/ToolsPage";

function Shell({ user, onLogout, children }: { user: User; onLogout: () => void; children: React.ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const closeMenu = () => setMenuOpen(false);

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  useEffect(() => {
    document.body.classList.toggle("nav-open", menuOpen);
    return () => document.body.classList.remove("nav-open");
  }, [menuOpen]);

  return (
    <div className="shell">
      <header className="topnav">
        <div className="brand">
          Vanta<span>Crawl</span>
        </div>
        <button
          className={`nav-toggle${menuOpen ? " open" : ""}`}
          type="button"
          aria-label={menuOpen ? "Close menu" : "Open menu"}
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((v) => !v)}
        >
          <span />
          <span />
          <span />
        </button>
        <div className={`nav-actions${menuOpen ? " open" : ""}`}>
          <span className="nav-user muted mono">
            {user.email}
            {user.is_admin ? " · admin" : ""}
          </span>
          <a className="btn" href="/" onClick={closeMenu}>
            Jobs
          </a>
          <a className="btn primary" href="/scans/new" onClick={closeMenu}>
            New scan
          </a>
          <a className="btn" href="/tools" onClick={closeMenu}>
            Tools
          </a>
          <button
            className="btn"
            type="button"
            onClick={() => {
              closeMenu();
              onLogout();
            }}
          >
            Log out
          </button>
        </div>
      </header>
      {menuOpen ? <button className="nav-backdrop" type="button" aria-label="Close menu" onClick={closeMenu} /> : null}
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
      <Route
        path="/tools"
        element={
          user ? (
            <Shell user={user} onLogout={logout}>
              <ToolsPage />
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
