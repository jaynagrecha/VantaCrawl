import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, setToken, User } from "../api";

export default function LoginPage({ onAuth }: { onAuth: (u: User) => void }) {
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const tok = await api.login(email.trim(), password);
      setToken(tok.access_token);
      const me = await api.me();
      onAuth(me);
      nav("/");
    } catch (err: any) {
      const msg = String(err.message || err);
      setError(msg);
      if (msg.toLowerCase().includes("not verified")) {
        nav(`/verify?email=${encodeURIComponent(email.trim())}`);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="card auth-card" onSubmit={submit}>
        <div className="brand" style={{ marginBottom: ".5rem" }}>
          Vanta<span>Crawl</span>
        </div>
        <h1>Welcome back</h1>
        <p className="lead">Sign in to run authorized scans and open live reports.</p>
        {error && <div className="error">{error}</div>}
        <div className="field">
          <label>Email</label>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label>Password</label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="muted" style={{ marginTop: "1rem", marginBottom: 0 }}>
          No account? <Link to="/register">Register</Link>
        </p>
      </form>
    </div>
  );
}
