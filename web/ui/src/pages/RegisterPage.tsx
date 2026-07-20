import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";

export default function RegisterPage() {
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
      await api.register(email.trim(), password);
      nav(`/verify?email=${encodeURIComponent(email.trim())}`);
    } catch (err: any) {
      setError(String(err.message || err));
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
        <h1>Create account</h1>
        <p className="lead">We’ll email a one-time code. Login unlocks only after verification.</p>
        {error && <div className="error">{error}</div>}
        <div className="field">
          <label>Email</label>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label>Password (min 8 chars)</label>
          <input
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "Creating…" : "Register & send OTP"}
        </button>
        <p className="muted" style={{ marginTop: "1rem", marginBottom: 0 }}>
          Already registered? <Link to="/login">Sign in</Link>
        </p>
      </form>
    </div>
  );
}
