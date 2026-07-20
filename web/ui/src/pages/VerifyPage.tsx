import { FormEvent, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, setToken, User } from "../api";

export default function VerifyPage({ onAuth }: { onAuth: (u: User) => void }) {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const initialEmail = useMemo(() => params.get("email") || "", [params]);
  const [email, setEmail] = useState(initialEmail);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const tok = await api.verifyOtp(email.trim(), code.trim());
      setToken(tok.access_token);
      const me = await api.me();
      onAuth(me);
      nav("/");
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    setBusy(true);
    setError("");
    setInfo("");
    try {
      const res = await api.resendOtp(email.trim());
      setInfo(res.message);
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
        <h1>Verify email</h1>
        <p className="lead">Enter the 6-digit code we sent via Gmail SMTP.</p>
        {error && <div className="error">{error}</div>}
        {info && <div className="success">{info}</div>}
        <div className="field">
          <label>Email</label>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label>OTP code</label>
          <input
            className="otp-input"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="••••••"
          />
        </div>
        <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "Verifying…" : "Verify & continue"}
        </button>
        <button className="btn" type="button" onClick={resend} disabled={busy} style={{ width: "100%", marginTop: ".6rem" }}>
          Resend code
        </button>
        <p className="muted" style={{ marginTop: "1rem", marginBottom: 0 }}>
          <Link to="/login">Back to sign in</Link>
        </p>
      </form>
    </div>
  );
}
