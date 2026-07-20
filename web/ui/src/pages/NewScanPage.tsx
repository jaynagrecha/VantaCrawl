import { FormEvent, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

type Meta = {
  modes: Record<string, { label: string; preset: Record<string, unknown> }>;
  speeds: Record<string, { label: string }>;
  default_settings: Record<string, unknown>;
  setting_groups: { id: string; title: string; keys: string[] }[];
};

export default function NewScanPage() {
  const nav = useNavigate();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [startUrl, setStartUrl] = useState("https://");
  const [title, setTitle] = useState("");
  const [mode, setMode] = useState("full_audit");
  const [speed, setSpeed] = useState("balanced");
  const [authorized, setAuthorized] = useState(false);
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [tab, setTab] = useState("core");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .meta()
      .then((m) => {
        setMeta(m);
        const preset = m.modes?.full_audit?.preset || {};
        setSettings({ ...m.default_settings, ...preset });
        if (preset.speed) setSpeed(String(preset.speed));
      })
      .catch((err) => setError(String(err.message || err)));
  }, []);

  useEffect(() => {
    if (!meta) return;
    const preset = meta.modes[mode]?.preset || {};
    setSettings((prev) => ({ ...meta.default_settings, ...prev, ...preset }));
    if (preset.speed) setSpeed(String(preset.speed));
  }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps

  const groups = meta?.setting_groups || [];
  const activeKeys = useMemo(
    () => groups.find((g) => g.id === tab)?.keys || [],
    [groups, tab]
  );

  function setSetting(key: string, value: unknown) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const job = await api.createJob({
        start_url: startUrl.trim(),
        title: title.trim(),
        mode,
        speed,
        authorized_confirmed: authorized,
        settings,
      });
      nav(`/jobs/${job.id}`);
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setBusy(false);
    }
  }

  if (!meta) {
    return <div className="card muted">Loading scan catalog…</div>;
  }

  return (
    <form onSubmit={submit}>
      <section className="card">
        <h1>New scan</h1>
        <p className="lead">Full desktop parity — mode presets, speed profiles, and expert toggles.</p>
        {error && <div className="error">{error}</div>}
        <div className="grid-2">
          <div>
            <div className="field">
              <label>Target URL</label>
              <input required value={startUrl} onChange={(e) => setStartUrl(e.target.value)} />
            </div>
            <div className="field">
              <label>Title (optional)</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Lab assessment" />
            </div>
            <div className="field">
              <label>Mode</label>
              <select value={mode} onChange={(e) => setMode(e.target.value)}>
                {Object.entries(meta.modes).map(([key, val]) => (
                  <option key={key} value={key}>
                    {val.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Parallelism</label>
              <select value={speed} onChange={(e) => setSpeed(e.target.value)}>
                {Object.entries(meta.speeds).map(([key, val]) => (
                  <option key={key} value={key}>
                    {val.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
              />
              <span>
                <strong>I confirm this target is authorized for testing.</strong>
                <br />
                <span className="muted">Required. Scans will not start without this confirmation.</span>
              </span>
            </label>
            <button className="btn primary" type="submit" disabled={busy || !authorized}>
              {busy ? "Starting…" : "Start scan"}
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <h2>Expert settings</h2>
        <div className="tabs">
          {groups.map((g) => (
            <button
              key={g.id}
              type="button"
              className={`tab ${tab === g.id ? "active" : ""}`}
              onClick={() => setTab(g.id)}
            >
              {g.title}
            </button>
          ))}
        </div>
        <div className="settings-grid">
          {activeKeys.map((key) => {
            const value = settings[key];
            if (typeof value === "boolean") {
              return (
                <div className="setting-item" key={key}>
                  <label>
                    <input
                      type="checkbox"
                      checked={Boolean(value)}
                      onChange={(e) => setSetting(key, e.target.checked)}
                    />
                    <span className="mono">{key}</span>
                  </label>
                </div>
              );
            }
            if (typeof value === "number") {
              return (
                <div className="field" key={key} style={{ marginBottom: 0 }}>
                  <label className="mono">{key}</label>
                  <input
                    type="number"
                    value={Number(value)}
                    onChange={(e) => setSetting(key, Number(e.target.value))}
                  />
                </div>
              );
            }
            return (
              <div className="field" key={key} style={{ marginBottom: 0 }}>
                <label className="mono">{key}</label>
                <input
                  value={value == null ? "" : String(value)}
                  onChange={(e) => setSetting(key, e.target.value)}
                />
              </div>
            );
          })}
        </div>
      </section>
    </form>
  );
}
