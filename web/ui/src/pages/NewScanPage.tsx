import { FormEvent, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

type FieldMeta = {
  key: string;
  label: string;
  help: string;
  control: string;
  options: { value: string; label: string }[];
  presets: { value: string; label: string }[];
};

type WordlistItem = { id: string; label: string; path?: string };

type Meta = {
  modes: Record<string, { label: string; preset: Record<string, unknown> }>;
  speeds: Record<string, { label: string }>;
  default_settings: Record<string, unknown>;
  setting_groups: { id: string; title: string; keys: string[] }[];
  setting_fields?: Record<string, FieldMeta>;
  wordlists?: WordlistItem[];
};

function humanize(key: string) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function SettingControl({
  fieldKey,
  value,
  meta,
  onChange,
}: {
  fieldKey: string;
  value: unknown;
  meta?: FieldMeta;
  onChange: (key: string, value: unknown) => void;
}) {
  const label = meta?.label || humanize(fieldKey);
  const help = meta?.help || "";
  const control = meta?.control || "auto";
  const options = meta?.options || [];
  const presets = meta?.presets || [];

  const isBool = typeof value === "boolean" || control === "checkbox";
  const isNumber = typeof value === "number" || control === "number";
  const isSelect = control === "select" && options.length > 0;
  const isPresetText = control === "text_with_presets";
  const isPassword = control === "password";

  if (isBool) {
    return (
      <div className="setting-item" key={fieldKey}>
        <label>
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(fieldKey, e.target.checked)}
          />
          <span>
            <span className="setting-label">{label}</span>
            {help ? <span className="setting-help">{help}</span> : null}
          </span>
        </label>
      </div>
    );
  }

  if (isSelect) {
    const current = value == null ? "" : String(value);
    const known = options.some((o) => o.value === current);
    return (
      <div className="field setting-field" key={fieldKey}>
        <label>{label}</label>
        {help ? <p className="setting-help-inline">{help}</p> : null}
        <select value={known ? current : current} onChange={(e) => onChange(fieldKey, e.target.value)}>
          {!known && current ? <option value={current}>{current} (custom)</option> : null}
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
    );
  }

  if (isPresetText) {
    const text = value == null ? "" : String(value);
    const matched = presets.find((p) => p.value === text);
    return (
      <div className="field setting-field setting-field-wide" key={fieldKey}>
        <label>{label}</label>
        {help ? <p className="setting-help-inline">{help}</p> : null}
        <select
          value={matched ? text : "__custom__"}
          onChange={(e) => {
            if (e.target.value === "__custom__") return;
            onChange(fieldKey, e.target.value);
          }}
        >
          {presets.map((opt) => (
            <option key={`${opt.label}:${opt.value}`} value={opt.value}>
              {opt.label}
            </option>
          ))}
          <option value="__custom__">Custom (edit below)</option>
        </select>
        <input
          value={text}
          onChange={(e) => onChange(fieldKey, e.target.value)}
          placeholder="Comma-separated values"
        />
      </div>
    );
  }

  if (isNumber) {
    return (
      <div className="field setting-field" key={fieldKey}>
        <label>{label}</label>
        {help ? <p className="setting-help-inline">{help}</p> : null}
        <input
          type="number"
          value={Number(value ?? 0)}
          onChange={(e) => onChange(fieldKey, Number(e.target.value))}
        />
      </div>
    );
  }

  return (
    <div className="field setting-field" key={fieldKey}>
      <label>{label}</label>
      {help ? <p className="setting-help-inline">{help}</p> : null}
      <input
        type={isPassword ? "password" : "text"}
        autoComplete={isPassword ? "new-password" : undefined}
        value={value == null ? "" : String(value)}
        onChange={(e) => onChange(fieldKey, e.target.value)}
      />
    </div>
  );
}

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
  const [targetsText, setTargetsText] = useState("");
  const [targetsFile, setTargetsFile] = useState<File | null>(null);
  const [wordlistFile, setWordlistFile] = useState<File | null>(null);
  const [extraWordlistFile, setExtraWordlistFile] = useState<File | null>(null);
  const [postmanFile, setPostmanFile] = useState<File | null>(null);
  const [harFile, setHarFile] = useState<File | null>(null);
  const [wordlistId, setWordlistId] = useState("");

  useEffect(() => {
    api
      .meta()
      .then((m) => {
        setMeta(m);
        const preset = m.modes?.full_audit?.preset || {};
        setSettings({ ...m.default_settings, ...preset });
        if (preset.speed) setSpeed(String(preset.speed));
        const lists = m.wordlists || [];
        const preferred =
          lists.find((w: WordlistItem) => /directory-list/i.test(w.id)) || lists[0];
        if (preferred) setWordlistId(preferred.id);
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
  const fields = meta?.setting_fields || {};
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
      const form = new FormData();
      form.append("start_url", startUrl.trim());
      form.append("title", title.trim());
      form.append("mode", mode);
      form.append("speed", speed);
      form.append("authorized_confirmed", String(authorized));
      form.append("settings_json", JSON.stringify(settings));
      form.append("targets_text", targetsText);
      form.append("wordlist_id", wordlistFile ? "__upload__" : wordlistId);
      if (targetsFile) form.append("targets_file", targetsFile);
      if (wordlistFile) form.append("wordlist_file", wordlistFile);
      if (extraWordlistFile) form.append("extra_wordlist_file", extraWordlistFile);
      if (postmanFile) form.append("postman_file", postmanFile);
      if (harFile) form.append("har_file", harFile);
      const job = await api.createJobWithFiles(form);
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
        <p className="lead">
          Choose a mode and parallelism, then fine-tune expert options. Dropdowns show every supported value.
        </p>
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
            <div className="field">
              <label>Extra targets (optional)</label>
              <textarea
                rows={3}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                placeholder={"One URL per line\nhttps://a.example\nhttps://b.example"}
              />
              <label className="setting-help-inline" style={{ display: "block", marginTop: ".55rem" }}>
                Or upload a URL list file (.txt) — not a wordlist
              </label>
              <input
                type="file"
                accept=".txt,text/plain"
                onChange={(e) => setTargetsFile(e.target.files?.[0] || null)}
              />
            </div>
            <div className="field">
              <label>Directory wordlist</label>
              <select
                value={wordlistFile ? "__upload__" : wordlistId}
                onChange={(e) => {
                  const v = e.target.value;
                  if (v === "__upload__") {
                    setWordlistId("__upload__");
                    return;
                  }
                  setWordlistId(v);
                  setWordlistFile(null);
                }}
              >
                <option value="">Server default</option>
                {(meta.wordlists || []).map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.label}
                  </option>
                ))}
                <option value="__upload__">Upload my own file…</option>
              </select>
              {(wordlistId === "__upload__" || wordlistFile) && (
                <input
                  type="file"
                  accept=".txt,text/plain"
                  required={wordlistId === "__upload__" && !wordlistFile}
                  onChange={(e) => setWordlistFile(e.target.files?.[0] || null)}
                  style={{ marginTop: ".45rem" }}
                />
              )}
              <p className="setting-help-inline" style={{ marginTop: ".35rem" }}>
                Bundled lists from the repo <code>Wordlist/</code> folder on the server — or upload your own .txt.
              </p>
            </div>
            <div className="field">
              <label>Extra wordlist (optional upload)</label>
              <input
                type="file"
                accept=".txt,text/plain"
                onChange={(e) => setExtraWordlistFile(e.target.files?.[0] || null)}
              />
            </div>
            <div className="field">
              <label>Postman collection (optional)</label>
              <input
                type="file"
                accept=".json,application/json"
                onChange={(e) => setPostmanFile(e.target.files?.[0] || null)}
              />
              <p className="setting-help-inline" style={{ marginTop: ".35rem" }}>
                Imported into API recon when provided.
              </p>
            </div>
            <div className="field">
              <label>HAR capture (optional)</label>
              <input
                type="file"
                accept=".har,.json,application/json"
                onChange={(e) => setHarFile(e.target.files?.[0] || null)}
              />
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
        <p className="lead" style={{ marginBottom: "0.85rem" }}>
          Plain-language labels with guided choices for enums. Presets cover common extension and status filters.
        </p>
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
          {activeKeys.map((key) => (
            <SettingControl
              key={key}
              fieldKey={key}
              value={settings[key]}
              meta={fields[key]}
              onChange={setSetting}
            />
          ))}
        </div>
      </section>
    </form>
  );
}
