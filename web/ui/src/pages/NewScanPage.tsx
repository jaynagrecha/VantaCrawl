import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, SettingsProfile } from "../api";
import FilePicker from "../components/FilePicker";

const MODE_SHORT: Record<string, string> = {
  full_audit: "Full Audit",
  deep_audit: "Deep Audit",
  fast_scan: "Fast Scan",
};

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

const GROUP_BLURBS: Record<string, string> = {
  core: "Crawl depth, concurrency, and basic scope rules.",
  discovery: "Subdomains, APIs, JS bundles, forms, and archive seeds.",
  enum: "Directory / file name probing — usually the heaviest phase.",
  security: "Vulnerability probes, secrets, headers, and impact checks.",
  download: "Offline mirror, assets, and file save behavior.",
  connection: "Cookies, proxies, TLS, and auth headers.",
  operations: "Checkpoints, limits, and run-control knobs.",
  stealth: "Browser identity, pacing, and WAF-friendly traffic shaping.",
  reports: "HTML/text exports and assessment packaging.",
};

function humanize(key: string) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function isToggleField(value: unknown, meta?: FieldMeta) {
  return typeof value === "boolean" || meta?.control === "checkbox";
}

function SettingControl({
  fieldKey,
  value,
  meta,
  onChange,
  dense,
}: {
  fieldKey: string;
  value: unknown;
  meta?: FieldMeta;
  onChange: (key: string, value: unknown) => void;
  dense?: boolean;
}) {
  const label = meta?.label || humanize(fieldKey);
  const help = meta?.help || "";
  const control = meta?.control || "auto";
  const options = meta?.options || [];
  const presets = meta?.presets || [];

  const isBool = isToggleField(value, meta);
  const isNumber = typeof value === "number" || control === "number";
  const isSelect = control === "select" && options.length > 0;
  const isPresetText = control === "text_with_presets";
  const isPassword = control === "password";

  if (isBool) {
    return (
      <label className={`expert-toggle ${dense ? "dense" : ""}`}>
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(fieldKey, e.target.checked)}
        />
        <span className="expert-toggle-copy">
          <span className="setting-label">{label}</span>
          {help ? <span className="setting-help">{help}</span> : null}
        </span>
      </label>
    );
  }

  if (isSelect) {
    const current = value == null ? "" : String(value);
    const known = options.some((o) => o.value === current);
    return (
      <div className="field setting-field">
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
      <div className="field setting-field setting-field-wide">
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
      <div className="field setting-field">
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
    <div className="field setting-field">
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
  const [expertOpen, setExpertOpen] = useState(false);
  const [expertQuery, setExpertQuery] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [targetsText, setTargetsText] = useState("");
  const [targetsFile, setTargetsFile] = useState<File | null>(null);
  const [wordlistFile, setWordlistFile] = useState<File | null>(null);
  const [extraWordlistFile, setExtraWordlistFile] = useState<File | null>(null);
  const [postmanFile, setPostmanFile] = useState<File | null>(null);
  const [harFile, setHarFile] = useState<File | null>(null);
  const [wordlistId, setWordlistId] = useState("");
  const [profiles, setProfiles] = useState<SettingsProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [profileHostPattern, setProfileHostPattern] = useState("");
  const [profileIsDefault, setProfileIsDefault] = useState(false);
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileHint, setProfileHint] = useState("");
  const skipModeResetRef = useRef(false);
  const lastMatchedUrlRef = useRef("");

  const baseline = useMemo(() => {
    if (!meta) return {} as Record<string, unknown>;
    const preset = meta.modes[mode]?.preset || {};
    return { ...meta.default_settings, ...preset };
  }, [meta, mode]);

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
    api
      .listSettingsProfiles()
      .then((res) => setProfiles(res.profiles || []))
      .catch(() => setProfiles([]));
  }, []);

  useEffect(() => {
    if (!meta) return;
    if (skipModeResetRef.current) {
      skipModeResetRef.current = false;
      return;
    }
    const preset = meta.modes[mode]?.preset || {};
    setSettings({ ...meta.default_settings, ...preset });
    if (preset.speed) setSpeed(String(preset.speed));
  }, [mode, meta]);

  function hostFromUrl(raw: string) {
    try {
      const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
      return (u.hostname || "").toLowerCase();
    } catch {
      return "";
    }
  }

  function applyProfile(profile: SettingsProfile, source: string) {
    if (!meta) return;
    skipModeResetRef.current = true;
    setSelectedProfileId(profile.id);
    setMode(profile.mode || "full_audit");
    setSpeed(profile.speed || "balanced");
    const preset = meta.modes[profile.mode]?.preset || {};
    setSettings({
      ...meta.default_settings,
      ...preset,
      ...(profile.settings || {}),
    });
    setProfileHostPattern(profile.host_pattern || "");
    setProfileIsDefault(Boolean(profile.is_default));
    if (profile.wordlist_id) setWordlistId(profile.wordlist_id);
    setProfileHint(`Loaded “${profile.name}” (${source}).`);
  }

  async function refreshProfiles() {
    const res = await api.listSettingsProfiles();
    setProfiles(res.profiles || []);
    return res.profiles || [];
  }

  async function onSelectProfile(id: string) {
    setSelectedProfileId(id);
    setProfileHint("");
    if (!id) {
      setProfileHostPattern("");
      setProfileIsDefault(false);
      return;
    }
    const profile = profiles.find((p) => p.id === id);
    if (profile) applyProfile(profile, "manual");
  }

  async function saveCurrentAsProfile() {
    const name = window.prompt("Profile name", title.trim() || hostFromUrl(startUrl) || "My profile");
    if (!name) return;
    setProfileBusy(true);
    setError("");
    try {
      const host =
        profileHostPattern.trim() || hostFromUrl(startUrl) || "";
      const created = await api.createSettingsProfile({
        name: name.trim(),
        mode,
        speed,
        settings,
        host_pattern: host,
        wordlist_id: wordlistFile ? "" : wordlistId,
        is_default: profileIsDefault,
      });
      const list = await refreshProfiles();
      setProfiles(list);
      setSelectedProfileId(created.id);
      setProfileHostPattern(created.host_pattern || host);
      setProfileHint(`Saved profile “${created.name}”.`);
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setProfileBusy(false);
    }
  }

  async function updateSelectedProfile() {
    if (!selectedProfileId) {
      setError("Select a profile to update, or Save as new.");
      return;
    }
    setProfileBusy(true);
    setError("");
    try {
      const updated = await api.updateSettingsProfile(selectedProfileId, {
        mode,
        speed,
        settings,
        host_pattern: profileHostPattern.trim() || hostFromUrl(startUrl),
        wordlist_id: wordlistFile ? "" : wordlistId,
        is_default: profileIsDefault,
      });
      await refreshProfiles();
      setProfileHint(`Updated “${updated.name}”.`);
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setProfileBusy(false);
    }
  }

  async function deleteSelectedProfile() {
    if (!selectedProfileId) return;
    const profile = profiles.find((p) => p.id === selectedProfileId);
    if (!window.confirm(`Delete profile “${profile?.name || selectedProfileId}”?`)) return;
    setProfileBusy(true);
    setError("");
    try {
      await api.deleteSettingsProfile(selectedProfileId);
      setSelectedProfileId("");
      setProfileHostPattern("");
      setProfileIsDefault(false);
      await refreshProfiles();
      setProfileHint("Profile deleted.");
    } catch (err: any) {
      setError(String(err.message || err));
    } finally {
      setProfileBusy(false);
    }
  }

  async function tryMatchProfileForUrl(url: string) {
    const trimmed = url.trim();
    if (!trimmed || trimmed === "https://" || trimmed === lastMatchedUrlRef.current) return;
    lastMatchedUrlRef.current = trimmed;
    try {
      const res = await api.matchSettingsProfile(trimmed);
      if (res.profile) {
        applyProfile(res.profile, res.reason === "default" ? "default" : "host match");
      }
    } catch {
      /* ignore match failures */
    }
  }

  const groups = meta?.setting_groups || [];
  const fields = meta?.setting_fields || {};

  const changedKeys = useMemo(() => {
    const out: string[] = [];
    for (const [key, value] of Object.entries(settings)) {
      if (!(key in baseline)) continue;
      if (JSON.stringify(baseline[key]) !== JSON.stringify(value)) out.push(key);
    }
    return out;
  }, [settings, baseline]);

  const changedSet = useMemo(() => new Set(changedKeys), [changedKeys]);

  const query = expertQuery.trim().toLowerCase();
  const searching = query.length > 0;

  const activeGroup = groups.find((g) => g.id === tab) || groups[0];

  const visibleKeys = useMemo(() => {
    if (searching) {
      const hits: string[] = [];
      for (const g of groups) {
        for (const key of g.keys) {
          const metaField = fields[key];
          const hay = [
            key,
            metaField?.label || "",
            metaField?.help || "",
            humanize(key),
            g.title,
          ]
            .join(" ")
            .toLowerCase();
          if (hay.includes(query)) hits.push(key);
        }
      }
      return hits;
    }
    return activeGroup?.keys || [];
  }, [searching, query, groups, fields, activeGroup]);

  const toggleKeys = visibleKeys.filter((k) => isToggleField(settings[k], fields[k]));
  const valueKeys = visibleKeys.filter((k) => !isToggleField(settings[k], fields[k]));

  function setSetting(key: string, value: unknown) {
    setSettings((prev) => ({ ...prev, [key]: value }));
  }

  function resetExpertToModeDefaults() {
    setSettings({ ...baseline });
    setExpertQuery("");
  }

  function resetActiveGroup() {
    if (!activeGroup || searching) return;
    setSettings((prev) => {
      const next = { ...prev };
      for (const key of activeGroup.keys) {
        if (key in baseline) next[key] = baseline[key];
      }
      return next;
    });
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
      const payload = {
        ...settings,
        ...(selectedProfileId
          ? {
              settings_profile_id: selectedProfileId,
              settings_profile_name:
                profiles.find((p) => p.id === selectedProfileId)?.name || "",
            }
          : {}),
      };
      form.append("settings_json", JSON.stringify(payload));
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

  const groupChangedCount = (keys: string[]) => keys.filter((k) => changedSet.has(k)).length;

  return (
    <form onSubmit={submit}>
      <section className="card">
        <h1>New scan</h1>
        <p className="lead">
          Full Audit = crawl + security (directory enum off unless you opt in). Deep Audit turns on heavy
          directory enum. Fast Scan is enum-only.
        </p>
        {error && <div className="error">{error}</div>}
        <div className="grid-2 scan-form">
          <div className="scan-form-main">
            <div className="field">
              <label>Target URL</label>
              <input
                required
                inputMode="url"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                value={startUrl}
                onChange={(e) => setStartUrl(e.target.value)}
                onBlur={(e) => tryMatchProfileForUrl(e.target.value)}
                placeholder="https://example.com"
              />
            </div>
            <div className="field settings-profile-panel">
              <label>Settings profile</label>
              <select
                value={selectedProfileId}
                onChange={(e) => onSelectProfile(e.target.value)}
                disabled={profileBusy}
              >
                <option value="">None — use mode defaults</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                    {p.host_pattern ? ` · ${p.host_pattern}` : ""}
                    {p.is_default ? " · default" : ""}
                  </option>
                ))}
              </select>
              <p className="setting-help-inline field-hint">
                Save your current Mode + Parallelism + Expert settings and reload them later. Host
                patterns auto-load when you enter a matching Target URL.
              </p>
              <div className="field" style={{ marginTop: "0.65rem" }}>
                <label>Host pattern (optional)</label>
                <input
                  value={profileHostPattern}
                  onChange={(e) => setProfileHostPattern(e.target.value)}
                  placeholder={hostFromUrl(startUrl) || "example.com or *.example.com"}
                />
              </div>
              <label className="checkbox" style={{ marginTop: "0.5rem" }}>
                <input
                  type="checkbox"
                  checked={profileIsDefault}
                  onChange={(e) => setProfileIsDefault(e.target.checked)}
                />
                <span className="checkbox-copy">
                  <strong>Account default</strong>
                  <span className="muted">Use when no host pattern matches</span>
                </span>
              </label>
              <div className="profile-actions">
                <button
                  type="button"
                  className="btn"
                  disabled={profileBusy}
                  onClick={() => void saveCurrentAsProfile()}
                >
                  Save as new…
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={profileBusy || !selectedProfileId}
                  onClick={() => void updateSelectedProfile()}
                >
                  Update selected
                </button>
                <button
                  type="button"
                  className="btn danger"
                  disabled={profileBusy || !selectedProfileId}
                  onClick={() => void deleteSelectedProfile()}
                >
                  Delete
                </button>
              </div>
              {profileHint ? <p className="setting-help-inline field-hint">{profileHint}</p> : null}
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
                    {MODE_SHORT[key] || val.label}
                  </option>
                ))}
              </select>
              <p className="setting-help-inline field-hint">
                {meta.modes[mode]?.label ||
                  "Full Audit skips directory enum by default. Deep Audit / Fast Scan enable it."}
              </p>
            </div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={Boolean(settings.directory_enum) || mode === "fast_scan"}
                disabled={mode === "fast_scan"}
                onChange={(e) => {
                  const on = e.target.checked;
                  setSettings((prev) => ({
                    ...prev,
                    directory_enum: on,
                    use_wordlist: on ? true : false,
                    mutation_enum: on ? Boolean(prev.mutation_enum ?? true) : false,
                  }));
                }}
              />
              <span className="checkbox-copy">
                <strong>Run directory enum</strong>
                <span className="muted">
                  Opt-in folder/file probing — usually the slowest phase. Off for Full Audit unless checked.
                </span>
              </span>
            </label>
            <div className="field">
              <label>Parallelism</label>
              <select value={speed} onChange={(e) => setSpeed(e.target.value)}>
                {Object.entries(meta.speeds).map(([key, val]) => (
                  <option key={key} value={key}>
                    {val.label.includes("–") ? val.label.split("–")[0].trim() : val.label}
                  </option>
                ))}
              </select>
              <p className="setting-help-inline field-hint">{meta.speeds[speed]?.label}</p>
            </div>
            <div className="field">
              <label>Extra targets (optional)</label>
              <textarea
                rows={3}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                placeholder={"One URL per line\nhttps://a.example\nhttps://b.example"}
              />
              <p className="setting-help-inline field-hint">Or upload a URL list (.txt) — not a wordlist</p>
              <FilePicker
                accept=".txt,text/plain"
                file={targetsFile}
                onChange={setTargetsFile}
                label="Upload URL list"
              />
            </div>
            {(Boolean(settings.directory_enum) || mode === "fast_scan" || mode === "deep_audit") && (
              <>
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
                    <FilePicker
                      accept=".txt,text/plain"
                      required={wordlistId === "__upload__" && !wordlistFile}
                      file={wordlistFile}
                      onChange={setWordlistFile}
                      label="Upload wordlist"
                    />
                  )}
                  <p className="setting-help-inline field-hint">
                    Bundled lists from the server <code>Wordlist/</code> folder — or upload your own .txt.
                  </p>
                </div>
                <div className="field">
                  <label>Extra wordlist (optional)</label>
                  <FilePicker
                    accept=".txt,text/plain"
                    file={extraWordlistFile}
                    onChange={setExtraWordlistFile}
                    label="Upload extra wordlist"
                  />
                </div>
              </>
            )}
            <div className="field">
              <label>Postman collection (optional)</label>
              <FilePicker
                accept=".json,application/json"
                file={postmanFile}
                onChange={setPostmanFile}
                label="Upload Postman JSON"
              />
              <p className="setting-help-inline field-hint">Imported into API recon when provided.</p>
            </div>
            <div className="field">
              <label>HAR capture (optional)</label>
              <FilePicker
                accept=".har,.json,application/json"
                file={harFile}
                onChange={setHarFile}
                label="Upload HAR"
              />
            </div>
          </div>
          <div className="scan-form-side">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
              />
              <span className="checkbox-copy">
                <strong>I confirm this target is authorized for testing.</strong>
                <span className="muted">Required. Scans will not start without this confirmation.</span>
              </span>
            </label>
            <button className="btn primary scan-submit" type="submit" disabled={busy || !authorized}>
              {busy ? "Starting…" : "Start scan"}
            </button>
          </div>
        </div>
      </section>

      <section className={`card expert-card ${expertOpen ? "open" : "collapsed"}`}>
        <header className="expert-head">
          <div className="expert-head-copy">
            <h2>Expert settings</h2>
            <p className="lead expert-lead">
              Optional fine-tuning. Most scans only need the basics above — open this when you need
              stealth, enum filters, or report knobs.
            </p>
          </div>
          <div className="expert-head-actions">
            {changedKeys.length > 0 ? (
              <span className="expert-changed-pill" title="Settings changed from the mode defaults">
                {changedKeys.length} customized
              </span>
            ) : (
              <span className="expert-default-pill">Using mode defaults</span>
            )}
            <button
              type="button"
              className="btn primary"
              onClick={() => setExpertOpen((v) => !v)}
              aria-expanded={expertOpen}
            >
              {expertOpen ? "Hide expert settings" : "Show expert settings"}
            </button>
          </div>
        </header>

        {expertOpen ? (
          <div className="expert-body">
            <div className="expert-toolbar">
              <div className="expert-search">
                <input
                  type="search"
                  value={expertQuery}
                  onChange={(e) => setExpertQuery(e.target.value)}
                  placeholder="Search settings (e.g. stealth, graphql, wordlist)…"
                  aria-label="Search expert settings"
                />
              </div>
              <div className="expert-toolbar-actions">
                <button
                  type="button"
                  className="btn"
                  onClick={resetActiveGroup}
                  disabled={searching || !activeGroup}
                  title="Reset only the active category to mode defaults"
                >
                  Reset category
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={resetExpertToModeDefaults}
                  disabled={changedKeys.length === 0}
                  title="Reset every expert setting to the current mode defaults"
                >
                  Reset all
                </button>
              </div>
            </div>

            <div className="expert-layout">
              <aside className="expert-nav" aria-label="Setting categories">
                <label className="expert-nav-mobile">
                  <span>Category</span>
                  <select
                    value={tab}
                    onChange={(e) => {
                      setTab(e.target.value);
                      setExpertQuery("");
                    }}
                    disabled={searching}
                  >
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.title}
                        {groupChangedCount(g.keys) ? ` (${groupChangedCount(g.keys)} changed)` : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <nav className="expert-nav-list">
                  {groups.map((g) => {
                    const changed = groupChangedCount(g.keys);
                    return (
                      <button
                        key={g.id}
                        type="button"
                        className={`expert-nav-item ${!searching && tab === g.id ? "active" : ""}`}
                        onClick={() => {
                          setTab(g.id);
                          setExpertQuery("");
                        }}
                      >
                        <span className="expert-nav-title">{g.title}</span>
                        <span className="expert-nav-meta">
                          <span className="expert-nav-count">{g.keys.length}</span>
                          {changed > 0 ? <span className="expert-nav-dot" title={`${changed} changed`} /> : null}
                        </span>
                      </button>
                    );
                  })}
                </nav>
              </aside>

              <div className="expert-panel">
                <div className="expert-panel-head">
                  <div>
                    <h3>
                      {searching
                        ? `Search results`
                        : activeGroup?.title || "Settings"}
                    </h3>
                    <p className="muted">
                      {searching
                        ? `${visibleKeys.length} match${visibleKeys.length === 1 ? "" : "es"} for “${expertQuery.trim()}”`
                        : GROUP_BLURBS[activeGroup?.id || ""] || "Tune this category for the current scan."}
                    </p>
                  </div>
                  {!searching && activeGroup ? (
                    <span className="expert-panel-count">
                      {activeGroup.keys.length} settings
                      {groupChangedCount(activeGroup.keys)
                        ? ` · ${groupChangedCount(activeGroup.keys)} changed`
                        : ""}
                    </span>
                  ) : null}
                </div>

                {visibleKeys.length === 0 ? (
                  <p className="expert-empty muted">No settings match that search.</p>
                ) : (
                  <>
                    {toggleKeys.length > 0 ? (
                      <div className="expert-section">
                        <h4>Switches</h4>
                        <div className="expert-toggles">
                          {toggleKeys.map((key) => (
                            <SettingControl
                              key={key}
                              fieldKey={key}
                              value={settings[key]}
                              meta={fields[key]}
                              onChange={setSetting}
                              dense
                            />
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {valueKeys.length > 0 ? (
                      <div className="expert-section">
                        <h4>Values</h4>
                        <div className="settings-grid expert-values">
                          {valueKeys.map((key) => (
                            <SettingControl
                              key={key}
                              fieldKey={key}
                              value={settings[key]}
                              meta={fields[key]}
                              onChange={setSetting}
                            />
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </>
                )}
              </div>
            </div>
          </div>
        ) : null}
      </section>
    </form>
  );
}
