const TOKEN_KEY = "vantacrawl_token";

export type User = {
  id: string;
  email: string;
  is_admin: boolean;
  is_verified: boolean;
  created_at: string;
};

export type Job = {
  id: string;
  title: string;
  start_url: string;
  mode: string;
  speed: string;
  status: string;
  authorized_confirmed: boolean;
  config_json: Record<string, unknown>;
  progress_json: Record<string, unknown>;
  log_tail: string;
  error_message: string;
  report_html_path: string;
  report_txt_path: string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  updated_at: string;
};

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }
  if (!res.ok) {
    const detail = data?.detail;
    const message = typeof detail === "string" ? detail : JSON.stringify(detail || res.statusText);
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  register: (email: string, password: string) =>
    request<{ message: string }>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  verifyOtp: (email: string, code: string) =>
    request<{ access_token: string }>("/api/auth/verify-otp", {
      method: "POST",
      body: JSON.stringify({ email, code }),
    }),
  resendOtp: (email: string) =>
    request<{ message: string }>("/api/auth/resend-otp", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),
  login: (email: string, password: string) =>
    request<{ access_token: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User>("/api/auth/me"),
  meta: () => request<any>("/api/meta/scan"),
  listJobs: () => request<{ jobs: Job[] }>("/api/jobs"),
  getJob: (id: string) => request<Job>(`/api/jobs/${id}`),
  createJob: (body: Record<string, unknown>) =>
    request<Job>("/api/jobs", { method: "POST", body: JSON.stringify(body) }),
  createJobWithFiles: async (form: FormData) => {
    const headers = new Headers();
    const token = getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const res = await fetch("/api/jobs/with-files", { method: "POST", headers, body: form });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data?.detail;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail || res.statusText));
    }
    return data as Job;
  },
  pauseJob: (id: string) => request<{ message: string }>(`/api/jobs/${id}/pause`, { method: "POST" }),
  resumeJob: (id: string) => request<{ message: string }>(`/api/jobs/${id}/resume`, { method: "POST" }),
  stopJob: (id: string) => request<{ message: string }>(`/api/jobs/${id}/stop`, { method: "POST" }),
  deleteJob: (id: string) => request<{ message: string }>(`/api/jobs/${id}`, { method: "DELETE" }),
  forceCancelJob: (id: string) =>
    request<{ message: string }>(`/api/jobs/${id}/force-cancel`, { method: "POST" }),
  buildSummaryReport: (id: string) =>
    request<{ message: string }>(`/api/jobs/${id}/summary-report`, { method: "POST" }),
  patchJobSettings: (id: string, settings: Record<string, unknown>) =>
    request<{ message: string }>(`/api/jobs/${id}/settings`, {
      method: "PATCH",
      body: JSON.stringify({ settings }),
    }),
  listArtifacts: (id: string) =>
    request<{ name: string; path: string; size: number; kind: string }[]>(`/api/reports/${id}/artifacts`),
};
