import { useStore } from "./store";
import type { Analysis, Dashboard, EventsPage, IntelJob, IntelStatus, Quality, ReportKind, Reports, SessionState, UploadResponse } from "./types";

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // el backend responde los mensajes de error en el idioma de la interfaz
  const lang = useStore.getState().lang;
  const headers = new Headers(init?.headers);
  headers.set("Accept-Language", lang);
  let res: Response;
  try {
    res = await fetch(BASE + path, { ...init, headers });
  } catch {
    throw new ApiError(0, lang === "en" ? "Could not reach the backend. Is it running on port 8000?" : "No se pudo contactar al backend. ¿Está en ejecución en el puerto 8000?");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* respuesta sin JSON */
    }
    throw new ApiError(res.status, detail || `Error ${res.status}`);
  }
  const type = res.headers.get("content-type") || "";
  return (type.includes("application/json") ? res.json() : res.blob()) as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export function qs(params: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) {
      if (v.length) p.set(k, v.join(","));
    } else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
  health: () =>
    request<{ status: string; ai_enabled: boolean; model: string | null; max_upload_mb: number; session_ttl_hours: number; session_store: string }>(
      "/health",
    ),
  state: (sid: string) => request<SessionState>(`/sessions/${sid}/state`),
  rules: () => request<{ rules: unknown[]; methodology: unknown }>("/rules"),
  upload: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<UploadResponse>("/upload", { method: "POST", body: fd });
  },
  uploadSample: () => request<UploadResponse>("/upload/sample", { method: "POST" }),
  mapping: (sid: string, body: { sheets: { name: string; mapping: Record<string, string | null> }[]; timezone: string; dayfirst: boolean }) =>
    request<Quality>(`/sessions/${sid}/mapping`, json(body)),
  events: (sid: string, params: Record<string, unknown>) => request<EventsPage>(`/sessions/${sid}/events${qs(params)}`),
  analyze: (sid: string) => request<Analysis>(`/sessions/${sid}/analyze`, { method: "POST" }),
  // mismo análisis en el idioma actual (cabecera Accept-Language): mismos IDs, textos traducidos
  analysis: (sid: string) => request<Analysis>(`/sessions/${sid}/analysis`),
  dashboard: (sid: string, params: Record<string, unknown>) => request<Dashboard>(`/sessions/${sid}/dashboard${qs(params)}`),
  generateReport: (sid: string, body: { lang: string; client: string; analyst: string }) =>
    request<Reports>(`/sessions/${sid}/report/generate`, json(body)),
  reports: (sid: string) => request<Reports>(`/sessions/${sid}/report`),
  updateBlock: (sid: string, kind: ReportKind, blockId: string, body: { text?: string; items?: string[] }) =>
    request<Reports>(`/sessions/${sid}/report/${kind}/blocks/${encodeURIComponent(blockId)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  updateMeta: (sid: string, body: { client?: string; analyst?: string; title?: string }) =>
    request<Reports>(`/sessions/${sid}/report/meta`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
  aiReport: (sid: string) => request<Reports>(`/sessions/${sid}/report/ai`, { method: "POST" }),
  chat: (sid: string, message: string) =>
    request<{ answer: string; claims: { text: string; kind: string; row_ids: string[]; valid: boolean; reason?: string }[]; rejected: number }>(
      `/sessions/${sid}/ai/chat`,
      json({ message }),
    ),
  pdf: (sid: string, kind: ReportKind) => request<Blob>(`/sessions/${sid}/export/pdf?kind=${kind}`, { method: "POST" }),
  iocsCsv: (sid: string) => request<Blob>(`/sessions/${sid}/export/iocs.csv`),
  intelStatus: () => request<IntelStatus>("/intel/status"),
  intelStart: (sid: string, body: { abuseipdb_key?: string; max_ips: number }) =>
    request<IntelJob>(`/sessions/${sid}/intel`, json(body)),
  intelGet: (sid: string) => request<IntelJob>(`/sessions/${sid}/intel`),
  intelCancel: (sid: string) => request<IntelJob>(`/sessions/${sid}/intel`, { method: "DELETE" }),
  deleteSession: (sid: string) => request<{ deleted: boolean }>(`/sessions/${sid}`, { method: "DELETE" }),
};

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
