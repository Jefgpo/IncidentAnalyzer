import { create } from "zustand";
import type { Analysis, Filters, Quality, Reports, SessionState, UploadResponse } from "./types";

export type Step = "upload" | "analysis" | "dashboard" | "report" | "export";
export const STEPS: Step[] = ["upload", "analysis", "dashboard", "report", "export"];

export const emptyFilters = (): Filters => ({
  severity: [],
  category: [],
  host: [],
  user: [],
  src_ip: [],
  date_from: "",
  date_to: "",
  hour: null,
  weekday: null,
});

function readPref(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writePref(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* almacenamiento no disponible */
  }
}

interface State {
  step: Step;
  lang: "es" | "en";
  theme: "light" | "dark";
  upload: UploadResponse | null;
  quality: Quality | null;
  analysis: Analysis | null;
  reports: Reports | null;
  filters: Filters;
  aiEnabled: boolean;
  aiModel: string | null;
  drawer: { title: string; params: Record<string, unknown> } | null;
  toasts: { id: number; text: string; tone: "success" | "error" }[];
  toast: (text: string, tone?: "success" | "error") => void;
  dismissToast: (id: number) => void;
  setStep: (s: Step) => void;
  setLang: (l: "es" | "en") => void;
  toggleTheme: () => void;
  setUpload: (u: UploadResponse | null) => void;
  setQuality: (q: Quality | null) => void;
  setAnalysis: (a: Analysis | null) => void;
  /** Cambia solo los textos del análisis (otro idioma): conserva informes y filtros. */
  translateAnalysis: (a: Analysis) => void;
  setReports: (r: Reports | null) => void;
  setFilters: (f: Partial<Filters>) => void;
  resetFilters: () => void;
  setAi: (enabled: boolean, model: string | null) => void;
  openDrawer: (title: string, params: Record<string, unknown>) => void;
  closeDrawer: () => void;
  reset: () => void;
  /** Sesión del backend: modo de guardado y vencimiento (para informar al usuario). */
  session: { store: string; ttlHours: number } | null;
  setSessionInfo: (info: { store: string; ttlHours: number }) => void;
  restoring: boolean;
  setRestoring: (v: boolean) => void;
  restore: (state: SessionState, step: Step) => void;
  dialog: DialogRequest | null;
  closeDialog: (ok: boolean) => void;
}

export interface DialogRequest {
  title: string;
  message: string;
  confirmLabel: string;
  tone?: "danger" | "default";
  resolve: (ok: boolean) => void;
}

const SESSION_KEY = "soc.session";

/** Lee el ID de sesión y el paso guardados en el navegador (solo eso: los datos viven en el backend). */
export function readSavedSession(): { id: string; step: Step } | null {
  try {
    const v = JSON.parse(localStorage.getItem(SESSION_KEY) ?? "null");
    return v && typeof v.id === "string" ? v : null;
  } catch {
    return null;
  }
}

export function clearSavedSession() {
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch {
    /* almacenamiento no disponible */
  }
}

const initialTheme = (readPref("soc.theme", "") ||
  (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light")) as "light" | "dark";

export const useStore = create<State>((set) => ({
  step: "upload",
  lang: readPref("soc.lang", "es") as "es" | "en",
  theme: initialTheme,
  upload: null,
  quality: null,
  analysis: null,
  reports: null,
  filters: emptyFilters(),
  aiEnabled: false,
  aiModel: null,
  drawer: null,
  toasts: [],
  toast: (text, tone = "success") => {
    const id = Date.now() + Math.random();
    set((s) => ({ toasts: [...s.toasts.slice(-2), { id, text, tone }] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 4500);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  setStep: (step) => set({ step }),
  setLang: (lang) => {
    writePref("soc.lang", lang);
    set({ lang });
  },
  toggleTheme: () =>
    set((s) => {
      const theme = s.theme === "dark" ? "light" : "dark";
      writePref("soc.theme", theme);
      return { theme };
    }),
  setUpload: (upload) => set({ upload, quality: null, analysis: null, reports: null, filters: emptyFilters() }),
  setQuality: (quality) => set({ quality, analysis: null, reports: null }),
  setAnalysis: (analysis) => set({ analysis, reports: null, filters: emptyFilters() }),
  translateAnalysis: (analysis) => set({ analysis }),
  setReports: (reports) => set({ reports }),
  setFilters: (f) => set((s) => ({ filters: { ...s.filters, ...f } })),
  resetFilters: () => set({ filters: emptyFilters() }),
  setAi: (aiEnabled, aiModel) => set({ aiEnabled, aiModel }),
  openDrawer: (title, params) => set({ drawer: { title, params } }),
  closeDrawer: () => set({ drawer: null }),
  reset: () => {
    clearSavedSession();
    set({ step: "upload", upload: null, quality: null, analysis: null, reports: null, filters: emptyFilters(), drawer: null });
  },
  dialog: null,
  closeDialog: (ok) =>
    set((s) => {
      s.dialog?.resolve(ok);
      return { dialog: null };
    }),
  session: null,
  setSessionInfo: (session) => set({ session }),
  restoring: !!readSavedSession(),
  setRestoring: (restoring) => set({ restoring }),
  restore: (st, step) => {
    // el paso guardado solo se respeta si los datos necesarios existen
    const ok: Record<Step, boolean> = {
      upload: true,
      analysis: !!st.quality,
      dashboard: !!st.analysis,
      report: !!st.analysis,
      export: !!st.reports,
    };
    set({ upload: st.upload, quality: st.quality, analysis: st.analysis, reports: st.reports, step: ok[step] ? step : "upload" });
  },
}));

// Guarda en el navegador solo el ID de sesión y el paso actual para poder retomar tras recargar.
useStore.subscribe((s) => {
  if (s.restoring) return;
  try {
    if (s.upload) localStorage.setItem(SESSION_KEY, JSON.stringify({ id: s.upload.session_id, step: s.step }));
  } catch {
    /* almacenamiento no disponible: la app sigue funcionando sin restauración */
  }
});

/** Confirmación accesible que reemplaza a window.confirm. Devuelve true si el usuario confirma. */
export function confirmDialog(opts: Omit<DialogRequest, "resolve">): Promise<boolean> {
  return new Promise((resolve) => useStore.setState({ dialog: { ...opts, resolve } }));
}
