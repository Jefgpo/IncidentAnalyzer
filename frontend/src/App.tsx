import { Bot, BotOff, Check, FilePlus2, Moon, ShieldCheck, Sun } from "lucide-react";
import { useEffect } from "react";
import ConfirmDialog from "./components/ConfirmDialog";
import EventsDrawer from "./components/EventsDrawer";
import { Spinner, Toasts } from "./components/ui";
import { type ApiError, api } from "./lib/api";
import { cls } from "./lib/format";
import { dict, fmt, useT } from "./lib/i18n";
import { STEPS, clearSavedSession, confirmDialog, readSavedSession, useStore, type Step } from "./lib/store";
import AnalysisPage from "./pages/AnalysisPage";
import DashboardPage from "./pages/DashboardPage";
import ExportPage from "./pages/ExportPage";
import ReportPage from "./pages/ReportPage";
import UploadPage from "./pages/UploadPage";

function useStepAvailability(): Record<Step, boolean> {
  const { quality, analysis, reports } = useStore();
  return { upload: true, analysis: !!quality, dashboard: !!analysis, report: !!analysis, export: !!reports };
}

let restoreStarted = false;

export default function App() {
  const t = useT();
  const { step, setStep, theme, toggleTheme, lang, setLang, aiEnabled, aiModel, setAi, upload, reset } = useStore();
  const { restoring, setRestoring, restore, session, setSessionInfo, toast } = useStore();
  const available = useStepAvailability();

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  // al cambiar de idioma, los textos del análisis (hallazgos, incidentes, conclusión) se piden traducidos
  const analysisLoaded = useStore((s) => !!s.analysis);
  const sessionId = upload?.session_id;
  useEffect(() => {
    if (!sessionId || !analysisLoaded || restoring) return;
    let alive = true;
    api
      .analysis(sessionId)
      .then((a) => alive && useStore.getState().translateAnalysis(a))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lang]);
  useEffect(() => {
    api
      .health()
      .then((h) => {
        setAi(h.ai_enabled, h.model);
        setSessionInfo({ store: h.session_store, ttlHours: h.session_ttl_hours });
      })
      .catch(() => setAi(false, null));
  }, [setAi, setSessionInfo]);

  // Retomar la sesión guardada (tras recargar la página o reiniciar el servidor)
  useEffect(() => {
    const saved = readSavedSession();
    if (!saved || restoreStarted) return;
    restoreStarted = true; // React StrictMode ejecuta los efectos dos veces en desarrollo
    api
      .state(saved.id)
      .then((st) => {
        restore(st, saved.step);
        toast(fmt(dict().restoredSession, { name: st.upload.filename }));
      })
      .catch((e) => {
        // solo se olvida la sesión si el servidor confirma que ya no existe; ante errores transitorios se conserva
        if ((e as ApiError).status === 404) {
          clearSavedSession();
          toast(dict().sessionExpired, "error");
        } else toast(fmt(dict().restoreFailed, { err: (e as Error).message }), "error");
      })
      .finally(() => setRestoring(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const newFile = async () => {
    if (upload && !(await confirmDialog({ title: t.confirmNewTitle, message: t.confirmNew, confirmLabel: t.deleteLabel, tone: "danger" }))) return;
    if (upload) await api.deleteSession(upload.session_id).catch(() => undefined);
    reset();
  };

  const idx = STEPS.indexOf(step);
  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only z-[80] rounded-lg bg-sky-700 px-4 py-2 font-medium text-white focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        {t.skipToContent}
      </a>
      <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-sky-600" size={26} />
            <div>
              <div className="text-sm font-bold leading-tight">{t.appName}</div>
              <div className="hidden text-xs text-slate-500 sm:block dark:text-slate-400">{t.tagline}</div>
            </div>
          </div>
          <nav aria-label={t.stepsNav} className="order-3 w-full overflow-x-auto lg:order-none lg:ml-6 lg:w-auto lg:flex-1">
            <ol className="flex items-center gap-1">
              {STEPS.map((s, i) => {
                const done = i < idx && available[s];
                return (
                  <li key={s} className="flex items-center">
                    <button
                      disabled={!available[s]}
                      title={available[s] ? undefined : t.blockedHint[s]}
                      onClick={() => setStep(s)}
                      aria-current={s === step ? "step" : undefined}
                      className={cls(
                        "flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm whitespace-nowrap transition disabled:cursor-not-allowed disabled:opacity-40",
                        s === step ? "bg-sky-700 text-white" : "hover:bg-slate-100 dark:hover:bg-slate-800",
                      )}
                    >
                      <span
                        className={cls(
                          "flex h-5 w-5 items-center justify-center rounded-full text-xs font-semibold",
                          s === step ? "bg-white/25" : done ? "bg-emerald-600 text-white" : "bg-slate-200 dark:bg-slate-700",
                        )}
                      >
                        {done ? <Check size={12} /> : i + 1}
                      </span>
                      {t.steps[s]}
                    </button>
                    {i < STEPS.length - 1 && <span className="mx-1 h-px w-4 bg-slate-300 dark:bg-slate-700" />}
                  </li>
                );
              })}
            </ol>
          </nav>
          <div className="ml-auto flex items-center gap-1">
            <span
              title={aiEnabled ? `${t.aiOn} · ${aiModel}` : t.aiOff}
              className={cls("hidden items-center gap-1 rounded-md px-2 py-1 text-xs md:flex", aiEnabled ? "text-violet-700 dark:text-violet-300" : "text-slate-400")}
            >
              {aiEnabled ? <Bot size={14} /> : <BotOff size={14} />} {aiEnabled ? t.aiOn : t.aiOffShort}
            </span>
            <select
              aria-label={t.language}
              className="rounded-md border border-slate-300 bg-transparent px-1.5 py-1 text-xs dark:border-slate-700"
              value={lang}
              onChange={(e) => setLang(e.target.value as "es" | "en")}
            >
              <option value="es">ES</option>
              <option value="en">EN</option>
            </select>
            <button className="btn-ghost px-2 py-1.5" onClick={toggleTheme} aria-label={t.theme} title={t.theme}>
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            {upload && (
              <button className="btn-ghost px-2 py-1.5 text-xs" onClick={newFile} title={t.newFile}>
                <FilePlus2 size={15} /> <span className="hidden sm:inline">{t.newFile}</span>
              </button>
            )}
          </div>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="mx-auto max-w-[1500px] px-4 py-5 focus:outline-none">
        {restoring && (
          <div className="flex justify-center pt-16">
            <Spinner label={t.restoring} />
          </div>
        )}
        {!restoring && step === "upload" && <UploadPage />}
        {!restoring && step === "analysis" && <AnalysisPage />}
        {!restoring && step === "dashboard" && <DashboardPage />}
        {!restoring && step === "report" && <ReportPage />}
        {!restoring && step === "export" && <ExportPage />}
      </main>
      <footer className="mx-auto max-w-[1500px] px-4 pb-6 text-center text-xs text-slate-500 dark:text-slate-400">
        {upload && session ? (
          session.store === "disk" ? (
            <>
              {fmt(t.sessionDisk, { h: session.ttlHours })}{" "}
              <button className="underline hover:text-slate-700 dark:hover:text-slate-200" onClick={newFile}>
                {t.deleteNow}
              </button>
            </>
          ) : (
            <>{fmt(t.sessionMemory, { h: session.ttlHours })}</>
          )
        ) : (
          t.sessionNote
        )}
      </footer>
      <EventsDrawer />
      <ConfirmDialog />
      <Toasts />
    </div>
  );
}
