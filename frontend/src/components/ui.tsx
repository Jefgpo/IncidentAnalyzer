import { AlertTriangle, Bot, Loader2, PencilLine, ShieldQuestion } from "lucide-react";
import type { ReactNode } from "react";
import { SEVERITY_BADGE, SEVERITY_EN, cls } from "../lib/format";
import { useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { BlockKind, BlockOrigin, Severity } from "../lib/types";

export function Card({ title, actions, children, className, subtitle }: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cls("card", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-slate-100 px-4 py-3 dark:border-slate-800">
          <div>
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number }) {
  const lang = useStore((s) => s.lang);
  return (
    <span className={cls("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold", SEVERITY_BADGE[severity])}>
      {lang === "en" ? SEVERITY_EN[severity] : severity}
      {score !== undefined && <span>· {score}</span>}
    </span>
  );
}

export function Chip({ children, tone = "slate", title }: { children: ReactNode; tone?: "slate" | "sky" | "violet" | "amber" | "emerald" | "red"; title?: string }) {
  const tones = {
    slate: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    sky: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200",
    violet: "bg-violet-100 text-violet-800 dark:bg-violet-900/50 dark:text-violet-200",
    amber: "bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200",
    emerald: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
    red: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  };
  return (
    <span title={title} className={cls("inline-flex max-w-full items-center gap-1 truncate rounded px-1.5 py-0.5 text-xs font-medium", tones[tone])}>
      {children}
    </span>
  );
}

export function OriginTag({ origin, review }: { origin: BlockOrigin; review?: string[] }) {
  const lang = useStore((s) => s.lang);
  if (review && review.length)
    return (
      <Chip tone="red" title={review.join("\n")}>
        <AlertTriangle size={11} /> {lang === "en" ? "Needs review" : "Requiere revisión"}
      </Chip>
    );
  if (origin === "ia")
    return (
      <Chip tone="violet">
        <Bot size={11} /> {lang === "en" ? "AI-generated" : "Generado por IA"}
      </Chip>
    );
  if (origin === "editado")
    return (
      <Chip tone="amber">
        <PencilLine size={11} /> {lang === "en" ? "Edited" : "Editado por analista"}
      </Chip>
    );
  return null;
}

const KIND_LABEL: Record<BlockKind, [string, string, "slate" | "sky" | "emerald" | "amber"]> = {
  hecho_observado: ["Hecho observado", "Observed fact", "emerald"],
  inferencia: ["Inferencia razonable", "Reasonable inference", "sky"],
  hipotesis: ["Hipótesis a validar", "Hypothesis to validate", "amber"],
  recomendacion: ["Recomendación", "Recommendation", "slate"],
  info: ["", "", "slate"],
};

export function KindTag({ kind }: { kind: BlockKind }) {
  const lang = useStore((s) => s.lang);
  const [es, en, tone] = KIND_LABEL[kind] ?? KIND_LABEL.info;
  if (!es) return null;
  return (
    <Chip tone={tone}>
      {kind === "hipotesis" && <ShieldQuestion size={11} />}
      {lang === "en" ? en : es}
    </Chip>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400" role="status">
      <Loader2 className="animate-spin" size={16} /> {label}
    </div>
  );
}

export function ErrorBox({ error, onClose }: { error: string | null; onClose?: () => void }) {
  if (!error) return null;
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/60 dark:text-red-200">
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <div className="flex-1 break-words">{error}</div>
      {onClose && (
        <button className="text-xs underline" onClick={onClose}>
          OK
        </button>
      )}
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {hint && <div className="mt-0.5 truncate text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center text-sm text-slate-500 dark:border-slate-700">{children}</div>;
}

/** Encabezado de página consistente: título, explicación breve y acción principal a la derecha. */
export function PageHeader({ title, description, actions, icon }: { title: string; description?: ReactNode; actions?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-3">
        {icon && <div className="mt-0.5 rounded-lg bg-sky-100 p-2 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300">{icon}</div>}
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {description && <p className="mt-0.5 max-w-3xl text-sm text-slate-600 dark:text-slate-400">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Aviso destacado (éxito / información / advertencia) con acción opcional. */
export function Callout({ tone = "info", title, children, action }: { tone?: "success" | "info" | "warning"; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  const tones = {
    success: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-100",
    info: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950/40 dark:text-sky-100",
    warning: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100",
  };
  return (
    <div className={cls("flex flex-wrap items-center gap-3 rounded-xl border px-4 py-3", tones[tone])} role={tone === "warning" ? "alert" : "status"}>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold">{title}</div>
        {children && <div className="mt-0.5 text-sm opacity-90">{children}</div>}
      </div>
      {action}
    </div>
  );
}

/** Notificaciones efímeras (toasts) para confirmar acciones sin interrumpir. */
export function Toasts() {
  const t0 = useT();
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(92vw,380px)] flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={cls(
            "pointer-events-auto flex items-start gap-2 rounded-xl border px-4 py-3 text-sm shadow-lg",
            t.tone === "error"
              ? "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100"
              : "border-emerald-300 bg-white text-slate-900 dark:border-emerald-800 dark:bg-slate-900 dark:text-slate-100",
          )}
        >
          <span className={cls("mt-1 h-2 w-2 shrink-0 rounded-full", t.tone === "error" ? "bg-red-500" : "bg-emerald-500")} />
          <span className="flex-1">{t.text}</span>
          <button className="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200" onClick={() => dismiss(t.id)} aria-label={t0.dismiss}>
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}
