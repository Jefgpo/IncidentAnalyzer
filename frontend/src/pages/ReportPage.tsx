import { Briefcase, Wrench, ArrowRight, BarChart3, Bot, FileText, MessageSquare, Pencil, RefreshCw, Send } from "lucide-react";
import { useEffect, useState } from "react";
import { Callout, Card, Chip, ErrorBox, KindTag, OriginTag, PageHeader, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { cls } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { confirmDialog, useStore } from "../lib/store";
import type { ReportBlock, ReportKind } from "../lib/types";

function RowRefs({ rows }: { rows?: string[] }) {
  const t = useT();
  const openDrawer = useStore((s) => s.openDrawer);
  if (!rows?.length) return null;
  return (
    <button className="mono mt-1 text-left text-xs text-sky-700 hover:underline dark:text-sky-300" onClick={() => openDrawer(t.citedRows, { rows: rows.join(","), size: 100 })}>
      {t.rowsPrefix} {rows.slice(0, 8).join(", ")}
      {rows.length > 8 ? ` +${rows.length - 8}` : ""}
    </button>
  );
}

function Block({ b, onSave }: { b: ReportBlock; onSave: (b: ReportBlock, value: { text?: string; items?: string[] }) => Promise<void> }) {
  const t = useT();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const start = () => {
    setDraft(b.type === "list" ? (b.items ?? []).join("\n") : b.text ?? "");
    setEditing(true);
  };
  const save = async () => {
    setSaving(true);
    await onSave(b, b.type === "list" ? { items: draft.split("\n") } : { text: draft });
    setSaving(false);
    setEditing(false);
  };
  const tags = (
    <div className="flex flex-wrap items-center gap-1">
      <KindTag kind={b.kind} />
      <OriginTag origin={b.origin} review={b.review} />
      {b.editable && !editing && (
        <button className="ml-auto inline-flex items-center gap-1 text-xs text-slate-500 opacity-0 transition group-hover:opacity-100 focus:opacity-100" onClick={start}>
          <Pencil size={11} /> {t.edit}
        </button>
      )}
    </div>
  );
  return (
    <div className={cls("group rounded-lg px-3 py-2", b.origin === "ia" && "border-l-4 border-violet-400 bg-violet-50/50 dark:bg-violet-950/20", b.origin === "editado" && "border-l-4 border-amber-400")}>
      {b.title && b.type !== "chart" && <h4 className="mb-1 text-sm font-semibold">{b.title}</h4>}
      {b.type !== "table" && b.type !== "chart" && tags}
      {editing ? (
        <div className="mt-1 space-y-2">
          <textarea className="input min-h-[120px] font-sans" value={draft} onChange={(e) => setDraft(e.target.value)} aria-label={t.editText} />
          {b.type === "list" && <div className="text-xs text-slate-500">{t.onePerLine}</div>}
          <div className="flex gap-2">
            <button className="btn-primary py-1 text-xs" onClick={save} disabled={saving}>
              {t.save}
            </button>
            <button className="btn-ghost py-1 text-xs" onClick={() => setEditing(false)}>
              {t.cancel}
            </button>
          </div>
        </div>
      ) : b.type === "paragraph" ? (
        <p className="mt-1 text-sm leading-relaxed">{b.text}</p>
      ) : b.type === "list" ? (
        <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
          {b.items?.map((it, i) => (
            <li key={i}>{it}</li>
          ))}
        </ul>
      ) : b.type === "chart" ? (
        <div className="flex items-center gap-2 rounded-md border border-dashed border-slate-300 px-3 py-2 text-xs text-slate-500 dark:border-slate-700">
          <BarChart3 size={14} aria-hidden="true" /> {b.title} {t.chartPlaceholder}
        </div>
      ) : (
        <div>
          {b.title && <h4 className="mb-1 text-sm font-semibold">{b.title}</h4>}
          <div tabIndex={0} role="region" aria-label={b.title ?? `${t.reportTable} · ${b.id}`} className="max-h-[360px] overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  {b.columns?.map((c) => (
                    <th key={c} className="th cursor-default">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {b.rows?.map((r, i) => (
                  <tr key={i}>
                    {r.map((v, j) => (
                      <td key={j} className={cls("td", (b.columns?.[j] ?? "").match(/ID fila|Row ID|Fragmento|Excerpt|Valor|Value|IP|Timestamp|Evento|Event/) && "mono break-all")}>
                        {v ?? ""}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <RowRefs rows={b.row_refs} />
    </div>
  );
}

function Chat() {
  const t = useT();
  const { upload, aiEnabled } = useStore();
  const [msg, setMsg] = useState("");
  const [log, setLog] = useState<{ q: string; a: string; rejected: number; rows: string[] }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const openDrawer = useStore((s) => s.openDrawer);
  const send = async () => {
    if (!upload || !msg.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.chat(upload.session_id, msg.trim());
      setLog([...log, { q: msg.trim(), a: r.answer, rejected: r.rejected, rows: r.claims.filter((c) => c.valid).flatMap((c) => c.row_ids) }]);
      setMsg("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title={<span className="flex items-center gap-2"><MessageSquare size={15} /> {t.chat}</span>} subtitle={t.chatHint}>
      {!aiEnabled ? (
        <p className="text-sm text-slate-500">{t.chatDisabled}</p>
      ) : (
        <div className="space-y-3">
          <div tabIndex={0} role="region" aria-label={t.chatAria} aria-live="polite" className="max-h-80 space-y-3 overflow-auto">
            {log.map((m, i) => (
              <div key={i} className="space-y-1 text-sm">
                <div className="rounded-lg bg-slate-100 px-3 py-2 dark:bg-slate-800">{m.q}</div>
                <div className="rounded-lg border-l-4 border-violet-400 bg-violet-50/50 px-3 py-2 dark:bg-violet-950/20">
                  <OriginTag origin="ia" /> <span className="ml-1">{m.a}</span>
                  {m.rows.length > 0 && (
                    <button className="mono mt-1 block text-xs text-sky-700 hover:underline dark:text-sky-300" onClick={() => openDrawer(t.aiCitedRows, { rows: m.rows.join(",") })}>
                      {t.rowsPrefix} {[...new Set(m.rows)].slice(0, 8).join(", ")}
                    </button>
                  )}
                  {m.rejected > 0 && <div className="mt-1 text-xs text-red-700 dark:text-red-400">{fmt(t.claimsRejected, { n: m.rejected })}</div>}
                </div>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <input className="input" placeholder={t.chatPlaceholder} value={msg} onChange={(e) => setMsg(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()} maxLength={2000} aria-label={t.chat} />
            <button className="btn-primary" onClick={send} disabled={busy || !msg.trim()} aria-label={t.send}>
              {busy ? <Spinner /> : <Send size={15} />}
            </button>
          </div>
          <ErrorBox error={error} />
        </div>
      )}
    </Card>
  );
}

export default function ReportPage() {
  const t = useT();
  const { upload, reports, setReports, aiEnabled, setStep, lang } = useStore();
  const [kind, setKind] = useState<ReportKind>("ejecutivo");
  const report = reports?.[kind] ?? null;
  const [client, setClient] = useState(reports?.tecnico.meta.client ?? t.defaultClient);
  const [analyst, setAnalyst] = useState(reports?.tecnico.meta.analyst ?? t.defaultAnalyst);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sid = upload?.session_id ?? "";
  // los valores por defecto (no editados) siguen al idioma de la interfaz
  useEffect(() => {
    const defaults = { client: ["Cliente (confidencial)", "Client (confidential)"], analyst: ["Analista SOC N2", "SOC L2 analyst"] };
    setClient((c) => (defaults.client.includes(c) ? t.defaultClient : c));
    setAnalyst((a) => (defaults.analyst.includes(a) ? t.defaultAnalyst : a));
  }, [t]);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const generate = async () => {
    if (reports && !(await confirmDialog({ title: t.regenTitle, message: t.regenMsg, confirmLabel: t.regenLabel, tone: "danger" }))) return;
    run(t.generatingReports, async () => setReports(await api.generateReport(sid, { lang, client, analyst })));
  };
  const saveBlock = async (b: ReportBlock, value: { text?: string; items?: string[] }) => {
    try {
      setReports(await api.updateBlock(sid, kind, b.id, value));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const header = (
    <div className="card flex flex-wrap items-end gap-3 px-4 py-3">
      <div className="min-w-[220px] flex-1">
        <label className="label" htmlFor="client">{t.client}</label>
        <input id="client" className="input" value={client} onChange={(e) => setClient(e.target.value)} maxLength={120} />
      </div>
      <div className="min-w-[200px] flex-1">
        <label className="label" htmlFor="analyst">{t.analyst}</label>
        <input id="analyst" className="input" value={analyst} onChange={(e) => setAnalyst(e.target.value)} maxLength={120} />
      </div>
      {report && (
        <button className="btn-secondary" onClick={() => run(t.saving, async () => setReports(await api.updateMeta(sid, { client, analyst })))}>
          {t.save}
        </button>
      )}
      <button className={report ? "btn-secondary" : "btn-primary"} onClick={generate} disabled={!!busy}>
        {report ? <RefreshCw size={15} /> : <FileText size={15} />} {report ? t.regenerate : t.generateReports}
      </button>
      {report && (
        <button
          className="btn btn-primary bg-violet-600 hover:bg-violet-700"
          disabled={!aiEnabled || !!busy}
          title={aiEnabled ? t.aiButtonTitle : t.aiOff}
          onClick={() => run(t.aiWorking, async () => (setReports(await api.aiReport(sid)), setKind("tecnico")))}
        >
          <Bot size={15} /> {t.aiImprove}
        </button>
      )}
      {report && (
        <button className="btn-primary" onClick={() => setStep("export")}>
          {t.steps.export} <ArrowRight size={15} />
        </button>
      )}
    </div>
  );

  const title = (
    <PageHeader
      icon={<FileText size={20} />}
      title={t.reportsTitle}
      description={t.reportsDesc}
    />
  );

  if (!report) {
    return (
      <div className="space-y-4">
        {title}
        {header}
        {busy && <Spinner label={busy} />}
        <ErrorBox error={error} />
        <p className="text-sm text-slate-500">
          {t.reportsIntro}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {title}
      {header}
      {busy && <Spinner label={busy} />}
      <ErrorBox error={error} />
      <div role="tablist" aria-label={t.reportTypeAria} className="grid gap-2 sm:grid-cols-2">
        {(
          [
            ["ejecutivo", t.execLabel, t.execDesc, Briefcase],
            ["tecnico", t.techLabel, t.techDesc, Wrench],
          ] as const
        ).map(([k, label, desc, Icon]) => (
          <button
            key={k}
            role="tab"
            aria-selected={kind === k}
            onClick={() => setKind(k)}
            className={cls(
              "flex items-start gap-3 rounded-xl border p-3 text-left transition",
              kind === k ? "border-sky-500 bg-sky-50 ring-1 ring-sky-400 dark:bg-sky-950/40" : "border-slate-200 bg-white hover:border-slate-400 dark:border-slate-800 dark:bg-slate-900",
            )}
          >
            <Icon size={20} className={kind === k ? "mt-0.5 text-sky-600" : "mt-0.5 text-slate-400"} />
            <span>
              <span className="block text-sm font-semibold">{label}</span>
              <span className="block text-xs text-slate-600 dark:text-slate-400">{desc}</span>
            </span>
          </button>
        ))}
      </div>
      {report.meta.lang && report.meta.lang !== lang && (
        <Callout
          tone="info"
          title={t.reportOtherLang}
          action={
            <button className="btn-secondary" onClick={generate} disabled={!!busy}>
              <RefreshCw size={15} aria-hidden="true" /> {t.regenerate}
            </button>
          }
        />
      )}
      {!aiEnabled && kind === "tecnico" && <div className="rounded-lg bg-slate-100 px-3 py-2 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300">{t.aiOff}{t.aiOffTemplates}</div>}
      <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
        <nav className="card sticky top-20 hidden h-fit max-h-[75vh] overflow-auto p-3 lg:block" aria-label={t.toc}>
          <div className="label">{t.toc}</div>
          <ol className="space-y-1 text-sm">
            {report.sections.map((s) => (
              <li key={s.id}>
                <a href={`#sec-${s.id}`} className="block rounded px-1 py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800">
                  {s.number}. {s.title.replace(/^(Anexo|Annex) [A-Z] – /, "")}
                </a>
              </li>
            ))}
          </ol>
        </nav>
        <article className="card space-y-6 p-6">
          <header className="border-b border-slate-200 pb-4 dark:border-slate-800">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="red">{report.meta.classification}</Chip>
              <Chip>v{report.meta.version}</Chip>
              {report.meta.ai_used && <Chip tone="violet">{fmt(t.aiModelChip, { m: report.meta.ai_model ?? "" })}</Chip>}
            </div>
            <h2 className="mt-2 text-xl font-bold">{report.meta.title}</h2>
            <p className="text-sm text-slate-500">
              {report.meta.client} · {report.meta.analyst} · {report.meta.source_file}
            </p>
          </header>
          {report.sections.map((s) => (
            <section key={s.id} id={`sec-${s.id}`} className="scroll-mt-24 space-y-2">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                {/^\d+$/.test(s.number) ? `${s.number}. ` : ""}
                {s.title}
              </h3>
              {s.blocks.map((b) => (
                <Block key={b.id} b={b} onSave={saveBlock} />
              ))}
              {s.id === "limitaciones" && report.ai_review.length > 0 && (
                <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm dark:border-red-900 dark:bg-red-950/30">
                  <div className="mb-1 font-semibold text-red-700 dark:text-red-300">{t.aiDiscarded} ({report.ai_review.length})</div>
                  <ul className="list-disc space-y-1 pl-5 text-xs">
                    {report.ai_review.map((r, i) => (
                      <li key={i}>
                        <b>{r.section}:</b> «{r.text}» — <i>{r.reason}</i>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          ))}
        </article>
      </div>
      <Chat />
    </div>
  );
}
