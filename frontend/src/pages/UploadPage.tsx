import { AlertTriangle, ArrowRight, CheckCircle2, ChevronDown, FileSpreadsheet, Lock, Settings2, UploadCloud } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import EventsTable from "../components/EventsTable";
import { Callout, Card, Chip, ErrorBox, PageHeader, Spinner, Stat } from "../components/ui";
import { api } from "../lib/api";
import { cls, fmtTs } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { SheetInfo } from "../lib/types";

const TIMEZONES: { value: string; label: string }[] = [
  { value: "America/Argentina/Buenos_Aires", label: "Buenos Aires (UTC−3)" },
  { value: "America/Santiago", label: "Santiago" },
  { value: "America/Montevideo", label: "Montevideo (UTC−3)" },
  { value: "America/Sao_Paulo", label: "São Paulo (UTC−3)" },
  { value: "America/Bogota", label: "Bogotá (UTC−5)" },
  { value: "America/Lima", label: "Lima (UTC−5)" },
  { value: "America/Mexico_City", label: "Ciudad de México (UTC−6)" },
  { value: "America/New_York", label: "Nueva York (UTC−5/−4)" },
  { value: "UTC", label: "UTC" },
  { value: "Europe/London", label: "Londres" },
  { value: "Europe/Madrid", label: "Madrid (UTC+1/+2)" },
  { value: "Europe/Stockholm", label: "Estocolmo (UTC+1/+2)" },
  { value: "Europe/Berlin", label: "Berlín (UTC+1/+2)" },
];

// Agrupación de campos para reducir la carga cognitiva: primero lo imprescindible.
const GROUPS: { id: "core" | "auth" | "proc" | "net" | "ctx"; fields: string[] }[] = [
  { id: "core", fields: ["timestamp", "user", "host", "src_ip", "event_id", "outcome", "message"] },
  { id: "auth", fields: ["logon_type", "target_user", "src_host", "country", "city", "lat", "lon", "assigned_ip"] },
  { id: "proc", fields: ["command_line", "process", "parent_process", "hash", "service", "group", "privileges"] },
  { id: "net", fields: ["destination", "dst_ip", "dst_host", "port", "domain", "share", "bytes_out"] },
  { id: "ctx", fields: ["log_id", "log_source", "siem_severity", "action"] },
];
const ESSENTIAL = ["timestamp", "user", "host", "event_id"];

function sampleValue(sheet: SheetInfo, column: string): string | null {
  for (const row of sheet.preview) {
    const v = row[column];
    if (v !== null && v !== undefined && String(v).trim() !== "") return String(v);
  }
  return null;
}

function FieldSelect({ field, label, sheet, value, used, onChange }: {
  field: string;
  label: string;
  sheet: SheetInfo;
  value: string;
  used: Set<string>;
  onChange: (v: string) => void;
}) {
  const t = useT();
  const auto = value && sheet.suggested_mapping[field] === value;
  const sample = value ? sampleValue(sheet, value) : null;
  return (
    <div className="min-w-0">
      <label className="mb-1 flex items-center justify-between gap-2 text-xs font-medium text-slate-600 dark:text-slate-300" htmlFor={`m-${field}`}>
        <span className="truncate">{label}</span>
        {value ? (
          <Chip tone={auto ? "emerald" : "amber"} title={auto ? t.autoDetected : t.manualChosen}>
            {auto ? `${t.auto} ${Math.round((sheet.scores[field] ?? 0) * 100)}%` : t.manual}
          </Chip>
        ) : null}
      </label>
      <select
        id={`m-${field}`}
        className={cls("input py-1.5", !value && "text-slate-400")}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">{t.unmapped}</option>
        {sheet.columns.map((c) => (
          <option key={c} value={c} disabled={used.has(c) && c !== value}>
            {c}
            {used.has(c) && c !== value ? t.alreadyUsed : ""}
          </option>
        ))}
      </select>
      <div className="mono mt-1 h-4 truncate text-xs text-slate-500" title={sample ?? ""}>
        {sample ? fmt(t.sampleEg, { v: sample }) : value ? t.noPreviewValues : ""}
      </div>
    </div>
  );
}

export default function UploadPage() {
  const t = useT();
  const { upload, setUpload, quality, setQuality, setStep, toast, lang } = useStore();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  // Al volver a este paso se reconstruye el estado desde la sesión (mapeo confirmado o sugerido)
  const [included, setIncluded] = useState<Record<string, boolean>>(() =>
    Object.fromEntries((upload?.sheets ?? []).map((s) => [s.name, quality ? quality.sheets.some((q) => q.name === s.name) : s.selected])),
  );
  const [mappings, setMappings] = useState<Record<string, Record<string, string>>>(() =>
    Object.fromEntries(
      (upload?.sheets ?? []).map((s) => [s.name, { ...(quality?.sheets.find((q) => q.name === s.name)?.mapping ?? s.suggested_mapping) }]),
    ),
  );
  const [active, setActive] = useState<string>(() => upload?.sheets.find((s) => s.selected)?.name ?? upload?.sheets[0]?.name ?? "");
  const [tz, setTz] = useState(quality?.timezone ?? upload?.default_timezone ?? "America/Argentina/Buenos_Aires");
  const [dayfirst, setDayfirst] = useState(quality?.dayfirst ?? true);
  const input = useRef<HTMLInputElement>(null);

  const onFile = async (file: File | undefined | "sample") => {
    if (!file) return;
    setError(null);
    if (file !== "sample" && !file.name.toLowerCase().endsWith(".xlsx")) {
      setError(t.onlyXlsx);
      return;
    }
    setBusy(t.uploading);
    try {
      const res = file === "sample" ? await api.uploadSample() : await api.upload(file);
      setUpload(res);
      setIncluded(Object.fromEntries(res.sheets.map((s) => [s.name, s.selected])));
      setMappings(Object.fromEntries(res.sheets.map((s) => [s.name, { ...s.suggested_mapping }])));
      setActive(res.sheets.find((s) => s.selected)?.name ?? res.sheets[0]?.name ?? "");
      setTz(res.default_timezone);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const confirm = async () => {
    if (!upload) return;
    setError(null);
    setBusy(t.normalizing);
    try {
      const sheets = upload.sheets.filter((s) => included[s.name]).map((s) => ({ name: s.name, mapping: mappings[s.name] ?? {} }));
      if (!sheets.length) throw new Error(t.selectOneSheet);
      const q = await api.mapping(upload.session_id, { sheets, timezone: tz, dayfirst });
      setQuality(q);
      toast(fmt(t.normalizedToast, { n: q.total_rows.toLocaleString(), invalid: q.invalid_rows }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const sheet = upload?.sheets.find((s) => s.name === active);
  const mapping = mappings[active] ?? {};
  const usedCols = useMemo(() => new Set(Object.values(mappings[active] ?? {}).filter(Boolean)), [mappings, active]);
  const tzLabels = TIMEZONES.map((z) => ({ ...z, label: (t.tzCities as Record<string, string>)[z.value] ?? z.label }));
  const tzOptions = tzLabels.some((z) => z.value === tz) ? tzLabels : [{ value: tz, label: tz }, ...tzLabels];
  const includedCount = upload ? upload.sheets.filter((s) => included[s.name]).length : 0;

  // ---------------------------------------------------------------- estado vacío
  if (!upload) {
    return (
      <div className="mx-auto max-w-5xl space-y-6 pt-4">
        <PageHeader
          icon={<UploadCloud size={20} />}
          title={t.uploadTitle}
          description={t.uploadDesc}
        />
        <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
          <div className="space-y-3">
            <div
              role="button"
              tabIndex={0}
              aria-label={t.chooseFile}
              onClick={() => input.current?.click()}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDrag(false);
                onFile(e.dataTransfer.files[0]);
              }}
              className={cls(
                "card flex cursor-pointer flex-col items-center justify-center gap-3 border-2 border-dashed px-6 py-14 text-center transition focus-visible:outline-2 focus-visible:outline-sky-500",
                drag ? "border-sky-500 bg-sky-50 dark:bg-sky-950/40" : "hover:border-sky-400 hover:bg-slate-50 dark:hover:bg-slate-800/40",
              )}
            >
              <div className="rounded-full bg-sky-100 p-4 text-sky-700 dark:bg-sky-900/50 dark:text-sky-300">
                <UploadCloud size={34} />
              </div>
              <div className="text-lg font-semibold">{t.dropTitle}</div>
              <div className="text-sm text-slate-500">{t.dropOr}</div>
              <div className="text-xs text-slate-400">{fmt(t.dropLimits, { mb: 25 })}</div>
              <input ref={input} type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" hidden onChange={(e) => onFile(e.target.files?.[0])} />
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2 text-sm text-slate-500">
              {t.noFileHandy}
              <button className="btn-secondary py-1.5 text-xs" onClick={() => onFile("sample")} disabled={!!busy}>
                <FileSpreadsheet size={14} aria-hidden="true" /> {t.trySample}
              </button>
            </div>
            {busy && (
              <div className="flex justify-center">
                <Spinner label={busy} />
              </div>
            )}
            <ErrorBox error={error} onClose={() => setError(null)} />
          </div>
          <div className="space-y-4">
            <Card title={t.howItWorks}>
              <ol className="space-y-3 text-sm">
                {t.howSteps.map(([title, text], i) => (
                  <li key={title} className="flex gap-3">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-sky-700 text-xs font-semibold text-white">{i + 1}</span>
                    <span>
                      <b>{title}.</b> <span className="text-slate-600 dark:text-slate-400">{text}</span>
                    </span>
                  </li>
                ))}
              </ol>
            </Card>
            <div className="flex gap-3 rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400">
              <Lock size={18} className="mt-0.5 shrink-0 text-emerald-600" />
              <p>
                {t.privacyLead} <b>{t.privacyBold}</b> {t.privacyRest}
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------- mapeo y calidad
  const fields = lang === "en" && upload.fields_en ? upload.fields_en : upload.fields;
  const missingEssential = ESSENTIAL.filter((f) => !mapping[f]);
  const mappedCount = Object.values(mapping).filter(Boolean).length;
  const groupsToShow = GROUPS.map((g) => ({
    ...g,
    visible: g.id === "core" || showAll ? g.fields : g.fields.filter((f) => mapping[f]),
  })).filter((g) => g.visible.length);
  const hiddenCount = Object.keys(fields).length - groupsToShow.reduce((n, g) => n + g.visible.length, 0);

  return (
    <div className="space-y-5 pb-24">
      <PageHeader
        icon={<FileSpreadsheet size={20} />}
        title={quality ? t.normalizedTitle : t.reviewMappingTitle}
        description={
          quality ? t.normalizedDesc : t.mappingDesc
        }
        actions={
          <span className="text-xs text-slate-500">
            {fmt(t.fileInfo, { name: upload.filename, kb: (upload.size / 1024).toFixed(0), n: upload.sheets.length })}
          </span>
        }
      />
      <ErrorBox error={error} onClose={() => setError(null)} />

      {quality && (
        <Callout
          tone="success"
          title={
            <span className="flex items-center gap-2">
              <CheckCircle2 size={16} aria-hidden="true" /> {fmt(t.eventsReady, { n: quality.total_rows.toLocaleString() })}
            </span>
          }
          action={
            <button className="btn-primary" onClick={() => setStep("analysis")}>
              {t.goAnalyze} <ArrowRight size={15} />
            </button>
          }
        >
          {quality.invalid_rows ? fmt(t.invalidKept, { n: quality.invalid_rows }) : ""}
          {fmt(t.rangeLine, { from: fmtTs(quality.date_min, false), to: fmtTs(quality.date_max, false), tz: quality.timezone })}
        </Callout>
      )}

      <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
        <Card title={t.sheets} subtitle={t.sheetsHint}>
          <ul className="space-y-1.5">
            {upload.sheets.map((s) => {
              const noTs = !mappings[s.name]?.timestamp;
              return (
                <li key={s.name}>
                  <div
                    className={cls(
                      "flex items-start gap-2 rounded-lg px-2 py-2 transition",
                      s.name === active ? "bg-sky-50 ring-1 ring-sky-300 dark:bg-sky-950/40 dark:ring-sky-800" : "hover:bg-slate-50 dark:hover:bg-slate-800",
                    )}
                  >
                    <input
                      type="checkbox"
                      className="mt-1"
                      aria-label={`${t.include} ${s.name}`}
                      checked={!!included[s.name]}
                      onChange={(e) => setIncluded({ ...included, [s.name]: e.target.checked })}
                    />
                    <button className="min-w-0 flex-1 text-left" onClick={() => setActive(s.name)}>
                      <div className="truncate text-sm font-medium">{s.name}</div>
                      <div className="text-xs text-slate-500">
                        {fmt(t.sheetRows, { n: s.rows.toLocaleString() })} · {fmt(t.columnsCount, { n: s.columns.length })}
                      </div>
                      {noTs && <div className="mt-0.5 text-xs text-amber-700 dark:text-amber-400">{t.noTimestamp}</div>}
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        </Card>

        {sheet && (
          <Card
            title={fmt(t.columnsOf, { name: sheet.name })}
            subtitle={fmt(t.mappedHint, { n: mappedCount })}
            actions={
              <button className="btn-ghost py-1 text-xs" onClick={() => setShowAll(!showAll)} aria-expanded={showAll}>
                <Settings2 size={14} /> {showAll ? t.hideUnmapped : fmt(t.showAllFields, { n: hiddenCount })}
              </button>
            }
          >
            {missingEssential.length > 0 && included[sheet.name] && (
              <div className="mb-4 flex items-start gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                <span>
                  {t.missingEssential} <b>{missingEssential.map((f) => fields[f]).join(", ")}</b>.
                  {missingEssential.includes("timestamp") ? t.noDateSheet : t.notEvaluableRules}
                </span>
              </div>
            )}
            <div className="space-y-5">
              {groupsToShow.map((g) => (
                <fieldset key={g.id}>
                  <legend className="mb-2 flex items-baseline gap-2">
                    <span className="text-sm font-semibold">{t.fieldGroups[g.id][0]}</span>
                    <span className="text-xs text-slate-500">{t.fieldGroups[g.id][1]}</span>
                  </legend>
                  <div className="grid gap-x-5 gap-y-2 sm:grid-cols-2 xl:grid-cols-3">
                    {g.visible
                      .filter((f) => fields[f])
                      .map((f) => (
                        <FieldSelect
                          key={f}
                          field={f}
                          label={fields[f]}
                          sheet={sheet}
                          value={mapping[f] ?? ""}
                          used={usedCols}
                          onChange={(v) => setMappings({ ...mappings, [sheet.name]: { ...mapping, [f]: v } })}
                        />
                      ))}
                  </div>
                </fieldset>
              ))}
            </div>
            <button className="mt-5 flex items-center gap-1 text-xs font-medium text-sky-700 dark:text-sky-300" onClick={() => setShowPreview(!showPreview)} aria-expanded={showPreview}>
              <ChevronDown size={14} className={cls("transition", showPreview && "rotate-180")} /> {t.previewRows}
            </button>
            {showPreview && (
              <div tabIndex={0} role="region" aria-label={t.sheetPreviewAria} className="mt-2 max-h-64 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
                <table className="w-full border-collapse">
                  <thead>
                    <tr>
                      {sheet.columns.map((c) => (
                        <th key={c} className="th cursor-default">
                          {c}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sheet.preview.map((row, i) => (
                      <tr key={i}>
                        {sheet.columns.map((c) => (
                          <td key={c} className="td mono max-w-[260px] truncate" title={row[c] ?? ""}>
                            {row[c] ?? ""}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        )}
      </div>

      {quality && (
        <>
          <Card title={t.quality}>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
              <Stat label={t.totalRows} value={quality.total_rows.toLocaleString()} />
              <Stat label={t.validRows} value={quality.valid_rows.toLocaleString()} accent="#059669" />
              <Stat label={t.invalidRows} value={quality.invalid_rows} accent={quality.invalid_rows ? "#d97706" : undefined} />
              <Stat label={t.formulaCells} value={quality.formula_cells} accent={quality.formula_cells ? "#dc2626" : undefined} />
              <Stat label={t.dateRange} value={<span className="text-sm">{fmtTs(quality.date_min, false)}</span>} hint={`→ ${fmtTs(quality.date_max, false)} (${quality.timezone})`} />
              <Stat label={t.fieldsPresent} value={quality.fields_present.length} hint={quality.fields_present.join(", ")} />
            </div>
            {quality.issue_rows.length > 0 && (
              <details className="mt-3">
                <summary className="cursor-pointer text-sm font-medium text-amber-700 dark:text-amber-400">
                  {t.issues} ({quality.issue_rows.length})
                </summary>
                <ul tabIndex={0} role="region" aria-label={t.issues} className="mt-2 max-h-48 space-y-0.5 overflow-auto text-xs">
                  {quality.issue_rows.map((r) => (
                    <li key={r.row_id}>
                      <span className="mono text-sky-700 dark:text-sky-300">{r.row_id}</span> — {r.issues.join("; ")}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </Card>
          <Card title={t.eventsTable} subtitle={t.eventsTableHint}>
            <EventsTable />
          </Card>
        </>
      )}

      {/* barra de acción fija: la acción principal siempre visible */}
      <div className="fixed inset-x-0 bottom-0 z-30 border-t border-slate-200 bg-white/95 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-slate-600 dark:text-slate-300" htmlFor="tz">
              {t.logsTimezone}
            </label>
            <select id="tz" className="input w-auto py-1.5" value={tz} onChange={(e) => setTz(e.target.value)} title={t.tzTitle}>
              {tzOptions.map((z) => (
                <option key={z.value} value={z.value}>
                  {z.label}
                </option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
            <input type="checkbox" checked={dayfirst} onChange={(e) => setDayfirst(e.target.checked)} /> {t.dayfirst}
          </label>
          <span className="text-xs text-slate-500">{fmt(t.sheetsSelected, { n: includedCount })}</span>
          <div className="ml-auto flex items-center gap-2">
            {busy && <Spinner label={busy} />}
            {quality ? (
              <>
                <button className="btn-secondary" onClick={confirm} disabled={!!busy || !includedCount}>
                  {t.renormalize}
                </button>
                <button className="btn-primary" onClick={() => setStep("analysis")}>
                  {t.goAnalyze} <ArrowRight size={15} />
                </button>
              </>
            ) : (
              <button className="btn-primary px-5" onClick={confirm} disabled={!!busy || !includedCount}>
                {t.confirmMapping} <ArrowRight size={15} />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
