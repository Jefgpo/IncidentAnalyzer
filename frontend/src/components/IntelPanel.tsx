import { ExternalLink, KeyRound, Radar, ShieldAlert, Square } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { cls } from "../lib/format";
import { fmt, useT } from "../lib/i18n";
import { useStore } from "../lib/store";
import type { IntelJob, IntelProviderResult, IntelResultRow, IntelStatus, IntelVerdict } from "../lib/types";
import { Card, Chip, Empty, ErrorBox, Spinner, Stat } from "./ui";

const VERDICT_TONE: Record<IntelVerdict, "red" | "amber" | "emerald" | "slate"> = {
  malicioso: "red",
  sospechoso: "amber",
  limpio: "emerald",
  sin_datos: "slate",
  error: "slate",
};

function Verdict({ r }: { r?: IntelProviderResult }) {
  const t = useT();
  if (!r) return <span className="text-xs text-slate-500">—</span>;
  const key = r.verdict in VERDICT_TONE ? r.verdict : "sin_datos";
  const v = { tone: VERDICT_TONE[key], label: t.verdicts[key] };
  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-1">
        <Chip tone={v.tone}>{v.label}</Chip>
        <a href={r.link} target="_blank" rel="noopener noreferrer" className="text-slate-400 hover:text-sky-600" title={t.openInProvider} aria-label={t.openInProvider}>
          <ExternalLink size={12} aria-hidden="true" />
        </a>
        {r.cached && <span className="text-xs text-slate-500">{t.cachedTag}</span>}
      </div>
      <div className="text-xs text-slate-500">{r.summary}</div>
    </div>
  );
}

function IpList({ title, ips, tone, rows }: { title: string; ips: string[]; tone: string; rows: Record<string, IntelResultRow> }) {
  const t = useT();
  const openDrawer = useStore((s) => s.openDrawer);
  return (
    <Card title={<span className="flex items-center gap-2"><span className={cls("h-2.5 w-2.5 rounded-full", tone)} />{title} ({ips.length})</span>}>
      {ips.length === 0 ? (
        <p className="text-sm text-slate-500">{t.noBadIps}</p>
      ) : (
        <ul className="space-y-1.5">
          {ips.map((ip) => {
            const r = rows[ip];
            return (
              <li key={ip} className="flex flex-wrap items-center gap-2 text-sm">
                <button className="mono font-medium text-sky-700 hover:underline dark:text-sky-300" onClick={() => openDrawer(fmt(t.eventsOf, { ip }), { src_ip: ip, size: 100 })}>
                  {ip}
                </button>
                {r?.incident_ids.map((i) => <Chip key={i} tone="red">{i}</Chip>)}
                <span className="text-xs text-slate-500">
                  {[r?.abuseipdb?.country, r?.abuseipdb?.isp, r?.abuseipdb?.score !== undefined ? fmt(t.abuseScore, { n: r.abuseipdb.score }) : null].filter(Boolean).join(" · ")}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

export default function IntelPanel() {
  const t = useT();
  const sid = useStore((s) => s.upload?.session_id ?? "");
  const openDrawer = useStore((s) => s.openDrawer);
  const lang = useStore((s) => s.lang);
  const [status, setStatus] = useState<IntelStatus | null>(null);
  const [job, setJob] = useState<IntelJob | null>(null);
  const [abuseKey, setAbuseKey] = useState("");
  const [maxIps, setMaxIps] = useState(25);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    api.intelStatus().then((s) => (setStatus(s), setMaxIps(s.default_max_ips))).catch((e) => setError(e.message));
    if (sid) api.intelGet(sid).then(setJob).catch(() => undefined);
  }, [sid, lang]); // los motivos y notas del job llegan traducidos

  // sondeo del progreso mientras el job está en curso
  useEffect(() => {
    if (!sid || job?.status !== "en_curso") return;
    const h = setInterval(() => api.intelGet(sid).then(setJob).catch((e) => setError(e.message)), 2000);
    return () => clearInterval(h);
  }, [sid, job?.status]);

  const rows = useMemo(() => Object.fromEntries((job?.results ?? []).map((r) => [r.ip, r])), [job]);
  const prov = status?.providers ?? {};
  const canRun = !!(prov.abuseipdb?.configured || abuseKey.trim());
  const running = job?.status === "en_curso";

  const start = async () => {
    setError(null);
    setStarting(true);
    try {
      setJob(await api.intelStart(sid, { abuseipdb_key: abuseKey.trim() || undefined, max_ips: maxIps }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setStarting(false);
    }
  };

  const keyField = (name: "abuseipdb", value: string, set: (v: string) => void) => {
    const p = prov[name];
    return (
      <div className="min-w-[240px] flex-1">
        <label className="label flex items-center justify-between" htmlFor={`k-${name}`}>
          <span>{p?.label ?? name} API key</span>
          {p?.configured ? <Chip tone="emerald">{t.keyConfigured}</Chip> : <Chip>{t.keyNotConfigured}</Chip>}
        </label>
        <input
          id={`k-${name}`}
          type="password"
          autoComplete="off"
          className="input"
          placeholder={p?.configured ? t.keyPlaceholderOptional : fmt(t.keyPlaceholder, { env: p?.env_var ?? "" })}
          value={value}
          onChange={(e) => set(e.target.value)}
          maxLength={200}
        />
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <Card
        title={<span className="flex items-center gap-2"><Radar size={15} aria-hidden="true" /> {t.intelTitle}</span>}
        subtitle={t.intelHint}
      >
        <div className="flex flex-wrap items-end gap-3">
          {keyField("abuseipdb", abuseKey, setAbuseKey)}
          <div className="w-28">
            <label className="label" htmlFor="maxips">{t.maxIps}</label>
            <input id="maxips" type="number" min={1} max={500} className="input" value={maxIps} onChange={(e) => setMaxIps(Math.max(1, Math.min(500, Number(e.target.value) || 1)))} />
          </div>
          {running ? (
            <button className="btn-secondary" onClick={async () => setJob(await api.intelCancel(sid))}>
              <Square size={14} aria-hidden="true" /> {t.stop}
            </button>
          ) : (
            <button className="btn-primary" onClick={start} disabled={!canRun || starting}>
              <ShieldAlert size={15} /> {job?.status === "completado" ? t.queryAgain : t.queryReputation}
            </button>
          )}
        </div>
        <p className="mt-2 flex items-start gap-1.5 text-xs text-slate-500">
          <KeyRound size={12} className="mt-0.5 shrink-0" />
          {t.keysNote}
        </p>
        <div className="mt-2">
          <ErrorBox error={error} onClose={() => setError(null)} />
        </div>
      </Card>

      {job && job.status !== "sin_ejecutar" && job.providers && (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            {Object.entries(job.providers).map(([name, p]) => (
              <div key={name} className="card px-4 py-3">
                <div className="flex items-center justify-between text-sm font-medium">
                  <span>{p.label}</span>
                  <Chip tone={p.state === "error" ? "red" : p.state === "completado" ? "emerald" : p.state === "omitido" ? "slate" : "sky"}>
                    {(t.intelStates as Record<string, string>)[p.state] ?? p.state}
                    {p.key_source ? fmt(t.keyFrom, { src: p.key_source }) : ""}
                  </Chip>
                </div>
                {p.state !== "omitido" && (
                  <>
                    <div className="mt-2 h-2 overflow-hidden rounded bg-slate-200 dark:bg-slate-800">
                      <div className="h-full bg-sky-700 transition-all" style={{ width: `${p.total ? (100 * p.done) / p.total : 100}%` }} />
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      {p.done}/{p.total} IPs
                      {p.state === "en_curso" && p.eta_s > 30 && fmt(t.remainingMin, { n: Math.ceil(((p.total - p.done) * p.eta_s) / Math.max(p.total, 1) / 60) })}
                      {p.note && ` · ${p.note}`}
                    </div>
                  </>
                )}
                {p.error && <div className="mt-1 text-xs text-red-600 dark:text-red-400">{p.error}</div>}
              </div>
            ))}
          </div>
          {running && <Spinner label={t.querying} />}

          {job.summary && (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
                <Stat label={t.statPublic} value={job.total_public ?? 0} hint={fmt(t.statPublicHint, { n: job.selected ?? 0, max: job.max_ips ?? 0 })} />
                <Stat label={t.statMalicious} value={job.summary.bad_abuseipdb.length} accent="#dc2626" hint={t.statMaliciousHint} />
                <Stat label={t.statSuspicious} value={job.summary.suspicious.length} accent="#a16207" hint={t.statSuspiciousHint} />
              </div>
              <div className="grid gap-4 lg:grid-cols-2">
                <IpList title={t.badRep} ips={job.summary.bad_abuseipdb} tone="bg-red-600" rows={rows} />
                <IpList title={t.suspRep} ips={job.summary.suspicious} tone="bg-yellow-500" rows={rows} />
              </div>
            </>
          )}

          <Card title={t.perIp} subtitle={t.perIpHint}>
            {(job.results ?? []).length === 0 ? (
              <Empty>{t.noPublicIps}</Empty>
            ) : (
              <div tabIndex={0} role="region" aria-label={t.perIpAria} className="overflow-auto">
                <table className="w-full min-w-[820px] border-collapse">
                  <thead>
                    <tr>
                      {t.intelCols.map((h) => (
                        <th key={h} className="th cursor-default">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(job.results ?? []).map((r) => (
                      <tr key={r.ip}>
                        <td className="td mono">
                          <button className="text-sky-700 hover:underline dark:text-sky-300" onClick={() => openDrawer(fmt(t.eventsOf, { ip: r.ip }), { src_ip: r.ip, size: 100 })}>
                            {r.ip}
                          </button>
                        </td>
                        <td className="td tabular-nums">{r.events}</td>
                        <td className="td">
                          <div className="flex flex-wrap gap-1">
                            {r.incident_ids.map((i) => <Chip key={i} tone="red">{i}</Chip>)}
                            {r.finding_ids.slice(0, 5).map((f) => <Chip key={f}>{f}</Chip>)}
                            {r.finding_ids.length > 5 && <span className="text-xs text-slate-500">+{r.finding_ids.length - 5}</span>}
                          </div>
                        </td>
                        <td className="td"><Verdict r={r.abuseipdb} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {(job.skipped?.length ?? 0) > 0 && (
              <details className="mt-3 text-xs">
                <summary className="cursor-pointer text-slate-500">{fmt(t.notQueried, { n: job.skipped!.length })}</summary>
                <ul className="mt-1 space-y-0.5">
                  {job.skipped!.map((s) => (
                    <li key={s.ip}><span className="mono">{s.ip}</span> — {s.reason}</li>
                  ))}
                </ul>
              </details>
            )}
            {(job.not_queried?.length ?? 0) > 0 && (
              <p className="mt-2 text-xs text-slate-500">{fmt(t.overLimit, { n: job.not_queried!.length, max: job.max_ips ?? 0 })}</p>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
