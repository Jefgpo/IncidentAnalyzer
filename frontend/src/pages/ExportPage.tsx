import { Briefcase, Download, FileDown, ShieldOff, Trash2, Wrench } from "lucide-react";
import { useState } from "react";
import { Card, ErrorBox, PageHeader, Spinner } from "../components/ui";
import { api, downloadBlob } from "../lib/api";
import { fmt, useT } from "../lib/i18n";
import { confirmDialog, useStore } from "../lib/store";
import type { ReportKind } from "../lib/types";

const KINDS: { kind: ReportKind; label: "execLabel" | "techLabel"; audience: "execAudience" | "techAudience"; file: string; Icon: typeof Briefcase }[] = [
  { kind: "ejecutivo", label: "execLabel", audience: "execAudience", file: "informe_ejecutivo", Icon: Briefcase },
  { kind: "tecnico", label: "techLabel", audience: "techAudience", file: "informe_tecnico", Icon: Wrench },
];

export default function ExportPage() {
  const t = useT();
  const { upload, reports, reset, setReports, toast } = useStore();
  const [busy, setBusy] = useState<ReportKind | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sid = upload?.session_id ?? "";

  const pdf = async (kind: ReportKind, file: string) => {
    setBusy(kind);
    setError(null);
    try {
      const version = reports?.[kind].meta.version ?? 1;
      const blob = await api.pdf(sid, kind);
      downloadBlob(blob, `${file}_v${version}.pdf`);
      setReports(await api.reports(sid));
      toast(fmt(t.pdfDownloaded, { f: `${file}_v${version}.pdf` }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const wipe = async () => {
    if (!(await confirmDialog({ title: t.wipeTitle, message: t.wipeMsg, confirmLabel: t.wipeLabel, tone: "danger" }))) return;
    await api.deleteSession(sid).catch(() => undefined);
    reset();
    toast(t.deleted);
  };

  if (!reports) return <ErrorBox error={t.needReport} />;

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <PageHeader icon={<FileDown size={20} />} title={t.exportPageTitle} description={t.exportHelp} />
      <div className="grid gap-4 md:grid-cols-2">
        {KINDS.map(({ kind, label, audience, file, Icon }) => {
          const rep = reports[kind];
          const blocks = rep.sections.flatMap((s) => s.blocks);
          const ai = blocks.filter((b) => b.origin === "ia").length;
          const edited = blocks.filter((b) => b.origin === "editado").length;
          return (
            <Card
              key={kind}
              title={
                <span className="flex items-center gap-2">
                  <Icon size={16} className="text-sky-700 dark:text-sky-400" aria-hidden="true" /> {t[label]}
                </span>
              }
              subtitle={t[audience]}
            >
              <dl className="mb-4 grid grid-cols-2 gap-2 text-sm">
                <div>
                  <dt className="label">{t.statSections}</dt>
                  <dd className="font-semibold">{rep.sections.length}</dd>
                </div>
                <div>
                  <dt className="label">{t.nextVersion}</dt>
                  <dd className="font-semibold">v{rep.meta.version}</dd>
                </div>
                <div>
                  <dt className="label">{t.editedCount}</dt>
                  <dd className="font-semibold">{edited}</dd>
                </div>
                <div>
                  <dt className="label">{t.aiBlocks}</dt>
                  <dd className="font-semibold">{ai}</dd>
                </div>
              </dl>
              <button className="btn-primary w-full py-2.5" onClick={() => pdf(kind, file)} disabled={!!busy}>
                {busy === kind ? <Spinner /> : <FileDown size={17} aria-hidden="true" />} {t.downloadPdf}
              </button>
            </Card>
          );
        })}
      </div>
      <ErrorBox error={error} />
      <Card title={t.iocsCardTitle} subtitle={t.iocsCardHint}>
        <button className="btn-secondary" onClick={async () => downloadBlob(await api.iocsCsv(sid), "iocs.csv")}>
          <Download size={15} /> {t.downloadIocs}
        </button>
      </Card>
      <Card title={<span className="flex items-center gap-2"><ShieldOff size={15} aria-hidden="true" /> {t.clientData}</span>}>
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
          {t.clientDataNote}
        </p>
        <button className="btn-danger" onClick={wipe}>
          <Trash2 size={15} /> {t.deleteData}
        </button>
      </Card>
    </div>
  );
}
