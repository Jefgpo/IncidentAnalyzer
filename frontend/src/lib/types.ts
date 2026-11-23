export type Severity = "Crítico" | "Alto" | "Medio" | "Bajo";

export interface SheetInfo {
  name: string;
  rows: number;
  columns: string[];
  preview: Record<string, string | null>[];
  suggested_mapping: Record<string, string>;
  scores: Record<string, number>;
  selected: boolean;
}

export interface UploadResponse {
  session_id: string;
  filename: string;
  size: number;
  sheets: SheetInfo[];
  fields: Record<string, string>;
  fields_en?: Record<string, string>;
  default_timezone: string;
}

export interface Quality {
  total_rows: number;
  valid_rows: number;
  invalid_rows: number;
  formula_cells: number;
  fields_present: string[];
  issue_rows: { row_id: string; issues: string[]; valid: boolean }[];
  sheets: { name: string; rows: number; mapping: Record<string, string> }[];
  timezone: string;
  dayfirst: boolean;
  date_min?: string;
  date_max?: string;
}

export interface EventRow {
  row_id: string;
  sheet: string;
  excel_row: number;
  ts_iso: string | null;
  user?: string | null;
  target_user?: string | null;
  host?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  event_id?: string | null;
  outcome?: string | null;
  logon_type?: string | null;
  process?: string | null;
  command_line?: string | null;
  message?: string | null;
  sem?: string | null;
  issues: string[];
  raw: Record<string, string | null>;
  finding_ids?: string[];
  [k: string]: unknown;
}

export interface EventsPage {
  total: number;
  page: number;
  size: number;
  rows: EventRow[];
}

export interface ScoreFactor {
  factor: string;
  points: number;
}

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  summary: string;
  rows: string[];
  start: string | null;
  end: string | null;
  entities: Record<string, string[]>;
  related: Record<string, string[]>;
  metrics: Record<string, unknown>;
  auth_success: boolean | null;
  confidence: string;
  fp_notes: string[];
  details: string[];
  category: string;
  tactic: string;
  mitre: { id: string; name: string }[];
  is_anomaly: boolean;
  score: number;
  severity: Severity;
  score_factors: ScoreFactor[];
  incident_id: string | null;
}

export interface Phase {
  tactic: string;
  label: string;
  label_en: string;
  mitre_tactic: string;
  first_seen: string;
  finding_ids: string[];
}

export interface Link {
  a: string;
  b: string;
  entity_type: string;
  value: string;
  shared: string[];
  rows_a: string[];
  rows_b: string[];
}

export interface Incident {
  id: string;
  title: string;
  finding_ids: string[];
  anomaly_ids: string[];
  start: string;
  end: string;
  entities: Record<string, string[]>;
  phases: Phase[];
  timeline: { ts: string; row_id: string; finding_ids: string[]; rule_ids: string[]; tactics: string[]; description: string }[];
  links: Link[];
  score: number;
  severity: Severity;
  score_factors: ScoreFactor[];
  summary: string;
}

export interface RuleStatus {
  id: string;
  name: string;
  name_en: string;
  category: string;
  tactic: string;
  mitre: { id: string; name: string }[];
  description: string;
  description_en: string;
  requires: string[];
  status: "con_hallazgos" | "sin_hallazgos" | "no_evaluable" | "error";
  missing: string[];
  count: number;
}

export interface Ioc {
  id: string;
  type: string;
  value: string;
  context: string;
  count: number;
  rows: string[];
  rows_truncated: boolean;
  finding_ids: string[];
}

export interface Methodology {
  formula: string;
  factors: { factor: string; points: string; detail: string }[];
  bands: { severity: Severity; range: string }[];
  base: Record<string, number>;
}

export interface Analysis {
  findings: Finding[];
  incidents: Incident[];
  isolated: string[];
  conclusion: { verdict: string; incident_count: number; text: string; justification: string[]; kind: string; unattached_anomalies: string[] };
  rules: RuleStatus[];
  categories: { category: string; label: string; label_en: string; findings: number; rules_total: number; rules_evaluable: number; status: string }[];
  iocs: Ioc[];
  methodology: Methodology;
  baseline_end: string | null;
  span_hours: number;
  config: { timezone: string; business_hours: { start: number; end: number; weekdays: number[] }; allowed_countries: string[]; min_baseline_hours: number };
  elapsed_s: number;
}

export interface Dashboard {
  kpis: {
    total_events: number;
    total_rows: number;
    invalid_rows: number;
    findings: number;
    findings_core: number;
    anomalies: number;
    incidents: number;
    by_severity: Record<Severity, number>;
    affected_hosts: string[];
    affected_users: string[];
    affected_ips: string[];
  };
  by_severity: { severity: Severity; count: number }[];
  by_category: { category: string; label: string; label_en: string; count: number } & Record<string, unknown>[];
  timeline: { ts: string; events: number; evidence: number; spike: boolean }[];
  top_ips: { value: string; events: number; evidence: number }[];
  top_users: { value: string; events: number; evidence: number }[];
  top_hosts: { value: string; events: number; evidence: number }[];
  heatmap: { weekday: number; label: string; hour: number; events: number; evidence: number }[];
  lateral: {
    nodes: { id: string; kind: string; in: number; out: number }[];
    edges: { source: string; target: string; count: number; rows: string[]; kinds: string[]; users: string[]; lateral: boolean }[];
  };
  incidents: { id: string; title: string; severity: Severity; score: number; start: string; end: string }[];
  date_range: { min?: string; max?: string };
  options: { hosts: string[]; users: string[] };
}

export type BlockOrigin = "determinista" | "ia" | "editado";
export type BlockKind = "hecho_observado" | "inferencia" | "hipotesis" | "recomendacion" | "info";

export interface ReportBlock {
  id: string;
  type: "paragraph" | "list" | "table" | "chart" | "finding";
  text?: string;
  items?: string[];
  columns?: string[];
  rows?: (string | number | null)[][];
  chart?: string;
  title?: string;
  origin: BlockOrigin;
  kind: BlockKind;
  row_refs?: string[];
  review?: string[];
  editable: boolean;
  finding_id?: string;
}

export interface ReportSection {
  id: string;
  number: string;
  title: string;
  blocks: ReportBlock[];
}

export type ReportKind = "ejecutivo" | "tecnico";

export interface Report {
  meta: {
    kind: ReportKind;
    title: string;
    client: string;
    analyst: string;
    lang: string;
    generated_at: string;
    version: number;
    classification: string;
    source_file: string;
    ai_used: boolean;
    ai_model?: string | null;
  };
  sections: ReportSection[];
  ai_review: { section: string; text: string; reason: string }[];
}

export interface Filters {
  severity: string[];
  category: string[];
  host: string[];
  user: string[];
  src_ip: string[];
  date_from: string;
  date_to: string;
  hour?: number | null;
  weekday?: number | null;
}

export type IntelVerdict = "malicioso" | "sospechoso" | "limpio" | "sin_datos" | "error";

export interface IntelProviderResult {
  verdict: IntelVerdict;
  score?: number;
  summary: string;
  link: string;
  country?: string | null;
  isp?: string | null;
  as_owner?: string | null;
  usage_type?: string | null;
  total_reports?: number;
  is_tor?: boolean;
  malicious?: number;
  suspicious?: number;
  cached?: boolean;
}

export interface IntelResultRow {
  ip: string;
  events: number;
  finding_ids: string[];
  incident_ids: string[];
  abuseipdb?: IntelProviderResult;
}

export interface IntelProviderState {
  label: string;
  state: "en_curso" | "completado" | "error" | "omitido" | "cancelado";
  key_source: "pantalla" | "entorno" | null;
  done: number;
  total: number;
  error: string | null;
  note: string | null;
  eta_s: number;
}

export interface IntelJob {
  status: "sin_ejecutar" | "en_curso" | "completado" | "cancelado";
  total_public?: number;
  selected?: number;
  max_ips?: number;
  skipped?: (IntelResultRow & { reason: string })[];
  not_queried?: string[];
  providers?: Record<string, IntelProviderState>;
  results?: IntelResultRow[];
  summary?: {
    queried: number;
    bad_abuseipdb: string[];
    suspicious: string[];
    providers_used: string[];
  } | null;
}

export interface IntelStatus {
  providers: Record<string, { label: string; configured: boolean; env_var: string; min_interval_s: number }>;
  default_max_ips: number;
}

export type Reports = Record<ReportKind, Report>;

export interface SessionState {
  upload: UploadResponse;
  quality: Quality | null;
  analysis: Analysis | null;
  reports: Reports | null;
  intel: unknown;
  expires_at: number;
  store: "disk" | "memory";
}
