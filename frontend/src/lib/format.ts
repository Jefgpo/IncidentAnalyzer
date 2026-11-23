import type { Severity } from "./types";

export const SEVERITY_ORDER: Severity[] = ["Crítico", "Alto", "Medio", "Bajo"];
export const SEVERITY_EN: Record<Severity, string> = { Crítico: "Critical", Alto: "High", Medio: "Medium", Bajo: "Low" };

/** Colores validados para fondo claro y oscuro (mismos que el PDF). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  Crítico: "#dc2626",
  Alto: "#ea580c",
  Medio: "#ca8a04",
  Bajo: "#0284c7",
};

/** Color de texto por criticidad con contraste AA sobre fondo claro y oscuro. */
export const SEVERITY_TEXT: Record<Severity, string> = {
  Crítico: "text-red-700 dark:text-red-400",
  Alto: "text-orange-700 dark:text-orange-400",
  Medio: "text-yellow-700 dark:text-yellow-400",
  Bajo: "text-sky-700 dark:text-sky-400",
};

/** Etiqueta visible de una criticidad según el idioma de la interfaz. */
export const sevLabel = (s: Severity, lang: "es" | "en") => (lang === "en" ? SEVERITY_EN[s] : s);

export const SEVERITY_BADGE: Record<Severity, string> = {
  Crítico: "bg-red-700 text-white",
  Alto: "bg-orange-700 text-white",
  Medio: "bg-yellow-500 text-slate-900",
  Bajo: "bg-sky-700 text-white",
};

/** Paleta categórica de referencia (validada CVD) en orden fijo; pasos distintos para modo oscuro. */
const CATEGORY_ORDER = ["bruteforce", "suspicious_logon", "privesc", "execution", "lateral", "anomaly"];
const CATEGORICAL_LIGHT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"];
const CATEGORICAL_DARK = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300"];
export const CATEGORY_COLOR: Record<string, string> = Object.fromEntries(CATEGORY_ORDER.map((c, i) => [c, CATEGORICAL_LIGHT[i]]));
export function categoryColor(cat: string, theme: "light" | "dark"): string {
  const i = CATEGORY_ORDER.indexOf(cat);
  return (theme === "dark" ? CATEGORICAL_DARK : CATEGORICAL_LIGHT)[i < 0 ? 0 : i];
}
/** Serie 1 / serie 2 para gráficos de dos series (eventos vs evidencia). */
export const SERIES = { light: ["#2a78d6", "#eb6834"], dark: ["#3987e5", "#d95926"] };

/** Formatea un ISO con offset conservando la hora local del cliente (la del propio timestamp). */
export function fmtTs(iso: string | null | undefined, withSeconds = true): string {
  if (!iso) return "—";
  const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return iso;
  const [, y, mo, d, h, mi, s] = m;
  return `${d}/${mo}/${y} ${h}:${mi}${withSeconds ? `:${s}` : ""}`;
}

export function fmtHour(iso: string): string {
  const m = iso.match(/^\d{4}-(\d{2})-(\d{2})T(\d{2})/);
  return m ? `${m[2]}/${m[1]} ${m[3]}h` : iso;
}

/** Defang de IoCs para evitar clics accidentales: hxxp, [.] */
export function defang(value: string, type: string): string {
  if (type === "url") return value.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  if (type === "domain" || (type === "ip" && !value.includes(":"))) return value.replace(/\./g, "[.]");
  return value;
}

export function cls(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}
