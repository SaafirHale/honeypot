/**
 * stats.json schema v1, and a parser that treats the file as untrusted input.
 *
 * Every string in this document was typed by an attacker or derived from
 * attacker traffic. The parser checks shapes and types, drops what does not
 * fit, and caps lengths again, so a tampered file cannot break the page.
 * Rendering is plain React text; nothing here is ever injected as HTML.
 */

export type Count = { value: string; count: number };
export type Hour = { t: string; sessions: number; logins: number };
export type Day = { d: string; sessions: number };
export type Country = { code: string; name: string; sessions: number };
export type Asn = { asn: number; org: string; sessions: number };
export type Credential = { username: string; password: string; count: number };
export type RecentCommand = { t: string; cmd: string; country: string };
export type Payload = {
  sha256: string;
  count: number;
  via: string[];
  first_seen: string;
  last_seen: string;
};

export type Totals = {
  sessions: number;
  ssh_sessions: number;
  telnet_sessions: number;
  login_attempts: number;
  login_successes: number;
  unique_sources: number;
  countries: number;
  asns: number;
  commands: number;
  unique_commands: number;
  payloads: number;
  downloads_blocked: number;
};

export type Stats = {
  schema: 1;
  dataset: string;
  generated_at: string;
  window: {
    start: string;
    end: string;
    days: number;
    first_event: string | null;
    last_event: string | null;
  };
  totals: Totals;
  hourly: Hour[];
  daily: Day[];
  countries: Country[];
  asns: Asn[];
  usernames: Count[];
  passwords: Count[];
  credentials: Credential[];
  client_versions: Count[];
  commands: Count[];
  recent_commands: RecentCommand[];
  payloads: Payload[];
  attribution: { geoip?: string; geoip_builds?: Record<string, string> };
};

export class StatsError extends Error {}

type Obj = Record<string, unknown>;

const ISO = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const CC = /^[A-Z]{2}$/;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function str(v: unknown, max = 200): string {
  if (typeof v !== "string") return "";
  // Defence in depth: the collector already strips these.
  const clean = v.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, "");
  return clean.length > max ? clean.slice(0, max - 1) + "\u2026" : clean;
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0;
}

function iso(v: unknown): string | null {
  return typeof v === "string" && ISO.test(v) ? v : null;
}

function list<T>(v: unknown, item: (o: Obj) => T | null, max = 500): T[] {
  if (!Array.isArray(v)) return [];
  const out: T[] = [];
  for (const x of v.slice(0, max)) {
    if (!isObj(x)) continue;
    const parsed = item(x);
    if (parsed !== null) out.push(parsed);
  }
  return out;
}

const count = (o: Obj): Count | null => {
  const value = str(o.value, 200);
  return value ? { value, count: num(o.count) } : null;
};

export function parseStats(raw: unknown): Stats {
  if (!isObj(raw)) throw new StatsError("stats.json is not an object");
  if (raw.schema !== 1) throw new StatsError(`unsupported schema: ${String(raw.schema)}`);
  const w = isObj(raw.window) ? raw.window : {};
  const t = isObj(raw.totals) ? raw.totals : {};
  const end = iso(w.end);
  if (!end) throw new StatsError("window.end missing");

  const totals = {} as Totals;
  for (const k of [
    "sessions", "ssh_sessions", "telnet_sessions", "login_attempts", "login_successes",
    "unique_sources", "countries", "asns", "commands", "unique_commands", "payloads",
    "downloads_blocked",
  ] as const) {
    totals[k] = num(t[k]);
  }

  const attr = isObj(raw.attribution) ? raw.attribution : {};
  const builds = isObj(attr.geoip_builds) ? attr.geoip_builds : {};

  return {
    schema: 1,
    dataset: str(raw.dataset, 32) || "live",
    generated_at: iso(raw.generated_at) ?? end,
    window: {
      start: iso(w.start) ?? end,
      end,
      days: num(w.days),
      first_event: iso(w.first_event),
      last_event: iso(w.last_event),
    },
    totals,
    hourly: list(raw.hourly, (o) => {
      const at = iso(o.t);
      return at ? { t: at, sessions: num(o.sessions), logins: num(o.logins) } : null;
    }, 24 * 31),
    daily: list(raw.daily, (o) => {
      const d = iso(o.d);
      return d ? { d, sessions: num(o.sessions) } : null;
    }, 400),
    countries: list(raw.countries, (o) => {
      const code = str(o.code, 2);
      return CC.test(code) ? { code, name: str(o.name, 60) || code, sessions: num(o.sessions) } : null;
    }, 260),
    asns: list(raw.asns, (o) => {
      const asn = num(o.asn);
      return asn ? { asn, org: str(o.org, 80), sessions: num(o.sessions) } : null;
    }, 50),
    usernames: list(raw.usernames, count, 50),
    passwords: list(raw.passwords, count, 50),
    credentials: list(raw.credentials, (o) => {
      const username = str(o.username, 60);
      const password = str(o.password, 60);
      return username || password ? { username, password, count: num(o.count) } : null;
    }, 50),
    client_versions: list(raw.client_versions, count, 50),
    commands: list(raw.commands, count, 50),
    recent_commands: list(raw.recent_commands, (o) => {
      const at = iso(o.t);
      const cmd = str(o.cmd, 200);
      const country = str(o.country, 2);
      return at && cmd ? { t: at, cmd, country: CC.test(country) ? country : "ZZ" } : null;
    }, 100),
    payloads: list(raw.payloads, (o) => {
      const sha = typeof o.sha256 === "string" ? o.sha256 : "";
      if (!SHA256.test(sha)) return null;
      const via = Array.isArray(o.via)
        ? o.via.filter((v): v is string => v === "download" || v === "upload")
        : [];
      return {
        sha256: sha,
        count: num(o.count),
        via,
        first_seen: iso(o.first_seen) ?? "",
        last_seen: iso(o.last_seen) ?? "",
      };
    }, 50),
    attribution: {
      geoip: str(attr.geoip, 120) || undefined,
      geoip_builds: Object.fromEntries(
        Object.entries(builds)
          .map(([k, v]) => [str(k, 20), iso(v)] as const)
          .filter((kv): kv is readonly [string, string] => kv[1] !== null),
      ),
    },
  };
}

// ------------------------------------------------------------------ format --

const nf = new Intl.NumberFormat("en-US");
export const fmt = (n: number) => nf.format(n);

export function pct(part: number, whole: number): string {
  if (!whole) return "0%";
  const p = (part / whole) * 100;
  return p >= 10 || p === 0 ? `${Math.round(p)}%` : `${p.toFixed(1)}%`;
}

/** "2026-10-25T13:00:00Z" -> "25 Oct 13:00" (always UTC). */
export function utcShort(isoTs: string): string {
  const d = new Date(isoTs);
  if (Number.isNaN(d.getTime())) return "";
  const mon = d.toLocaleString("en-GB", { month: "short", timeZone: "UTC" });
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${d.getUTCDate()} ${mon} ${hh}:${mm}`;
}

export function utcDay(isoTs: string): string {
  const d = new Date(isoTs);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCDate()} ${d.toLocaleString("en-GB", { month: "short", timeZone: "UTC" })}`;
}

/** Five-step sequential bucket (0 = none) on a log scale, for the map fill. */
export function bucket(value: number, max: number, steps = 5): number {
  if (value <= 0 || max <= 0) return 0;
  if (max === 1) return steps;
  const b = Math.ceil((Math.log(value + 1) / Math.log(max + 1)) * steps);
  return Math.min(steps, Math.max(1, b));
}
