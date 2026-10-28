/* ================================================================ */
/* Couche « mode réel » — flux publics de renseignement sur les      */
/* menaces + vérifications techniques en direct. Usage défensif.     */
/* Sources : abuse.ch (ThreatFox, Feodo, URLhaus, MalwareBazaar),    */
/* Google DNS-over-HTTPS, ipwho.is, Brave Search API, Puter/OpenAI.  */
/* ================================================================ */

import { useEffect, useReducer } from "react";
import { API_NINJAS_KEY, BRAVE_API_KEY, type LiveSourceId } from "./data";

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

export interface LiveEvent {
  id: string;
  ts: number;
  source: LiveSourceId;
  ioc: string;
  iocType: "ip:port" | "domain" | "url" | "sha256" | "cve";
  malware: string;
  threat: string;
  tags: string[];
  country?: string;
  severity: 0 | 1 | 2;
}

export interface SourceStatus {
  status: "loading" | "ok" | "error";
  count: number;
  latency: number | null;
  updated: number | null;
  error?: string;
}

export interface Exposure {
  ip: string;
  city?: string;
  country?: string;
  flag?: string;
  org?: string;
  asn?: number | string;
  listed: boolean;
  ts: number;
}

export interface FeedState {
  events: LiveEvent[];
  sources: Record<LiveSourceId, SourceStatus>;
  exposure: Exposure | null;
  exposureError: string | null;
  loading: boolean;
  lastRefresh: number;
  paused: boolean;
}

const initialSources = (): Record<LiveSourceId, SourceStatus> => ({
  THREATFOX: { status: "loading", count: 0, latency: null, updated: null },
  FEODO: { status: "loading", count: 0, latency: null, updated: null },
  URLHAUS: { status: "loading", count: 0, latency: null, updated: null },
  MALWAREBAZAAR: { status: "loading", count: 0, latency: null, updated: null },
  CVE: { status: "loading", count: 0, latency: null, updated: null },
});

let state: FeedState = {
  events: [],
  sources: initialSources(),
  exposure: null,
  exposureError: null,
  loading: true,
  lastRefresh: 0,
  paused: false,
};
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());
const setState = (p: Partial<FeedState>) => {
  state = { ...state, ...p };
  emit();
};

export const getFeed = () => state;
export const setPaused = (v: boolean) => setState({ paused: v });

/* Pare-feu cognitif — mode masquage global (IP, ports, DNS, hachages) */
let maskMode = false;
export const getMaskMode = () => maskMode;
export function setMaskMode(v: boolean) {
  maskMode = v;
  emit();
}

export function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function timeAgo(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `il y a ${s} s`;
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
  return `il y a ${Math.floor(s / 86400)} j`;
}

/* ------------------------------------------------------------------ */
/* Fetch avec délai d'attente                                          */
/* ------------------------------------------------------------------ */

async function rawFetch(url: string, init: RequestInit = {}, ms = 14000): Promise<Response> {
  const c = new AbortController();
  const t = window.setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: c.signal });
  } finally {
    window.clearTimeout(t);
  }
}

async function jfetch(url: string, init: RequestInit = {}, ms = 14000): Promise<any> {
  const r = await rawFetch(url, init, ms);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/* ------------------------------------------------------------------ */
/* Collecteurs de flux                                                 */
/* ------------------------------------------------------------------ */

async function fetchThreatFox(): Promise<LiveEvent[]> {
  const j = await jfetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 1 }),
  });
  const rows = Array.isArray(j?.data) ? j.data : [];
  return rows.slice(0, 120).map((r: any, i: number): LiveEvent => ({
    id: `TF-${r.id ?? i}`,
    ts: Date.parse(r.first_seen) || Date.now(),
    source: "THREATFOX",
    ioc: String(r.ioc),
    iocType: r.type === "sha256" ? "sha256" : r.type === "url" ? "url" : r.type === "domain" ? "domain" : "ip:port",
    malware: r.malware_printable || r.malware || "inconnu",
    threat: r.threat_type || "malware",
    tags: Array.isArray(r.tags) ? r.tags.slice(0, 3) : [],
    severity: r.threat_type === "botnet_cc" ? 2 : Number(r.confidence_level) >= 70 ? 2 : 1,
  }));
}

async function fetchFeodo(): Promise<LiveEvent[]> {
  const j = await jfetch("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json");
  const rules = Array.isArray(j?.rules) ? j.rules : [];
  return rules.slice(0, 120).map((r: any, i: number): LiveEvent => ({
    id: `FD-${r.ip_address}-${r.port}`,
    ts: Date.parse(r.first_seen) || Date.now(),
    source: "FEODO",
    ioc: `${r.ip_address}:${r.port}`,
    iocType: "ip:port",
    malware: r.malware || "botnet",
    threat: "botnet_cc",
    tags: [r.status === "online" ? "en ligne" : "hors ligne", r.as_name].filter(Boolean).slice(0, 3),
    country: r.country ?? undefined,
    severity: 2,
  }));
}

async function fetchUrlhaus(): Promise<LiveEvent[]> {
  const j = await jfetch("https://urlhaus-api.abuse.ch/v1/urls/recent/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "limit=80",
  });
  const urls = Array.isArray(j?.urls) ? j.urls : [];
  return urls.map((r: any, i: number): LiveEvent => ({
    id: `UH-${r.id ?? i}`,
    ts: Date.parse(r.date_added) || Date.now(),
    source: "URLHAUS",
    ioc: String(r.url),
    iocType: "url",
    malware: r.threat || "malware",
    threat: "payload_delivery",
    tags: Array.isArray(r.tags) ? r.tags.slice(0, 3) : [],
    severity: /c2|botnet/i.test(String(r.threat ?? "")) ? 2 : 1,
  }));
}

async function fetchCve(): Promise<LiveEvent[]> {
  /* CIRCL d'abord, NVD en repli */
  try {
    const j = await jfetch("https://cve.circl.lu/api/last/30", {}, 12000);
    const items = Array.isArray(j) ? j : [];
    if (items.length) {
      return items.map((c: any, i: number): LiveEvent => {
        const id = String(c?.id ?? c?.cve?.id ?? `CVE-${i}`);
        const summary = String(c?.summary ?? c?.cve?.descriptions?.find((d: any) => d.lang === "en")?.value ?? "");
        return {
          id,
          ts: Date.parse(c?.Published ?? c?.published ?? c?.cve?.published ?? "") || Date.now(),
          source: "CVE",
          ioc: id,
          iocType: "cve",
          malware: "CVE",
          threat: summary.slice(0, 90) || "vulnérabilité publiée",
          tags: [],
          severity: /remote|arbitrary|exécution|execution/i.test(summary) ? 2 : 1,
        };
      });
    }
  } catch {
    /* bascule NVD */
  }
  const j = await jfetch(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=30",
    {},
    14000
  );
  const vulns = Array.isArray(j?.vulnerabilities) ? j.vulnerabilities : [];
  return vulns.map((v: any, i: number): LiveEvent => {
    const c = v?.cve ?? {};
    const id = String(c.id ?? `CVE-${i}`);
    const desc = String(c.descriptions?.find((d: any) => d.lang === "en")?.value ?? "");
    return {
      id,
      ts: Date.parse(c.published ?? "") || Date.now(),
      source: "CVE",
      ioc: id,
      iocType: "cve",
      malware: "CVE",
      threat: desc.slice(0, 90) || "vulnérabilité publiée",
      tags: [],
      severity: /remote|arbitrary|exécution|execution/i.test(desc) ? 2 : 1,
    };
  });
}

/* Sonde d'exposition : la vraie adresse publique du visiteur */
async function updateExposure(): Promise<void> {
  try {
    const j = await jfetch("https://api.ipify.org?format=json", {}, 10000);
    const ip = String(j?.ip ?? "");
    if (!ip) throw new Error("pas d'IP");
    let geo: any = null;
    try {
      geo = await geoIp(ip);
    } catch {
      geo = null;
    }
    const listed = feodoMatch(ip) !== null;
    setState({
      exposure: {
        ip,
        city: geo?.city,
        country: geo?.country,
        flag: geo?.flag?.emoji,
        org: geo?.connection?.org,
        asn: geo?.connection?.asn,
        listed,
        ts: Date.now(),
      },
      exposureError: null,
    });
  } catch (e: any) {
    setState({ exposureError: String(e?.message ?? e) });
  }
}

async function fetchMalwareBazaar(): Promise<LiveEvent[]> {
  const j = await jfetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_recent", selector: "time", limit: "60" }),
  });
  const rows = Array.isArray(j?.data) ? j.data : [];
  return rows.map((r: any, i: number): LiveEvent => ({
    id: `MB-${String(r.sha256_hash ?? i).slice(0, 12)}`,
    ts: Date.parse(r.first_seen) || Date.now(),
    source: "MALWAREBAZAAR",
    ioc: String(r.sha256_hash),
    iocType: "sha256",
    malware: r.signature || r.file_type || "inconnu",
    threat: "payload",
    tags: Array.isArray(r.tags) ? r.tags.slice(0, 3) : [],
    severity: 1,
  }));
}

/* ------------------------------------------------------------------ */
/* Rafraîchissement du store                                           */
/* ------------------------------------------------------------------ */

let feedPromise: Promise<void> | null = null;

export function ensureFeed(): Promise<void> {
  if (!feedPromise) feedPromise = refreshFeed();
  return feedPromise;
}

export async function refreshFeed(): Promise<void> {
  setState({ loading: true });
  const fetchers: [LiveSourceId, () => Promise<LiveEvent[]>][] = [
    ["THREATFOX", fetchThreatFox],
    ["FEODO", fetchFeodo],
    ["URLHAUS", fetchUrlhaus],
    ["MALWAREBAZAAR", fetchMalwareBazaar],
    ["CVE", fetchCve],
  ];
  const results = await Promise.all(
    fetchers.map(async ([id, fn]) => {
      const t0 = performance.now();
      try {
        const ev = await fn();
        return { id, ok: true as const, ev, latency: Math.round(performance.now() - t0), err: undefined as string | undefined };
      } catch (e: any) {
        return { id, ok: false as const, ev: [] as LiveEvent[], latency: Math.round(performance.now() - t0), err: String(e?.message ?? e) };
      }
    })
  );
  const sources = { ...state.sources };
  const merged = new Map<string, LiveEvent>();
  for (const prev of state.events) merged.set(prev.ioc, prev);
  const now = Date.now();
  for (const r of results) {
    sources[r.id] = r.ok
      ? { status: "ok", count: r.ev.length, latency: r.latency, updated: now }
      : { ...sources[r.id], status: "error", latency: r.latency, updated: sources[r.id].updated, error: r.err };
    for (const ev of r.ev) merged.set(ev.ioc, ev);
  }
  const events = [...merged.values()].sort((a, b) => b.ts - a.ts).slice(0, 300);
  setState({ events, sources, loading: false, lastRefresh: now });
  updateExposure();
}

/* ------------------------------------------------------------------ */
/* Hook React                                                          */
/* ------------------------------------------------------------------ */

export function useFeed(): FeedState {
  const [, force] = useReducer((x: number) => x + 1, 0);
  useEffect(() => {
    listeners.add(force);
    return () => {
      listeners.delete(force);
    };
  }, []);
  useEffect(() => {
    if (state.events.length === 0) refreshFeed();
    const t = window.setInterval(() => {
      if (!state.paused) refreshFeed();
    }, 90_000);
    const onBurst = () => refreshFeed();
    window.addEventListener("aegis-refresh", onBurst);
    return () => {
      window.clearInterval(t);
      window.removeEventListener("aegis-refresh", onBurst);
    };
  }, []);
  return state;
}

/* ------------------------------------------------------------------ */
/* Vérifications ponctuelles (Scanner + Attribution)                   */
/* ------------------------------------------------------------------ */

export async function threatFoxSearch(term: string): Promise<any | null> {
  const j = await jfetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "search_ioc", search_term: term }),
  }, 12000);
  if (j?.query_status === "ok" && Array.isArray(j.data) && j.data.length) return j.data[0];
  return null;
}

export function feodoMatch(ip: string): LiveEvent | null {
  return state.events.find((e) => e.source === "FEODO" && e.ioc.startsWith(ip + ":")) ?? null;
}

export async function resolveDns(name: string, type: "A" | "MX" | "PTR" = "A"): Promise<string[]> {
  const j = await jfetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {}, 10000);
  if (j?.Status !== 0 || !Array.isArray(j.Answer)) return [];
  const wanted = type === "A" ? 1 : type === "MX" ? 15 : 12;
  return j.Answer.filter((a: any) => a.type === wanted).map((a: any) => String(a.data));
}

export async function geoIp(ip: string): Promise<any | null> {
  const j = await jfetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {}, 10000);
  return j?.success ? j : null;
}

export async function urlhausCheck(url: string): Promise<any | null> {
  const j = await jfetch("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `url=${encodeURIComponent(url)}`,
  }, 12000);
  if (j?.query_status === "ok" && j.url) return j.url;
  return null;
}

export async function braveSearch(
  query: string,
  count = 4
): Promise<{ title: string; url: string; desc: string }[]> {
  const r = await rawFetch(
    `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=${count}&safesearch=strict`,
    { headers: { Accept: "application/json", "X-Subscription-Token": BRAVE_API_KEY } },
    12000
  );
  if (!r.ok) throw new Error(`Brave HTTP ${r.status}`);
  const j = await r.json();
  return (j?.web?.results ?? []).slice(0, count).map((x: any) => ({
    title: String(x.title ?? ""),
    url: String(x.url ?? ""),
    desc: String(x.description ?? ""),
  }));
}

/* ------------------------------------------------------------------ */
/* SEO autonome — API Ninjas (zéro Google)                             */
/* ------------------------------------------------------------------ */

export async function ninjasDns(domain: string): Promise<any[]> {
  const r = await rawFetch(`https://api.api-ninjas.com/v1/dnslookup?domain=${encodeURIComponent(domain)}`, {
    headers: { "X-Api-Key": API_NINJAS_KEY },
  }, 12000);
  if (!r.ok) throw new Error(`API Ninjas HTTP ${r.status}`);
  const j = await r.json();
  return Array.isArray(j) ? j : [];
}

export async function ninjasWhois(domain: string): Promise<any> {
  const r = await rawFetch(`https://api.api-ninjas.com/v1/whois?domain=${encodeURIComponent(domain)}`, {
    headers: { "X-Api-Key": API_NINJAS_KEY },
  }, 12000);
  if (!r.ok) throw new Error(`API Ninjas HTTP ${r.status}`);
  return r.json();
}
