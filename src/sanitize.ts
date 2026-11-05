/* ================================================================ */
/* Pare-feu cognitif — moteur de masquage.                           */
/* Neutralise clés API, jetons, IP, ports, DNS, e-mails, journaux…   */
/* avant toute exposition. Rien ne quitte la machine en clair.       */
/* ================================================================ */

export type CatId =
  | "jwt" | "url" | "email" | "api" | "ipv6" | "ipv4" | "hash" | "mac" | "domain" | "port" | "path";

export interface Rule {
  id: CatId;
  label: string;
  sample: string;
  re: RegExp;
  priority: number;
  mask: (m: RegExpExecArray) => string;
}

const B = "\u2593"; // ▓

/* ------------------------------------------------------------------ */
/* Règles (ordre de priorité : les plus spécifiques d'abord)           */
/* ------------------------------------------------------------------ */

export const RULES: Rule[] = [
  {
    id: "jwt",
    label: "Jetons JWT",
    sample: "eyJhbGciOi…",
    priority: 1,
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g,
    mask: () => `eyJ${B}${B}${B}.${B}${B}.${B}${B}`,
  },
  {
    id: "url",
    label: "URL complètes",
    sample: "https://hote/chemin",
    priority: 2,
    re: /https?:\/\/[^\s"'<>]+/gi,
    mask: (m) => {
      const u = m[0];
      const proto = u.startsWith("https") ? "https" : "http";
      return `${proto}://${B}${B}${B}.${B}${B}/${B}${B}${B}`;
    },
  },
  {
    id: "email",
    label: "Adresses e-mail",
    sample: "nom@domaine.fr",
    priority: 3,
    re: /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g,
    mask: (m) => {
      const [local, ...rest] = m[0].split("@");
      const tld = rest.join("@").split(".").pop() ?? "fr";
      return `${local.slice(0, 1)}${B}${B}${B}@${B}${B}${B}.${tld}`;
    },
  },
  {
    id: "api",
    label: "Clés & secrets API",
    sample: "sk-… / X-Api-Key: …",
    priority: 4,
    re: /(?:\b(?:BSA|sk|pk|ghp|gho|xox[baprs]|AIza)[A-Za-z0-9._-]{10,}\b)|(?:(?:api[_-]?key|apikey|token|secret|authorization|bearer)[\s:=."'-]+[A-Za-z0-9._-]{14,})/gi,
    mask: (m) => {
      const s = m[0];
      return s.length > 18 ? `${s.slice(0, 4)}${B}${B}${B}${B}${B}${B}` : `${s.slice(0, 3)}${B}${B}${B}${B}`;
    },
  },
  {
    id: "ipv6",
    label: "Adresses IPv6",
    sample: "2001:db8::1",
    priority: 5,
    re: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g,
    mask: () => `${B}${B}${B}${B}:${B}:${B}::${B}`,
  },
  {
    id: "ipv4",
    label: "Adresses IPv4",
    sample: "203.0.113.42",
    priority: 6,
    re: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    mask: (m) => `${m[1]}.${B}.${B}.${B}`,
  },
  {
    id: "hash",
    label: "Hachages & empreintes",
    sample: "sha256:9f86d08…",
    priority: 7,
    re: /\b[0-9a-f]{32,64}\b/gi,
    mask: (m) => `${m[0].slice(0, 8)}${B}${B}${B}…`,
  },
  {
    id: "mac",
    label: "Adresses MAC",
    sample: "aa:bb:cc:dd:ee:ff",
    priority: 8,
    re: /\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/g,
    mask: () => `${B}${B}:${B}${B}:${B}${B}:${B}${B}:${B}${B}:${B}${B}`,
  },
  {
    id: "domain",
    label: "Noms DNS",
    sample: "serveur.exemple.fr",
    priority: 9,
    re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|fr|ma|top|xyz|io|dev|gov|info|tk|ml|click|online|site|live|shop)\b/gi,
    mask: (m) => {
      const parts = m[0].split(".");
      const tld = parts.pop();
      return `${parts.map(() => `${B}${B}${B}`).join(".")}.${tld}`;
    },
  },
  {
    id: "port",
    label: "Ports réseau",
    sample: ":443 / port 22",
    priority: 10,
    re: /(?<![:\/]):\d{2,5}(?=\s|$|\/tcp|\/udp|[,)\]])|(\bport\s+)\d{1,5}\b/gi,
    mask: (m) => (m[1] ? `${m[1]}${B}${B}${B}` : `:${B}${B}${B}`),
  },
  {
    id: "path",
    label: "Chemins système (logs)",
    sample: "/var/log/auth.log",
    priority: 11,
    re: /(?:\/(?:home|var|etc|usr|tmp|root|opt|srv)\/[^\s"'<>:]+)/g,
    mask: () => `/${B}${B}${B}/${B}${B}${B}`,
  },
];

/* ------------------------------------------------------------------ */
/* Segmentisation (un seul passage, priorités respectées)              */
/* ------------------------------------------------------------------ */

export interface Segment {
  text: string;
  cat?: CatId;
}

interface Match {
  start: number;
  end: number;
  cat: CatId;
  masked: string;
  priority: number;
}

export function sanitize(text: string, enabled: Set<CatId>): { segments: Segment[]; plain: string; counts: Record<string, number> } {
  const matches: Match[] = [];
  const counts: Record<string, number> = {};
  for (const rule of RULES) {
    if (!enabled.has(rule.id)) continue;
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length, cat: rule.id, masked: rule.mask(m), priority: rule.priority });
      counts[rule.id] = (counts[rule.id] ?? 0) + 1;
      if (m[0].length === 0) rule.re.lastIndex += 1;
    }
  }
  /* tri : position puis priorité ; rejet des chevauchements */
  matches.sort((a, b) => a.start - b.start || a.priority - b.priority);
  const kept: Match[] = [];
  let lastEnd = -1;
  for (const m of matches) {
    if (m.start >= lastEnd) {
      kept.push(m);
      lastEnd = m.end;
    }
  }
  const segments: Segment[] = [];
  let cursor = 0;
  for (const m of kept) {
    if (m.start > cursor) segments.push({ text: text.slice(cursor, m.start) });
    segments.push({ text: m.masked, cat: m.cat });
    cursor = m.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor) });
  return { segments, plain: segments.map((s) => s.text).join(""), counts };
}

/* Masquage rapide d'un IOC (flux, radar) */
export function maskIoc(s: string): string {
  const set = new Set<CatId>(["ipv4", "ipv6", "port", "domain", "url", "hash", "email"]);
  return sanitize(s, set).plain;
}

/* Score de fuite cognitive : nombre de marqueurs résiduels */
export function leakScore(text: string): number {
  const all = new Set<CatId>(RULES.map((r) => r.id));
  const { counts } = sanitize(text, all);
  return Object.values(counts).reduce((a, b) => a + b, 0);
}

/* ------------------------------------------------------------------ */
/* Échantillons d'injection                                            */
/* ------------------------------------------------------------------ */

export const SAMPLES: { id: string; label: string; text: string }[] = [
  {
    id: "nginx",
    label: "JOURNAL NGINX",
    text: `203.0.113.42 - admin@client-xyz.fr [11/Jun/2026:09:14:02 +0200] "GET /wp-login.php HTTP/1.1" 404 512 "-" "sqlmap/1.9"
upstream 10.24.1.7:8080 — requête relayée vers api.interne-paiement.fr:443
erreur auth : Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r
fichier lu : /var/log/nginx/access.log — empreinte 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`,
  },
  {
    id: "curl",
    label: "EN-TÊTES cURL",
    text: `> GET /v1/threats HTTP/2
> Host: api.fournisseur-securite.com
> X-Api-Key: raGrcnzRKEm0mAwsmWsyrUuq25hfv1ouZH1h1FVq
> Authorization: Bearer BSAq1DN5k0fnKRNudkcPittnCR0SuMV.
> User-Agent: curl/8.6.0
< HTTP/2 200 — depuis 51.15.22.90:443 (AS12876)
contact incident : soc@fournisseur-securite.com`,
  },
  {
    id: "dns",
    label: "ZONE DNS",
    text: `; transfert de zone refusé vers 198.51.100.23
mail.banque-client.ma.      IN  MX   10 mx1.banque-client.ma.
mx1.banque-client.ma.       IN  A    196.200.132.14
app.portail-assures.fr.     IN  CNAME front.portail-assures.fr.
ns1.portail-assures.fr.     IN  A    172.67.180.5
_sip._tcp.portail-assures.fr. IN SRV 10 60 5060 sip.portail-assures.fr.`,
  },
];
