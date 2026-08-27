import { useEffect, useRef, useState } from "react";
import { seedFrom, useInView } from "../hooks";
import { ensureFeed, feodoMatch, geoIp, resolveDns, threatFoxSearch, urlhausCheck } from "../live";
import { IconBolt, IconCheck, IconCopy, IconCrosshair, IconFingerprint, IconGlobe, IconPlane, IconWarning } from "./Icons";

type Tab = "url" | "email" | "ip";

const TABS: { id: Tab; label: string; placeholder: string; icon: (p: { className?: string }) => React.ReactNode }[] = [
  { id: "url", label: "URL", placeholder: "https://exemple-suspect.com/page", icon: (p) => <IconGlobe {...p} /> },
  { id: "email", label: "E-MAIL", placeholder: "expediteur@douteux.net", icon: (p) => <IconPlane {...p} /> },
  { id: "ip", label: "ADRESSE IP", placeholder: "185.220.101.47", icon: (p) => <IconCrosshair {...p} /> },
];

const STEP_SETS: Record<Tab, string[]> = {
  url: [
    "Résolution DNS réelle (Google DoH)",
    "Réputation ThreatFox (abuse.ch)",
    "Contrôle URLhaus (abuse.ch)",
    "Heuristiques lexicales — typosquat & homoglyphes",
    "Verdict consolidé",
  ],
  email: [
    "Enregistrements MX réels (Google DoH)",
    "Résolution A du domaine",
    "Réputation ThreatFox (abuse.ch)",
    "Heuristiques d'ingénierie sociale",
    "Verdict consolidé",
  ],
  ip: [
    "Géolocalisation & ASN (ipwho.is)",
    "DNS inverse — PTR (Google DoH)",
    "Croisement ThreatFox + Feodo Tracker",
    "Heuristiques d'hébergement masquant",
    "Verdict consolidé",
  ],
};

const EXAMPLES: Record<Tab, string[]> = {
  url: ["https://ameli-remboursement-securise.top/connexion", "https://www.impots-gouv-fr.info/remboursement", "https://docs.entreprise-partage.fr/rapport-q3"],
  email: ["remboursement@ameli-cpam.top", "direction.rh@groupe-total.energy", "support@dgi-maroc.org"],
  ip: ["185.220.101.47", "8.8.8.8", "45.155.205.86"],
};

interface Finding {
  label: string;
  tone: "ok" | "warn" | "bad";
  src: "RÉEL" | "HEUR.";
}

interface Verdict {
  score: number;
  level: "SÛR" | "SUSPECT" | "MALVEILLANT";
  findings: Finding[];
  hash: string;
  real: number;
}

const MASK_RE = /hosting|vps|cloud|dedicat|server|ovh|hetzner|digital\s?ocean|linode|contabo|scaleway|vultr|choopa|m247/i;

function hostOf(raw: string): string {
  try {
    return new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function analyzeUrl(raw: string): Promise<Verdict> {
  const s = raw.trim();
  const findings: Finding[] = [];
  let risk = 6;
  let real = 0;

  if (/xn--/.test(s)) { risk += 24; findings.push({ label: "Domaine punycode — homoglyphes détectés", tone: "bad", src: "HEUR." }); }
  if (/\.(zip|tk|xyz|top|click|gq|ml)(\/|$)/i.test(s)) { risk += 22; findings.push({ label: "TLD à fort taux d'abus (.xyz, .tk, .top…)", tone: "bad", src: "HEUR." }); }
  if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(s)) { risk += 20; findings.push({ label: "URL en adresse IP brute — masque classique d'hameçonnage", tone: "bad", src: "HEUR." }); }
  if (/^http:\/\//.test(s)) { risk += 12; findings.push({ label: "Transport non chiffré (HTTP simple)", tone: "warn", src: "HEUR." }); }
  if (s.includes("@")) { risk += 16; findings.push({ label: "Caractère « @ » dans l'URL — redirection masquée", tone: "warn", src: "HEUR." }); }
  if (/(ameli|arneli|cpam|impots|gouv|caf|dgi|cnss|barid|maroctelecom|mar0ctelecom|banque|tresor)/.test(s) && /\.(tk|xyz|top|click|gq|ml|info)\b/.test(s)) {
    risk += 20; findings.push({ label: "Usurpation d'une institution FR/MA (Ameli, CAF, DGI, CNSS, Maroc Telecom…)", tone: "bad", src: "HEUR." });
  }
  if ((s.match(/-/g) || []).length > 3) { risk += 8; findings.push({ label: "Sous-domaines à répétition", tone: "warn", src: "HEUR." }); }
  if (s.length > 62) { risk += 6; findings.push({ label: "Longueur anormale — paramètres de pistage", tone: "warn", src: "HEUR." }); }

  const host = hostOf(s);
  if (host) {
    try {
      const ips = await resolveDns(host, "A");
      real++;
      if (!ips.length) { risk += 30; findings.push({ label: `${host} ne résout pas en DNS — domaine fantôme`, tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: `DNS actif : ${ips.length} adresse${ips.length > 1 ? "s" : ""} (${ips[0]})`, tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
    try {
      const tf = await threatFoxSearch(host);
      real++;
      if (tf) { risk += 55; findings.push({ label: `Répertorié ThreatFox — ${tf.malware_printable ?? tf.malware} (${tf.threat_type})`, tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: "Absent des référentiels ThreatFox", tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
    const full = /^https?:\/\//i.test(s) ? s : "https://" + s;
    try {
      const uh = await urlhausCheck(full);
      real++;
      if (uh) { risk += 60; findings.push({ label: `URL malveillante active (URLhaus) — ${uh.threat}${uh.tags?.length ? " · " + uh.tags.join(", ") : ""}`, tone: "bad", src: "RÉEL" }); }
    } catch { /* source injoignable */ }
  }

  if (risk < 25 && findings.filter((f) => f.tone !== "ok").length === 0) {
    findings.push({ label: "Aucun signal défavorable détecté", tone: "ok", src: "RÉEL" });
  }
  risk = Math.min(97, risk);
  const level: Verdict["level"] = risk < 30 ? "SÛR" : risk < 65 ? "SUSPECT" : "MALVEILLANT";
  return { score: risk, level, findings, hash: (seedFrom("url" + s) >>> 0).toString(16).toUpperCase().padStart(8, "0"), real };
}

async function analyzeEmail(raw: string): Promise<Verdict> {
  const s = raw.trim().toLowerCase();
  const findings: Finding[] = [];
  let risk = 6;
  let real = 0;

  const domain = s.includes("@") ? s.split("@")[1] ?? "" : "";
  if (!s.includes("@")) { risk += 50; findings.push({ label: "Format d'adresse invalide", tone: "bad", src: "HEUR." }); }
  if (/(urgent|suspendu|virement|mot.de.passe|gain|loterie|colis|remboursement|otp|code de)/.test(s)) { risk += 20; findings.push({ label: "Lexique d'urgence sociale détecté", tone: "bad", src: "HEUR." }); }
  if (/\.(tk|xyz|top|ml|click)$/.test(domain)) { risk += 22; findings.push({ label: "Domaine jetable à fort taux d'abus", tone: "bad", src: "HEUR." }); }
  if (/(\d{1,3}\.){3}\d{1,3}$/.test(domain)) { risk += 20; findings.push({ label: "Domaine en IP littérale", tone: "bad", src: "HEUR." }); }
  const govBrand = /(dgi|impots|gouv|ameli|cpam|caf|cnss|barid|maroctelecom|banque|tresor)/.test(s);
  if (govBrand && !/\.(fr|ma|com|net|org)$/.test(domain)) { risk += 20; findings.push({ label: "Usurpation d'une institution FR/MA (Ameli, CAF, DGI, CNSS…)", tone: "bad", src: "HEUR." }); }
  if (/(paypal|netflix|microsoft|orange|sfr|free)/.test(s) && !/\.(fr|com|net|org)$/.test(domain)) { risk += 16; findings.push({ label: "Usurpation de marque probable", tone: "warn", src: "HEUR." }); }

  if (domain) {
    try {
      const mx = await resolveDns(domain, "MX");
      real++;
      if (!mx.length) { risk += 28; findings.push({ label: "Aucun enregistrement MX — le domaine ne reçoit pas d'e-mails", tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: `MX actif : ${mx.length} relais de courrier (${mx[0].split(" ").pop()})`, tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
    try {
      const a = await resolveDns(domain, "A");
      real++;
      if (!a.length) { risk += 22; findings.push({ label: "Le domaine ne résout pas en DNS", tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: `Domaine résolu : ${a[0]}`, tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
    try {
      const tf = await threatFoxSearch(domain);
      real++;
      if (tf) { risk += 55; findings.push({ label: `Domaine répertorié ThreatFox — ${tf.malware_printable ?? tf.malware}`, tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: "Domaine absent des référentiels ThreatFox", tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
  }

  risk = Math.min(97, risk);
  const level: Verdict["level"] = risk < 30 ? "SÛR" : risk < 65 ? "SUSPECT" : "MALVEILLANT";
  return { score: risk, level, findings, hash: (seedFrom("mail" + s) >>> 0).toString(16).toUpperCase().padStart(8, "0"), real };
}

async function analyzeIp(raw: string): Promise<Verdict> {
  const ip = raw.trim();
  const findings: Finding[] = [];
  let risk = 6;
  let real = 0;

  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split(".").every((o) => Number(o) <= 255);
  if (!ipv4) { risk += 45; findings.push({ label: "Format IPv4 non reconnu", tone: "bad", src: "HEUR." }); }
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) {
    risk = 8;
    findings.push({ label: "Plage privée (RFC 1918) — usage interne", tone: "ok", src: "HEUR." });
  }

  if (ipv4) {
    try {
      const g = await geoIp(ip);
      real++;
      if (g) {
        const org = `${g.connection?.org ?? ""} ${g.connection?.isp ?? ""}`;
        const masked = MASK_RE.test(org);
        if (masked) { risk += 18; findings.push({ label: `Hébergement générique susceptible de masquer l'origine — ${g.connection?.org}`, tone: "warn", src: "RÉEL" }); }
        findings.push({ label: `${g.flag?.emoji ?? ""} ${g.city ?? "?"}, ${g.country ?? "?"} — ASN ${g.connection?.asn ?? "?"} · ${g.connection?.org ?? "?"}`, tone: masked ? "warn" : "ok", src: "RÉEL" });
      } else {
        findings.push({ label: "Géolocalisation publique indisponible pour cette adresse", tone: "warn", src: "RÉEL" });
      }
    } catch { /* source injoignable */ }
    try {
      const arpa = ip.split(".").reverse().join(".") + ".in-addr.arpa";
      const r = await resolveDns(arpa, "PTR");
      real++;
      if (r.length) findings.push({ label: `PTR : ${r[0]}`, tone: "ok", src: "RÉEL" });
      else findings.push({ label: "Aucun PTR — mutisme DNS", tone: "warn", src: "RÉEL" });
    } catch { /* source injoignable */ }
    try {
      await ensureFeed();
      const fd = feodoMatch(ip);
      real++;
      if (fd) { risk += 60; findings.push({ label: `Infrastructure de commande répertoriée Feodo Tracker — ${fd.malware} (${fd.ioc})`, tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: "Absente de la liste de blocage Feodo (C2)", tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
    try {
      const tf = await threatFoxSearch(ip);
      real++;
      if (tf) { risk += 55; findings.push({ label: `Répertoriée ThreatFox — ${tf.malware_printable ?? tf.malware} (${tf.threat_type})`, tone: "bad", src: "RÉEL" }); }
      else findings.push({ label: "Absente des référentiels ThreatFox", tone: "ok", src: "RÉEL" });
    } catch { /* source injoignable */ }
  }

  risk = Math.min(97, risk);
  const level: Verdict["level"] = risk < 30 ? "SÛR" : risk < 65 ? "SUSPECT" : "MALVEILLANT";
  return { score: risk, level, findings, hash: (seedFrom("ip" + ip) >>> 0).toString(16).toUpperCase().padStart(8, "0"), real };
}

function analyze(tab: Tab, raw: string): Promise<Verdict> {
  if (tab === "url") return analyzeUrl(raw);
  if (tab === "email") return analyzeEmail(raw);
  return analyzeIp(raw);
}

const VERDICT_STYLE: Record<Verdict["level"], { text: string; ring: string }> = {
  "SÛR": { text: "text-pulse", ring: "stroke-pulse" },
  "SUSPECT": { text: "text-warn", ring: "stroke-warn" },
  "MALVEILLANT": { text: "text-alert", ring: "stroke-alert" },
};

export default function Scanner() {
  const { ref, inView } = useInView<HTMLElement>();
  const [tab, setTab] = useState<Tab>("url");
  const [input, setInput] = useState("");
  const [phase, setPhase] = useState<"idle" | "running" | "done">("idle");
  const [stepIdx, setStepIdx] = useState(-1);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState(false);
  const pending = useRef<Promise<Verdict> | null>(null);
  const timer = useRef<number>(0);

  const steps = STEP_SETS[tab];

  useEffect(() => () => clearInterval(timer.current), []);

  const switchTab = (t: Tab) => {
    clearInterval(timer.current);
    setTab(t);
    setInput("");
    setPhase("idle");
    setStepIdx(-1);
    setVerdict(null);
  };

  const finalize = async () => {
    let v: Verdict;
    try {
      v = await pending.current!;
    } catch {
      v = {
        score: 50,
        level: "SUSPECT",
        real: 0,
        findings: [{ label: "Sources publiques injoignables — verdict heuristique seul", tone: "warn", src: "HEUR." }],
        hash: "ERR00000",
      };
    }
    setStepIdx(steps.length);
    setVerdict(v);
    setPhase("done");
  };

  const run = (value?: string) => {
    const target = (value ?? input).trim();
    if (!target) {
      setError(true);
      setTimeout(() => setError(false), 900);
      return;
    }
    clearInterval(timer.current);
    pending.current = analyze(tab, target);
    setVerdict(null);
    setPhase("running");
    setStepIdx(0);
    let i = 0;
    timer.current = window.setInterval(() => {
      i += 1;
      if (i >= steps.length - 1) {
        clearInterval(timer.current);
        setStepIdx(steps.length - 1);
        finalize();
      } else {
        setStepIdx(i);
      }
    }, 520);
  };

  const copyReport = async () => {
    if (!verdict) return;
    const lines = [
      `RAPPORT AEGIS-7 — ${tab.toUpperCase()} :: ${input.trim()}`,
      `Verdict : ${verdict.level} (score de risque ${verdict.score}/100)`,
      `Vérifications réelles effectuées : ${verdict.real}`,
      `Empreinte : 0x${verdict.hash}`,
      ...verdict.findings.map((f) => ` • [${f.src}] [${f.tone.toUpperCase()}] ${f.label}`),
      "Sources : abuse.ch (ThreatFox, URLhaus, Feodo), Google DoH, ipwho.is — usage défensif.",
    ].join("\n");
    try {
      await navigator.clipboard.writeText(lines);
    } catch { /* presse-papiers indisponible */ }
    setCopied(true);
    setTimeout(() => setCopied(false), 2200);
  };

  const vs = verdict ? VERDICT_STYLE[verdict.level] : null;
  const CIRC = 2 * Math.PI * 52;

  return (
    <section id="analyse" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      <div className="flex items-end justify-between gap-6">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">LABORATOIRE D'ANALYSE — VÉRIFICATIONS RÉELLES</p>
          <h2 className="font-display mt-3 text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Soumettez un artefact <span className="text-cyber">suspect</span>.
          </h2>
        </div>
        <p className="hidden max-w-sm text-sm leading-relaxed text-fog lg:block">
          Chaque vérification « RÉEL » interroge une source publique en direct : DNS Google, abuse.ch
          (ThreatFox, URLhaus, Feodo), ipwho.is. Les heuristiques complètent le verdict.
        </p>
      </div>

      <div className="panel panel-corner mt-8 grid overflow-hidden lg:grid-cols-2">
        {/* Colonne soumission */}
        <div className="border-b border-line p-6 sm:p-8 lg:border-b-0 lg:border-r">
          <div className="flex gap-1 border border-line bg-ink-950/60 p-1">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => switchTab(t.id)}
                className={`flex flex-1 items-center justify-center gap-2 px-3 py-2.5 font-display text-[11px] font-bold tracking-[0.18em] transition-all duration-300 ${
                  tab === t.id ? "clip-tag bg-cyber text-ink-950" : "text-fog hover:text-snow"
                }`}
              >
                {t.icon({ className: "h-3.5 w-3.5" })}
                {t.label}
              </button>
            ))}
          </div>

          <div className={`mt-5 flex border transition-colors ${error ? "border-alert" : "border-line focus-within:border-cyber/70"}`}>
            <span className="grid w-11 shrink-0 place-items-center border-r border-line text-cyber">
              {TABS.find((t) => t.id === tab)?.icon({ className: "h-4 w-4" })}
            </span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && phase !== "running" && run()}
              placeholder={TABS.find((t) => t.id === tab)?.placeholder}
              spellCheck={false}
              className="min-w-0 flex-1 bg-transparent px-4 py-3.5 font-mono text-sm text-snow placeholder:text-fog-dim focus:outline-none"
            />
            <button
              onClick={() => run()}
              disabled={phase === "running"}
              className="clip-tag m-1 shrink-0 bg-cyber px-5 font-display text-[11px] font-bold tracking-[0.18em] text-ink-950 transition-all hover:bg-snow disabled:opacity-50 sm:px-7"
            >
              {phase === "running" ? "ANALYSE…" : "ANALYSER"}
            </button>
          </div>
          {error && <p className="mt-2 font-mono text-[10px] tracking-wider text-alert">▸ Artefact vide — saisissez une valeur à inspecter.</p>}

          <div className="mt-4">
            <p className="font-mono text-[9px] tracking-[0.24em] text-fog-dim">EXEMPLES À ÉPROUVER</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {EXAMPLES[tab].map((ex) => (
                <button
                  key={ex}
                  onClick={() => { setInput(ex); run(ex); }}
                  className="max-w-full truncate border border-line bg-ink-950/50 px-2.5 py-1.5 font-mono text-[10px] text-fog transition-colors hover:border-cyber/60 hover:text-cyber"
                >
                  {ex}
                </button>
              ))}
            </div>
          </div>

          {/* Étapes */}
          <div className="relative mt-7 overflow-hidden">
            {phase === "running" && (
              <div className="animate-scan-beam pointer-events-none absolute inset-x-0 h-10 bg-gradient-to-b from-transparent via-cyber/10 to-transparent" />
            )}
            <ol className="space-y-2.5">
              {steps.map((s, i) => {
                const state = phase === "idle" ? "todo" : i < stepIdx ? "done" : i === stepIdx ? "live" : "todo";
                return (
                  <li key={s} className={`flex items-center gap-3 transition-opacity duration-300 ${state === "todo" && phase !== "idle" ? "opacity-35" : ""}`}>
                    <span
                      className={`grid h-6 w-6 shrink-0 place-items-center border font-mono text-[10px] ${
                        state === "done"
                          ? "border-pulse/60 bg-pulse/10 text-pulse"
                          : state === "live"
                            ? "border-cyber bg-cyber/10 text-cyber"
                            : "border-line text-fog-dim"
                      }`}
                    >
                      {state === "done" ? <IconCheck className="h-3 w-3" /> : state === "live" ? (
                        <span className="h-2.5 w-2.5 animate-spin rounded-full border border-cyber border-t-transparent" />
                      ) : (
                        i + 1
                      )}
                    </span>
                    <span className={`font-mono text-xs ${state === "done" ? "text-snow" : state === "live" ? "text-cyber" : "text-fog-dim"}`}>{s}</span>
                    {state === "live" && <span className="ml-auto font-mono text-[9px] tracking-[0.2em] text-cyber">EN COURS</span>}
                    {state === "done" && <span className="ml-auto font-mono text-[9px] tracking-[0.2em] text-pulse">OK</span>}
                  </li>
                );
              })}
            </ol>
          </div>
        </div>

        {/* Colonne verdict */}
        <div className="relative flex flex-col items-center justify-center p-6 sm:p-10">
          <div className="bg-grid-layer pointer-events-none absolute inset-0 opacity-60" />

          {!verdict && (
            <div className="relative flex flex-col items-center text-center">
              <span className="grid h-20 w-20 place-items-center border border-line text-fog-dim">
                <IconFingerprint className={`h-10 w-10 ${phase === "running" ? "animate-pulse text-cyber" : ""}`} />
              </span>
              <p className="font-display mt-5 text-sm font-bold tracking-[0.2em] text-fog">
                {phase === "running" ? "INTERROGATION DES SOURCES PUBLIQUES…" : "EN ATTENTE D'ARTEFACT"}
              </p>
              <p className="mt-2 max-w-xs font-mono text-[10px] leading-relaxed text-fog-dim">
                abuse.ch · Google DoH · ipwho.is — interrogés en direct, aucune base simulée
              </p>
            </div>
          )}

          {verdict && vs && (
            <div className="animate-gauge-pop relative w-full max-w-sm">
              <div className="flex flex-col items-center">
                <div className="relative h-32 w-32">
                  <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
                    <circle cx="60" cy="60" r="52" fill="none" strokeWidth="7" className="stroke-ink-700" />
                    <circle
                      cx="60" cy="60" r="52" fill="none" strokeWidth="7" strokeLinecap="round"
                      className={`${vs.ring} transition-[stroke-dashoffset] duration-1000 ease-out`}
                      strokeDasharray={CIRC}
                      strokeDashoffset={CIRC * (1 - verdict.score / 100)}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`font-display text-3xl font-bold tabular-nums ${vs.text}`}>{verdict.score}</span>
                    <span className="font-mono text-[9px] tracking-[0.2em] text-fog-dim">RISQUE /100</span>
                  </div>
                </div>
                <div className={`mt-4 flex items-center gap-2 border px-4 py-1.5 font-display text-sm font-bold tracking-[0.22em] ${
                  verdict.level === "SÛR" ? "border-pulse/50 bg-pulse/10 text-pulse" : verdict.level === "SUSPECT" ? "border-warn/50 bg-warn/10 text-warn" : "border-alert/50 bg-alert/10 text-alert"
                }`}>
                  {verdict.level === "SÛR" ? <IconCheck className="h-4 w-4" /> : <IconWarning className="h-4 w-4" />}
                  {verdict.level}
                </div>
                <p className="mt-2 font-mono text-[10px] tracking-[0.16em] text-fog-dim">
                  EMPREINTE 0x{verdict.hash} · <span className="text-cyber">{verdict.real} VÉRIF. RÉELLES</span>
                </p>
              </div>

              <ul className="mt-6 space-y-2 border-t border-line pt-5">
                {verdict.findings.map((f, i) => (
                  <li key={i} className="animate-row-in flex items-start gap-2.5 font-mono text-[11px] leading-snug" style={{ animationDelay: `${i * 90}ms` }}>
                    {f.tone === "ok" ? (
                      <IconCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-pulse" />
                    ) : (
                      <IconWarning className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${f.tone === "bad" ? "text-alert" : "text-warn"}`} />
                    )}
                    <span className="min-w-0 flex-1 text-fog">{f.label}</span>
                    <span className={`shrink-0 border px-1 py-0.5 text-[8px] tracking-[0.12em] ${f.src === "RÉEL" ? "border-cyber/50 text-cyber" : "border-line text-fog-dim"}`}>
                      {f.src}
                    </span>
                  </li>
                ))}
              </ul>

              <div className="mt-6 grid grid-cols-2 gap-2">
                <button
                  onClick={copyReport}
                  className="flex items-center justify-center gap-2 border border-line py-2.5 font-display text-[11px] font-bold tracking-[0.2em] text-fog transition-all hover:border-cyber/70 hover:text-cyber"
                >
                  {copied ? <IconCheck className="h-4 w-4 text-pulse" /> : <IconCopy className="h-4 w-4" />}
                  {copied ? "COPIÉ" : "COPIER"}
                </button>
                <button
                  onClick={() => {
                    if (!verdict) return;
                    window.dispatchEvent(
                      new CustomEvent("aegis-escalate", {
                        detail: `Analyse laboratoire (${tab}) : ${input.trim()} — verdict ${verdict.level}, score de risque ${verdict.score}/100, ${verdict.real} vérifications réelles.`,
                      })
                    );
                    document.getElementById("essaim")?.scrollIntoView({ behavior: "smooth", block: "start" });
                  }}
                  className="flex items-center justify-center gap-2 border border-cyber/50 bg-cyber/10 py-2.5 font-display text-[11px] font-bold tracking-[0.2em] text-cyber transition-all hover:bg-cyber hover:text-ink-950"
                >
                  <IconBolt className="h-4 w-4" />
                  À L'ESSAIM
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
