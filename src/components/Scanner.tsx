import { useEffect, useRef, useState } from "react";
import { mulberry32, seedFrom, useInView } from "../hooks";
import { IconCheck, IconCopy, IconCrosshair, IconFingerprint, IconGlobe, IconPlane, IconWarning } from "./Icons";

type Tab = "url" | "email" | "ip";

const TABS: { id: Tab; label: string; placeholder: string; icon: (p: { className?: string }) => React.ReactNode }[] = [
  { id: "url", label: "URL", placeholder: "https://exemple-suspect.com/page", icon: (p) => <IconGlobe {...p} /> },
  { id: "email", label: "E-MAIL", placeholder: "expediteur@douteux.net", icon: (p) => <IconPlane {...p} /> },
  { id: "ip", label: "ADRESSE IP", placeholder: "185.220.101.47", icon: (p) => <IconCrosshair {...p} /> },
];

const STEP_SETS: Record<Tab, string[]> = {
  url: [
    "Résolution DNS + âge du domaine",
    "Réputation — listes noires collaboratives",
    "Analyse lexicale (typosquatting, homoglyphes)",
    "Pré-détonation en bac à sable",
    "Verdict neuronal NX-2",
  ],
  email: [
    "Vérification SPF / DKIM / DMARC",
    "Analyse des en-têtes Received",
    "Détection d'ingénierie sociale (NLP)",
    "Extraction et scan des pièces jointes",
    "Verdict neuronal NX-2",
  ],
  ip: [
    "Whois + géolocalisation ASN",
    "Historique d'abus (feeds Tor / proxies)",
    "Ports ouverts et bannières de service",
    "Corrélation avec campagnes connues",
    "Verdict neuronal NX-2",
  ],
};

const EXAMPLES: Record<Tab, string[]> = {
  url: ["https://paypa1-secure-verify.xyz/login?id=8841", "https://www.impots-gouv-fr.info/remboursement", "https://docs.entreprise-partage.fr/rapport-q3"],
  email: ["urgent-suspension@banque-fr.net", "direction.rh@groupe-total.energy", "gain-loterie@win-prize.tk"],
  ip: ["185.220.101.47", "8.8.8.8", "45.155.205.86"],
};

interface Finding {
  label: string;
  tone: "ok" | "warn" | "bad";
}

interface Verdict {
  score: number;
  level: "SÛR" | "SUSPECT" | "MALVEILLANT";
  findings: Finding[];
  hash: string;
}

function analyze(tab: Tab, raw: string): Verdict {
  const input = raw.trim();
  const rnd = mulberry32(seedFrom(tab + input));
  let risk = 6 + Math.round(rnd() * 18);
  const findings: Finding[] = [];
  const s = input.toLowerCase();

  if (tab === "url") {
    if (/xn--/.test(s)) { risk += 24; findings.push({ label: "Domaine punycode — homoglyphes détectés", tone: "bad" }); }
    if (/\.(zip|tk|xyz|top|click|gq|ml)\b/.test(s)) { risk += 22; findings.push({ label: "TLD à fort taux d'abus (.xyz, .tk…)", tone: "bad" }); }
    if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(s)) { risk += 20; findings.push({ label: "URL en adresse IP brute — masque d'hameçonnage", tone: "bad" }); }
    if (/http:\/\//.test(s)) { risk += 12; findings.push({ label: "Transport non chiffré (HTTP simple)", tone: "warn" }); }
    if (s.includes("@")) { risk += 16; findings.push({ label: "Caractère « @ » dans l'URL — redirection masquée", tone: "warn" }); }
    if (/(login|verify|secure|update|bank|wallet|remboursement)/.test(s) && /\.(xyz|tk|info|top|click)/.test(s)) { risk += 18; findings.push({ label: "Lexique bancaire + domaine jetable : leurre typique", tone: "bad" }); }
    if ((s.match(/-/g) || []).length > 2) { risk += 8; findings.push({ label: "Sous-domaines à répétition", tone: "warn" }); }
    if (s.length > 62) { risk += 6; findings.push({ label: "Longueur anormale — paramètres de pistage", tone: "warn" }); }
    if (risk < 30) findings.push({ label: "Certificat TLS valide, domaine ancien et réputé", tone: "ok" }, { label: "Aucune correspondance en base de phishing", tone: "ok" });
  } else if (tab === "email") {
    if (!s.includes("@")) { risk += 50; findings.push({ label: "Format d'adresse invalide", tone: "bad" }); }
    const domain = s.split("@")[1] || "";
    if (/(urgent|suspendu|virement|mot.de.passe|gain|loterie|colis)/.test(s)) { risk += 20; findings.push({ label: "Lexique d'urgence sociale détecté", tone: "bad" }); }
    if (/\.(tk|xyz|top|ml|click)$/.test(domain)) { risk += 22; findings.push({ label: "Domaine jetable à fort taux d'abus", tone: "bad" }); }
    if (/(\d{1,3}\.){3}\d{1,3}$/.test(domain)) { risk += 20; findings.push({ label: "Domaine en IP littérale", tone: "bad" }); }
    if (/(banque|impots|paypal|netflix|microsoft|total)/.test(s) && !/\.(fr|com|net|org)$/.test(domain)) { risk += 16; findings.push({ label: "Usurpation de marque probable", tone: "warn" }); }
    if (domain.split(".").length < 2) { risk += 10; findings.push({ label: "Suffixe de domaine incomplet", tone: "warn" }); }
    if (risk < 30) findings.push({ label: "Alignement SPF/DKIM/DMARC conforme", tone: "ok" }, { label: "Expéditeur connu, historique sain", tone: "ok" });
  } else {
    const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(input);
    if (!ipv4) { risk += 40; findings.push({ label: "Format IPv4 non reconnu", tone: "bad" }); }
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(input)) { risk = 8; findings.push({ label: "Plage privée (RFC 1918) — usage interne", tone: "ok" }); }
    if (rnd() < 0.5 && ipv4) { risk += 24; findings.push({ label: "Répertoriée comme nœud de sortie Tor", tone: "bad" }); }
    if (rnd() < 0.4 && ipv4) { risk += 16; findings.push({ label: "Observée dans des scans de ports récents", tone: "warn" }); }
    if (rnd() < 0.3 && ipv4) { risk += 12; findings.push({ label: "ASN hébergeur « bulletproof »", tone: "warn" }); }
    if (risk < 30 && findings.length === 0) findings.push({ label: "Aucun historique d'abus sur les 90 derniers jours", tone: "ok" });
  }

  risk = Math.min(97, risk);
  const level: Verdict["level"] = risk < 30 ? "SÛR" : risk < 65 ? "SUSPECT" : "MALVEILLANT";
  return { score: risk, level, findings, hash: (seedFrom(tab + input) >>> 0).toString(16).toUpperCase().padStart(8, "0") };
}

const VERDICT_STYLE: Record<Verdict["level"], { text: string; hex: string; ring: string }> = {
  "SÛR": { text: "text-pulse", hex: "#43f08d", ring: "stroke-pulse" },
  "SUSPECT": { text: "text-warn", hex: "#ffb020", ring: "stroke-warn" },
  "MALVEILLANT": { text: "text-alert", hex: "#ff4d5e", ring: "stroke-alert" },
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
  const pending = useRef<Verdict | null>(null);
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
      if (i >= steps.length) {
        clearInterval(timer.current);
        setStepIdx(steps.length);
        setVerdict(pending.current);
        setPhase("done");
      } else {
        setStepIdx(i);
      }
    }, 430);
  };

  const copyReport = async () => {
    if (!verdict) return;
    const lines = [
      `RAPPORT AEGIS-7 — ${tab.toUpperCase()} :: ${input.trim()}`,
      `Verdict : ${verdict.level} (score de risque ${verdict.score}/100)`,
      `Empreinte : 0x${verdict.hash}`,
      ...verdict.findings.map((f) => ` • [${f.tone.toUpperCase()}] ${f.label}`),
      "Généré par l'agent IA AEGIS-7 — démonstration (données simulées).",
    ].join("\n");
    try {
      await navigator.clipboard.writeText(lines);
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    }
  };

  const vs = verdict ? VERDICT_STYLE[verdict.level] : null;
  const CIRC = 2 * Math.PI * 52;

  return (
    <section id="analyse" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      <div className="flex items-end justify-between gap-6">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">LABORATOIRE D'ANALYSE</p>
          <h2 className="font-display mt-3 text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Soumettez un artefact <span className="text-cyber">suspect</span>.
          </h2>
        </div>
        <p className="hidden max-w-sm text-sm leading-relaxed text-fog lg:block">
          URL, adresse d'expédition ou IP : l'agent interroge 14 bases de réputation et son moteur
          neuronal, puis rend un verdict argumenté.
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
                    {state === "done" && <span className="ml-auto font-mono text-[9px] tracking-[0.2em] text-pulse">OK · 0.{(i + 2) * 7}s</span>}
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
                {phase === "running" ? "INTERROGATION DES MOTEURS…" : "EN ATTENTE D'ARTEFACT"}
              </p>
              <p className="mt-2 max-w-xs font-mono text-[10px] leading-relaxed text-fog-dim">
                Moteur NX-2 v7.3 · 14 bases de réputation · bac à sable de pré-détonation opérationnel
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
                  EMPREINTE 0x{verdict.hash} · ARTEFACT : <span className="text-fog">{input.trim().slice(0, 30)}</span>
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
                    <span className="text-fog">{f.label}</span>
                  </li>
                ))}
              </ul>

              <button
                onClick={copyReport}
                className="mt-6 flex w-full items-center justify-center gap-2 border border-line py-2.5 font-display text-[11px] font-bold tracking-[0.2em] text-fog transition-all hover:border-cyber/70 hover:text-cyber"
              >
                {copied ? <IconCheck className="h-4 w-4 text-pulse" /> : <IconCopy className="h-4 w-4" />}
                {copied ? "RAPPORT COPIÉ" : "COPIER LE RAPPORT"}
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
