import { useRef, useState } from "react";
import { braveSearch, ensureFeed, feodoMatch, geoIp, resolveDns, threatFoxSearch } from "../live";
import { useInView } from "../hooks";
import { IconBolt, IconCheck, IconCopy, IconCrosshair, IconExternal, IconWarning } from "./Icons";

type PhaseStatus = "todo" | "run" | "done" | "err";

const PHASE_META = [
  { code: "PH-1", title: "Géolocalisation & ASN", source: "ipwho.is" },
  { code: "PH-2", title: "DNS inverse (PTR)", source: "Google DoH" },
  { code: "PH-3", title: "Croisement des référentiels", source: "ThreatFox + Feodo" },
  { code: "PH-4", title: "Contexte OSINT public", source: "Brave Search" },
  { code: "PH-5", title: "Verdict & mesures", source: "AEGIS-7" },
];

const MASK_RE = /hosting|vps|cloud|dedicat|server|ovh|hetzner|digital\s?ocean|linode|contabo|scaleway|vultr|choopa|m247/i;

const EXAMPLES = [
  { ip: "185.220.101.47", label: "sortie Tor publique" },
  { ip: "94.102.49.190", label: "scanner récurrent" },
  { ip: "8.8.8.8", label: "témoin sain" },
  { ip: "1.1.1.1", label: "témoin CDN" },
];

interface Verdict {
  risk: "CRITIQUE" | "MODÉRÉ" | "FAIBLE";
  title: string;
  text: string;
  rule: string;
  report: string;
}

interface LogLine {
  id: number;
  cls: "sys" | "ok" | "warn" | "err";
  text: string;
}

const LOG_COLOR: Record<LogLine["cls"], string> = {
  sys: "text-fog-dim",
  ok: "text-pulse",
  warn: "text-warn",
  err: "text-alert",
};

const RISK_STYLE: Record<Verdict["risk"], string> = {
  CRITIQUE: "border-alert/60 bg-alert/10 text-alert",
  "MODÉRÉ": "border-warn/60 bg-warn/10 text-warn",
  FAIBLE: "border-pulse/60 bg-pulse/10 text-pulse",
};

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export default function Attribution() {
  const { ref, inView } = useInView<HTMLElement>();
  const [input, setInput] = useState("");
  const [inputErr, setInputErr] = useState(false);
  const [running, setRunning] = useState(false);
  const [phases, setPhases] = useState<PhaseStatus[]>(["todo", "todo", "todo", "todo", "todo"]);
  const [geo, setGeo] = useState<any | null>(null);
  const [masked, setMasked] = useState(false);
  const [ptr, setPtr] = useState<string | null>(null);
  const [tf, setTf] = useState<any | null>(null);
  const [feodo, setFeodo] = useState<any | null>(null);
  const [osint, setOsint] = useState<{ title: string; url: string; desc: string }[] | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const [copied, setCopied] = useState<string | null>(null);
  const idRef = useRef(0);
  const busyRef = useRef(false);

  const setP = (i: number, s: PhaseStatus) => setPhases((p) => p.map((x, k) => (k === i ? s : x)));
  const pushLog = (cls: LogLine["cls"], text: string) =>
    setLog((l) => [...l.slice(-60), { id: ++idRef.current, cls, text }]);

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* presse-papiers indisponible */
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const run = async (raw?: string) => {
    const ip = (raw ?? input).trim();
    const valid = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split(".").every((o) => Number(o) <= 255);
    if (!valid) {
      setInputErr(true);
      setTimeout(() => setInputErr(false), 900);
      return;
    }
    if (busyRef.current) return;
    busyRef.current = true;
    setRunning(true);
    setPhases(["todo", "todo", "todo", "todo", "todo"]);
    setGeo(null); setMasked(false); setPtr(null); setTf(null); setFeodo(null); setOsint(null); setVerdict(null);
    setLog([]);
    pushLog("sys", `═══ FILTRATION LANCÉE — adresse technique ${ip} ═══`);

    /* PH-1 — géolocalisation & ASN */
    setP(0, "run");
    let g: any = null;
    try {
      g = await geoIp(ip);
    } catch {
      g = null;
    }
    if (g) {
      setGeo(g);
      const org = `${g.connection?.org ?? ""} ${g.connection?.isp ?? ""}`;
      const isMasked = MASK_RE.test(org);
      setMasked(isMasked);
      pushLog("ok", `PH-1 ▸ ${g.flag?.emoji ?? ""} ${g.city ?? "?"}, ${g.country ?? "?"} — ASN ${g.connection?.asn ?? "?"} · ${g.connection?.org ?? "?"}`);
      if (isMasked) pushLog("warn", `PH-1 ▸ couche masquante identifiée : « ${g.connection?.org} » (hébergement générique)`);
      setP(0, "done");
    } else {
      pushLog("err", "PH-1 ▸ ipwho.is injoignable — étape écartée");
      setP(0, "err");
    }
    await wait(350);

    /* PH-2 — DNS inverse */
    setP(1, "run");
    try {
      const arpa = ip.split(".").reverse().join(".") + ".in-addr.arpa";
      const r = await resolveDns(arpa, "PTR");
      const p = r[0] ?? null;
      setPtr(p);
      if (p) pushLog("ok", `PH-2 ▸ PTR résolu : ${p}`);
      else pushLog("warn", "PH-2 ▸ aucun enregistrement PTR — mutisme DNS volontaire");
      setP(1, "done");
    } catch {
      pushLog("err", "PH-2 ▸ DoH injoignable — étape écartée");
      setP(1, "err");
    }
    await wait(350);

    /* PH-3 — croisement des référentiels */
    setP(2, "run");
    await ensureFeed();
    let tfHit: any = null;
    try {
      tfHit = await threatFoxSearch(ip);
    } catch {
      tfHit = null;
    }
    const fdHit = feodoMatch(ip);
    setTf(tfHit);
    setFeodo(fdHit);
    if (tfHit) pushLog("ok", `PH-3 ▸ ThreatFox : correspondance — ${tfHit.malware_printable ?? tfHit.malware} (${tfHit.threat_type}, confiance ${tfHit.confidence_level}%)`);
    else pushLog("sys", "PH-3 ▸ ThreatFox : aucune correspondance");
    if (fdHit) pushLog("ok", `PH-3 ▸ Feodo Tracker : infrastructure de commande répertoriée — ${fdHit.malware}`);
    else pushLog("sys", "PH-3 ▸ Feodo : absente de la liste de blocage C2");
    setP(2, tfHit || fdHit ? "done" : "done");
    await wait(350);

    /* PH-4 — contexte OSINT public */
    setP(3, "run");
    try {
      const res = await braveSearch(`"${ip}" abuse OR phishing OR botnet OR malware`, 3);
      setOsint(res);
      if (res.length) {
        pushLog("ok", `PH-4 ▸ Brave Search : ${res.length} référence(s) publique(s) trouvée(s)`);
        res.forEach((r) => pushLog("sys", `   · ${r.title.slice(0, 70)}`));
      } else {
        pushLog("sys", "PH-4 ▸ Brave Search : aucune mention publique");
      }
      setP(3, "done");
    } catch {
      pushLog("err", "PH-4 ▸ Brave Search injoignable — étape écartée");
      setP(3, "err");
    }
    await wait(350);

    /* PH-5 — verdict & mesures */
    setP(4, "run");
    await wait(400);
    const fam = tfHit?.malware_printable ?? tfHit?.malware ?? fdHit?.malware;
    let v: Verdict;
    if (tfHit || fdHit) {
      v = {
        risk: "CRITIQUE",
        title: "Infrastructure d'attaque confirmée",
        text: `L'adresse ${ip} est répertoriée par les référentiels publics${fam ? ` — famille ${fam}` : ""}${
          tfHit?.reference ? ` (source : ${String(tfHit.reference).slice(0, 60)})` : ""
        }. Recommandation : blocage immédiat au pare-feu et consignation de l'incident.`,
        rule: `iptables -A INPUT -s ${ip} -j DROP   # ${fam ?? "IOC confirmé"} — AEGIS-7`,
        report: [
          `RAPPORT D'ATTRIBUTION — AEGIS-7`,
          `Cible technique : ${ip}`,
          `Statut : infrastructure d'attaque confirmée (${fam ?? "référentiel public"})`,
          `Géo/ASN : ${g ? `${g.city}, ${g.country} — ASN ${g.connection?.asn} (${g.connection?.org})` : "inconnu"}`,
          `PTR : ${ptr ?? "aucun"}`,
          `Masquage : ${masked ? "hébergement générique détecté" : "non détecté"}`,
          `Mentions OSINT : ${osint?.length ?? 0}`,
          `Mesure : blocage périmétrique + signalement aux référentiels nationaux (ANSSI / DGSSI).`,
        ].join("\n"),
      };
    } else if (masked) {
      v = {
        risk: "MODÉRÉ",
        title: "Hébergement masquant probable",
        text: `L'adresse ${ip} provient d'un hébergeur générique${ptr ? ` (PTR : ${ptr})` : " sans PTR"} — profil typique des infrastructures jetables utilisées par les campagnes. Aucune confirmation publique à ce stade : surveillance renforcée recommandée.`,
        rule: `iptables -A INPUT -s ${ip} -j LOG --log-prefix "AEGIS-watch "   # surveillance renforcée`,
        report: [
          `RAPPORT D'ATTRIBUTION — AEGIS-7`,
          `Cible technique : ${ip}`,
          `Statut : hébergement masquant probable, non répertoriée`,
          `Géo/ASN : ${g ? `${g.city}, ${g.country} — ASN ${g.connection?.asn} (${g.connection?.org})` : "inconnu"}`,
          `PTR : ${ptr ?? "aucun"}`,
          `Mesure : journalisation active + réévaluation à chaque nouvel indicateur.`,
        ].join("\n"),
      };
    } else {
      v = {
        risk: "FAIBLE",
        title: "Aucun antécédent public",
        text: `L'adresse ${ip} n'apparaît dans aucun référentiel public consulté et ne présente pas de profil masquant. Aucune mesure coercitive justifiée à ce stade.`,
        rule: `# Aucune mesure requise — ${ip} non répertoriée`,
        report: [
          `RAPPORT D'ATTRIBUTION — AEGIS-7`,
          `Cible technique : ${ip}`,
          `Statut : aucun antécédent public (ThreatFox, Feodo, OSINT)`,
          `Géo/ASN : ${g ? `${g.city}, ${g.country} — ASN ${g.connection?.asn} (${g.connection?.org})` : "inconnu"}`,
          `Mesure : aucune — veille standard.`,
        ].join("\n"),
      };
    }
    setVerdict(v);
    setP(4, "done");
    pushLog(v.risk === "CRITIQUE" ? "err" : v.risk === "MODÉRÉ" ? "warn" : "ok", `PH-5 ▸ VERDICT : ${v.risk} — ${v.title}`);
    pushLog("sys", "═══ FILTRATION CLOSE ═══");
    setRunning(false);
    busyRef.current = false;
  };

  return (
    <section id="attribution" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">MODULE D'ATTRIBUTION D'INFRASTRUCTURE</p>
          <h2 className="font-display mt-3 max-w-2xl text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Derrière l'adresse masquée, <span className="text-alert">l'infrastructure réelle</span>.
          </h2>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-fog">
            Proxies, hébergements jetables, nœuds de sortie : l'agent filtre couche par couche — ASN, DNS inverse,
            référentiels d'indicateurs, OSINT publique — jusqu'à caractériser l'infrastructure qui sert les campagnes,
            puis fournit la règle de blocage prête à appliquer.
          </p>
        </div>
        <p className="max-w-xs shrink-0 border border-line bg-ink-900/60 p-4 font-mono text-[9px] leading-relaxed tracking-[0.1em] text-fog-dim">
          CADRE STRICTEMENT DÉFENSIF — INDICATEURS TECHNIQUES PUBLICS UNIQUEMENT, AUCUNE DONNÉE PERSONNELLE.
        </p>
      </div>

      {/* Saisie */}
      <div className="panel panel-corner mt-8 p-5 sm:p-6">
        <div className={`flex flex-col gap-3 border transition-colors sm:flex-row ${inputErr ? "border-alert" : "border-line focus-within:border-cyber/70"}`}>
          <span className="grid w-12 shrink-0 place-items-center border-r border-line text-cyber">
            <IconCrosshair className="h-5 w-5" />
          </span>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !running && run()}
            placeholder="Adresse technique à filtrer — ex. 185.220.101.47"
            spellCheck={false}
            className="min-w-0 flex-1 bg-transparent px-4 py-3.5 font-mono text-sm text-snow placeholder:text-fog-dim focus:outline-none"
          />
          <button
            onClick={() => run()}
            disabled={running}
            className="clip-tag group flex shrink-0 items-center justify-center gap-2.5 bg-alert px-8 py-3.5 font-display text-xs font-bold tracking-[0.22em] text-ink-950 transition-all hover:bg-snow disabled:opacity-50"
          >
            <IconBolt className={`h-4 w-4 ${running ? "animate-pulse" : "transition-transform group-hover:scale-125"}`} />
            {running ? "FILTRATION…" : "LANCER LA FILTRATION"}
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.ip}
              onClick={() => { setInput(ex.ip); run(ex.ip); }}
              disabled={running}
              className="flex items-center gap-2 border border-line bg-ink-950/50 px-2.5 py-1.5 font-mono text-[10px] text-fog transition-colors hover:border-alert/60 hover:text-alert disabled:opacity-50"
            >
              <span className="font-bold">{ex.ip}</span>
              <span className="text-fog-dim">· {ex.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-12">
        {/* Pipeline */}
        <div className="space-y-3 lg:col-span-5">
          {PHASE_META.map((ph, i) => {
            const st = phases[i];
            return (
              <div
                key={ph.code}
                className={`panel border-l-2 p-4 transition-all duration-300 ${
                  st === "run" ? "border-l-cyber bg-cyber/[0.05]" : st === "done" ? "border-l-pulse/70" : st === "err" ? "border-l-warn/70 opacity-80" : "border-l-line opacity-50"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={`grid h-7 w-7 shrink-0 place-items-center border font-mono text-[10px] ${
                    st === "done" ? "border-pulse/60 text-pulse" : st === "run" ? "border-cyber text-cyber" : st === "err" ? "border-warn/60 text-warn" : "border-line text-fog-dim"
                  }`}>
                    {st === "done" ? <IconCheck className="h-3.5 w-3.5" /> : st === "run" ? (
                      <span className="h-3 w-3 animate-spin rounded-full border border-cyber border-t-transparent" />
                    ) : st === "err" ? <IconWarning className="h-3.5 w-3.5" /> : i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="font-display text-[11px] font-bold tracking-[0.16em] text-snow">
                      {ph.code} — {ph.title.toUpperCase()}
                    </p>
                    <p className="font-mono text-[9px] tracking-[0.12em] text-fog-dim">{ph.source}</p>
                  </div>
                </div>

                {/* Résultats inline */}
                {i === 0 && st === "done" && geo && (
                  <p className="mt-3 border-t border-line/60 pt-2.5 font-mono text-[10px] leading-relaxed text-fog">
                    {geo.flag?.emoji} {geo.city}, {geo.country} · ASN {geo.connection?.asn} · {geo.connection?.org}
                    {masked && <span className="ml-2 border border-warn/50 bg-warn/10 px-1.5 py-0.5 text-[8px] tracking-[0.12em] text-warn">MASQUANT</span>}
                  </p>
                )}
                {i === 1 && st === "done" && (
                  <p className="mt-3 border-t border-line/60 pt-2.5 font-mono text-[10px] text-fog">
                    {ptr ?? "aucun PTR — mutisme DNS"}
                  </p>
                )}
                {i === 2 && st === "done" && (
                  <div className="mt-3 flex flex-wrap gap-2 border-t border-line/60 pt-2.5">
                    {tf ? (
                      <span className="border border-alert/50 bg-alert/10 px-2 py-1 font-mono text-[9px] tracking-[0.1em] text-alert">
                        THREATFOX : {tf.malware_printable ?? tf.malware} · {tf.threat_type}
                      </span>
                    ) : (
                      <span className="border border-line px-2 py-1 font-mono text-[9px] tracking-[0.1em] text-fog-dim">THREATFOX : RAS</span>
                    )}
                    {feodo ? (
                      <span className="border border-alert/50 bg-alert/10 px-2 py-1 font-mono text-[9px] tracking-[0.1em] text-alert">
                        FEODO : C2 {feodo.malware}
                      </span>
                    ) : (
                      <span className="border border-line px-2 py-1 font-mono text-[9px] tracking-[0.1em] text-fog-dim">FEODO : RAS</span>
                    )}
                  </div>
                )}
                {i === 3 && st === "done" && (
                  <ul className="mt-3 space-y-1.5 border-t border-line/60 pt-2.5">
                    {osint && osint.length > 0 ? osint.map((r) => (
                      <li key={r.url}>
                        <a href={r.url} target="_blank" rel="noopener noreferrer" className="group flex items-start gap-1.5 font-mono text-[10px] text-fog transition-colors hover:text-cyber">
                          <IconExternal className="mt-0.5 h-3 w-3 shrink-0 text-fog-dim group-hover:text-cyber" />
                          <span className="truncate">{r.title}</span>
                        </a>
                      </li>
                    )) : (
                      <li className="font-mono text-[10px] text-fog-dim">Aucune mention publique.</li>
                    )}
                  </ul>
                )}
                {i === 4 && st === "done" && verdict && (
                  <p className={`mt-3 border-t border-line/60 pt-2.5 font-mono text-[10px] tracking-[0.12em] ${RISK_STYLE[verdict.risk].split(" ").pop()}`}>
                    {verdict.risk} — {verdict.title}
                  </p>
                )}
              </div>
            );
          })}
        </div>

        {/* Verdict + mesures + journal */}
        <div className="flex flex-col gap-5 lg:col-span-7">
          {verdict && (
            <div className={`animate-gauge-pop border-2 p-5 ${RISK_STYLE[verdict.risk]}`}>
              <div className="flex items-center gap-3">
                {verdict.risk === "FAIBLE" ? <IconCheck className="h-5 w-5" /> : <IconWarning className="h-5 w-5" />}
                <p className="font-display text-sm font-bold tracking-[0.22em]">VERDICT : {verdict.risk}</p>
                <span className="ml-auto border border-current/40 px-2 py-1 font-mono text-[9px] tracking-[0.14em]">{verdict.title.toUpperCase()}</span>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-fog">{verdict.text}</p>
            </div>
          )}

          {verdict && (
            <div className="grid gap-5 md:grid-cols-2">
              <div className="panel p-4">
                <div className="flex items-center justify-between">
                  <p className="font-display text-[10px] font-bold tracking-[0.22em] text-fog">MESURE PARE-FEU</p>
                  <button onClick={() => copy("rule", verdict.rule)} className="flex items-center gap-1.5 border border-line px-2 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-cyber/60 hover:text-cyber">
                    {copied === "rule" ? <IconCheck className="h-3 w-3 text-pulse" /> : <IconCopy className="h-3 w-3" />}
                    {copied === "rule" ? "COPIÉE" : "COPIER"}
                  </button>
                </div>
                <pre className="mt-3 overflow-x-auto whitespace-pre-wrap border border-line bg-ink-950/70 p-3 font-mono text-[10px] leading-relaxed text-pulse">{verdict.rule}</pre>
              </div>
              <div className="panel p-4">
                <div className="flex items-center justify-between">
                  <p className="font-display text-[10px] font-bold tracking-[0.22em] text-fog">RAPPORT D'ATTRIBUTION</p>
                  <button onClick={() => copy("report", verdict.report)} className="flex items-center gap-1.5 border border-line px-2 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-cyber/60 hover:text-cyber">
                    {copied === "report" ? <IconCheck className="h-3 w-3 text-pulse" /> : <IconCopy className="h-3 w-3" />}
                    {copied === "report" ? "COPIÉ" : "COPIER"}
                  </button>
                </div>
                <pre className="mt-3 max-h-40 overflow-y-auto whitespace-pre-wrap border border-line bg-ink-950/70 p-3 font-mono text-[10px] leading-relaxed text-fog">{verdict.report}</pre>
              </div>
            </div>
          )}

          {/* Journal */}
          <div className="panel flex min-h-[220px] flex-1 flex-col overflow-hidden">
            <div className="border-b border-line px-4 py-2.5">
              <p className="font-mono text-[10px] tracking-[0.2em] text-fog-dim">JOURNAL DE FILTRATION</p>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 font-mono text-[11px] leading-relaxed">
              {log.length === 0 && (
                <p className="mt-4 text-center text-fog-dim">
                  <span className="animate-blink text-cyber">▍</span> Lancez une filtration — chaque couche sera levée une à une.
                </p>
              )}
              {log.map((l) => (
                <p key={l.id} className={`${LOG_COLOR[l.cls]} animate-row-in whitespace-pre-wrap break-words`}>{l.text}</p>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
