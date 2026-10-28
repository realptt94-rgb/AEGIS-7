import { useEffect, useMemo, useState } from "react";
import { getMaskMode, setMaskMode, useFeed } from "../live";
import { RULES, SAMPLES, leakScore, sanitize, type CatId, type Segment } from "../sanitize";
import { useCountUp, useInView } from "../hooks";
import { IconCheck, IconCopy, IconEyeScan, IconLock, IconShieldCore, IconWarning } from "./Icons";

const CAT_COLOR: Partial<Record<CatId, string>> = {
  jwt: "text-[#b18cff] bg-[#b18cff]/15 border-[#b18cff]/50",
  api: "text-alert bg-alert/15 border-alert/50",
  ipv4: "text-cyber bg-cyber/15 border-cyber/50",
  ipv6: "text-cyber bg-cyber/15 border-cyber/50",
  domain: "text-warn bg-warn/15 border-warn/50",
  url: "text-warn bg-warn/15 border-warn/50",
  port: "text-pulse bg-pulse/15 border-pulse/50",
  email: "text-[#ff8fa3] bg-[#ff8fa3]/15 border-[#ff8fa3]/50",
  hash: "text-fog bg-snow/10 border-line",
  mac: "text-fog bg-snow/10 border-line",
  path: "text-fog bg-snow/10 border-line",
};

const FW_KEY = "aegis7-fw-cats";

function loadEnabled(): Set<CatId> {
  try {
    const raw = localStorage.getItem(FW_KEY);
    if (raw) return new Set(JSON.parse(raw) as CatId[]);
  } catch {
    /* ignore */
  }
  return new Set(RULES.map((r) => r.id));
}

function MaskedText({ segments }: { segments: Segment[] }) {
  return (
    <pre className="whitespace-pre-wrap break-words font-mono text-[11.5px] leading-relaxed text-fog">
      {segments.map((s, i) =>
        s.cat ? (
          <span key={i} className={`animate-row-in inline-block border-b px-0.5 font-bold ${CAT_COLOR[s.cat] ?? "text-alert bg-alert/15 border-alert/50"}`}>
            {s.text}
          </span>
        ) : (
          <span key={i}>{s.text}</span>
        )
      )}
    </pre>
  );
}

export default function CognitiveFirewall() {
  const { ref, inView } = useInView<HTMLElement>();
  const [input, setInput] = useState(SAMPLES[0].text);
  const [enabled, setEnabled] = useState<Set<CatId>>(() => loadEnabled());
  const [copied, setCopied] = useState(false);
  const [fwOn, setFwOn] = useState(true);
  useFeed(); /* se resynchronise quand le mode masquage change depuis le flux */
  const maskGlobal = getMaskMode();

  useEffect(() => {
    try {
      localStorage.setItem(FW_KEY, JSON.stringify([...enabled]));
    } catch {
      /* ignore */
    }
  }, [enabled]);

  const { segments, plain, counts } = useMemo(
    () => (fwOn ? sanitize(input, enabled) : { segments: [{ text: input } as Segment], plain: input, counts: {} }),
    [input, enabled, fwOn]
  );

  const before = useMemo(() => leakScore(input), [input]);
  const after = leakScore(plain);
  const totalMasked = Object.values(counts).reduce((a, b) => a + b, 0);
  const shielded = useCountUp(totalMasked, true, 700);

  const toggle = (id: CatId) =>
    setEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(plain);
    } catch {
      /* ignore */
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const pct = before > 0 ? Math.round(((before - after) / before) * 100) : 100;

  return (
    <section id="bouclier" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      {/* En-tête */}
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-warn">PARE-FEU COGNITIF</p>
          <h2 className="font-display mt-3 max-w-2xl text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Rien ne sort en clair. <span className="text-warn">API, IP, DNS, ports, logs : masqués.</span>
          </h2>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-fog">
            Avant qu'un journal, un en-tête ou un diagnostic ne quitte la machine, chaque marqueur sensible est
            repéré et neutralisé. Les clés API, jetons, adresses, ports et noms DNS deviennent illisibles —
            y compris dans le flux réel ci-dessus.
          </p>
        </div>

        {/* Interrupteur + masquage global */}
        <div className="flex shrink-0 flex-col gap-2">
          <button
            onClick={() => setFwOn((v) => !v)}
            className={`group flex items-center gap-3 border px-4 py-3 transition-all duration-300 ${
              fwOn ? "border-warn/70 bg-warn/10 hover:bg-warn/20" : "border-line bg-ink-900/60 hover:border-warn/50"
            }`}
          >
            <span className={`grid h-9 w-9 place-items-center border transition-colors ${fwOn ? "border-warn/60 text-warn" : "border-line text-fog-dim"}`}>
              <IconShieldCore className="h-5 w-5" />
            </span>
            <span className="text-left">
              <span className={`block font-display text-[11px] font-bold tracking-[0.2em] ${fwOn ? "text-warn" : "text-fog"}`}>
                PARE-FEU {fwOn ? "ARMÉ" : "HORS LIGNE"}
              </span>
              <span className="block font-mono text-[9px] tracking-[0.14em] text-fog-dim">{RULES.length} RÈGLES · 1 PASSAGE</span>
            </span>
            <span className={`relative ml-2 h-5 w-10 shrink-0 border transition-colors ${fwOn ? "border-warn/70 bg-warn/20" : "border-line bg-ink-950"}`}>
              <span className={`absolute top-0.5 h-3.5 w-3.5 transition-all duration-300 ${fwOn ? "left-[22px] bg-warn" : "left-0.5 bg-fog-dim"}`} />
            </span>
          </button>
          <button
            onClick={() => setMaskMode(!maskGlobal)}
            className={`flex items-center justify-center gap-2 border px-4 py-2.5 font-display text-[10px] font-bold tracking-[0.18em] transition-all ${
              maskGlobal ? "border-pulse/70 bg-pulse/10 text-pulse" : "border-line text-fog hover:border-pulse/50 hover:text-pulse"
            }`}
          >
            <IconLock className="h-3.5 w-3.5" />
            {maskGlobal ? "FLUX RÉEL MASQUÉ — ACTIF" : "MASQUER AUSSI LE FLUX RÉEL"}
          </button>
        </div>
      </div>

      {/* Corps */}
      <div className="mt-8 grid gap-5 lg:grid-cols-12">
        {/* Entrée */}
        <div className="panel flex flex-col p-5 lg:col-span-5">
          <div className="flex items-center justify-between">
            <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">INJECTION — TEXTE BRUT</p>
            <span className="font-mono text-[9px] tracking-[0.14em] text-fog-dim">{input.length} CAR.</span>
          </div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={11}
            spellCheck={false}
            className="mt-3 min-h-[220px] flex-1 resize-none border border-line bg-ink-950/60 p-3.5 font-mono text-[11px] leading-relaxed text-snow focus:border-warn/60 focus:outline-none"
          />
          <div className="mt-3 flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button
                key={s.id}
                onClick={() => setInput(s.text)}
                className="border border-line bg-ink-950/50 px-2.5 py-1.5 font-mono text-[9px] tracking-[0.14em] text-fog transition-colors hover:border-warn/60 hover:text-warn"
              >
                {s.label}
              </button>
            ))}
            <button
              onClick={() => setInput("")}
              className="ml-auto border border-line px-2.5 py-1.5 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-alert/60 hover:text-alert"
            >
              VIDER
            </button>
          </div>

          {/* Score de fuite */}
          <div className="mt-5 border-t border-line pt-4">
            <div className="flex items-baseline justify-between">
              <p className="font-mono text-[9px] tracking-[0.22em] text-fog-dim">FUITE COGNITIVE</p>
              <p className="font-display text-xs font-bold tracking-[0.14em]">
                <span className="text-alert">{before}</span>
                <span className="mx-1.5 text-fog-dim">→</span>
                <span className={after === 0 ? "text-pulse" : "text-warn"}>{after}</span>
                <span className="ml-2 text-fog-dim">MARQUEUR{before > 1 ? "S" : ""}</span>
              </p>
            </div>
            <div className="mt-2 flex h-2 overflow-hidden border border-line bg-ink-950">
              <div
                className="bg-gradient-to-r from-alert via-warn to-pulse transition-all duration-700"
                style={{ width: `${fwOn ? pct : 0}%` }}
              />
            </div>
            <p className="mt-1.5 text-right font-mono text-[9px] tracking-[0.14em] text-fog-dim">
              NEUTRALISATION : <span className={pct === 100 ? "text-pulse" : "text-warn"}>{fwOn ? pct : 0}%</span>
            </p>
          </div>
        </div>

        {/* Sortie masquée */}
        <div className="panel relative flex flex-col overflow-hidden lg:col-span-7">
          <div className="flex items-center justify-between border-b border-line px-5 py-3">
            <p className="flex items-center gap-2.5 font-display text-[11px] font-bold tracking-[0.24em] text-snow">
              <IconEyeScan className={`h-4 w-4 ${fwOn ? "text-warn" : "text-fog-dim"}`} />
              SORTIE ASSAINIE
            </p>
            <div className="flex items-center gap-3">
              <span className={`border px-2 py-1 font-mono text-[9px] tracking-[0.14em] ${fwOn ? "border-warn/50 bg-warn/10 text-warn" : "border-line text-fog-dim"}`}>
                {Math.round(shielded)} MARQUEUR{Math.round(shielded) > 1 ? "S" : ""} MASQUÉ{Math.round(shielded) > 1 ? "S" : ""}
              </span>
              <button
                onClick={copy}
                className="flex items-center gap-1.5 border border-line px-2.5 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-warn/60 hover:text-warn"
              >
                {copied ? <IconCheck className="h-3 w-3 text-pulse" /> : <IconCopy className="h-3 w-3" />}
                {copied ? "COPIÉE" : "COPIER"}
              </button>
            </div>
          </div>
          <div className="scanfield relative min-h-[280px] flex-1 overflow-y-auto p-5">
            {fwOn ? (
              <MaskedText segments={segments} />
            ) : (
              <>
                <p className="flex items-center gap-2 font-mono text-[10px] tracking-[0.16em] text-alert">
                  <IconWarning className="h-4 w-4" /> PARE-FEU HORS LIGNE — SORTIE NON FILTRÉE
                </p>
                <pre className="mt-3 whitespace-pre-wrap break-words font-mono text-[11.5px] leading-relaxed text-fog">{input}</pre>
              </>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-line px-5 py-3">
            <span className="font-mono text-[8px] tracking-[0.18em] text-fog-dim">LÉGENDE :</span>
            {Object.entries(CAT_COLOR).slice(0, 8).map(([cat, cls]) => (
              <span key={cat} className={`border-b px-1 font-mono text-[9px] font-bold ${cls}`}>
                {RULES.find((r) => r.id === cat)?.label.split(" ")[0] ?? cat}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Matrice de règles */}
      <div className="panel mt-5 overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">MATRICE DES {RULES.length} RÈGLES</p>
          <div className="flex gap-2">
            <button onClick={() => setEnabled(new Set(RULES.map((r) => r.id)))} className="border border-line px-2.5 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-pulse/60 hover:text-pulse">
              TOUT ARMER
            </button>
            <button onClick={() => setEnabled(new Set())} className="border border-line px-2.5 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-alert/60 hover:text-alert">
              TOUT COUPER
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 divide-x divide-y divide-line/60 md:grid-cols-3 lg:grid-cols-6 lg:divide-y-0">
          {RULES.map((r) => {
            const on = enabled.has(r.id);
            const n = counts[r.id] ?? 0;
            return (
              <button
                key={r.id}
                onClick={() => toggle(r.id)}
                className={`group flex flex-col gap-1.5 px-4 py-4 text-left transition-all duration-200 ${
                  on ? "bg-snow/[0.03] hover:bg-snow/[0.06]" : "opacity-40 hover:opacity-70"
                }`}
              >
                <span className="flex items-center justify-between">
                  <span className={`font-display text-[10px] font-bold tracking-[0.16em] ${on ? "text-snow" : "text-fog-dim"}`}>{r.label.toUpperCase()}</span>
                  <span className={`grid h-4 w-4 place-items-center border transition-colors ${on ? "border-warn bg-warn text-ink-950" : "border-line"}`}>
                    {on && <IconCheck className="h-2.5 w-2.5" />}
                  </span>
                </span>
                <span className="font-mono text-[9px] text-fog-dim">{r.sample}</span>
                <span className={`mt-auto font-mono text-[9px] tracking-[0.14em] ${n > 0 ? "text-warn" : "text-fog-dim"}`}>
                  {n > 0 ? `${n} NEUTRALISÉ${n > 1 ? "S" : ""}` : "EN VEILLE"}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
