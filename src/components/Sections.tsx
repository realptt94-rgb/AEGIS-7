import { useState } from "react";
import { INTEL_CATS, INTEL_SOURCES, MODULES, PHASES, type DefenseModule } from "../data";
import { useCountUp, useInView } from "../hooks";
import {
  IconBolt, IconBrainChip, IconCheck, IconExternal, IconEyeScan,
  IconOnion, IconPlane, IconRadar, IconWave,
} from "./Icons";

/* ================================================================ */
/* Bande de statistiques                                             */
/* ================================================================ */

function Stat({ value, suffix, label, decimals = 0, delay = 0 }: { value: number; suffix?: string; label: string; decimals?: number; delay?: number }) {
  const { ref, inView } = useInView<HTMLDivElement>();
  const v = useCountUp(value, inView, 1600 + delay, decimals);
  const display = decimals > 0 ? v.toFixed(decimals).replace(".", ",") : Math.round(v).toLocaleString("fr-FR");
  return (
    <div
      ref={ref}
      className="border-line px-6 py-8 max-lg:odd:border-l-0 max-lg:[&:nth-child(n+3)]:border-t lg:border-l lg:first:border-l-0 sm:px-8"
    >
      <div className="font-display text-3xl font-bold tracking-tight text-snow tabular-nums sm:text-4xl">
        {display}
        {suffix && <span className="text-cyber">{suffix}</span>}
      </div>
      <div className="mt-2 font-mono text-[10px] tracking-[0.22em] text-fog-dim">{label}</div>
    </div>
  );
}

export function StatsBand() {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <div
      ref={ref}
      className={`reveal ${inView ? "reveal-in" : ""} mx-auto mt-24 max-w-7xl px-4 sm:px-6`}
    >
      <div className="panel grid grid-cols-2 lg:grid-cols-4">
        <Stat value={1284509} label="ATTAQUES NEUTRALISÉES / 30 J" delay={0} />
        <Stat value={146} label="OPÉRATEURS FR & MA SOUS GARDE" delay={150} />
        <Stat value={99.2} suffix="%" decimals={1} label="TAUX DE DÉTECTION" delay={300} />
        <Stat value={38} suffix=" ms" label="RÉPONSE MOYENNE" delay={450} />
      </div>
    </div>
  );
}

/* ================================================================ */
/* Modules de défense                                                */
/* ================================================================ */

const MODULE_ICONS: Record<string, (p: { className?: string }) => React.ReactNode> = {
  firewall: (p) => <IconBrainChip {...p} />,
  phishing: (p) => <IconEyeScan {...p} />,
  ids: (p) => <IconRadar {...p} />,
  torwatch: (p) => <IconOnion {...p} />,
  tgwatch: (p) => <IconPlane {...p} />,
  soar: (p) => <IconBolt {...p} />,
};

const MODULE_SPANS: Record<string, string> = {
  firewall: "lg:col-span-6",
  phishing: "lg:col-span-6",
  ids: "lg:col-span-4",
  torwatch: "lg:col-span-4",
  tgwatch: "lg:col-span-4",
  soar: "lg:col-span-12",
};

function ModuleCard({ mod, index }: { mod: DefenseModule; index: number }) {
  const { ref, inView } = useInView<HTMLDivElement>(0.12);
  const wide = mod.id === "soar";
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${(index % 3) * 110}ms` }}
      className={`reveal ${inView ? "reveal-in" : ""} group panel relative flex flex-col p-6 transition-all duration-300 hover:-translate-y-1 hover:border-cyber/50 sm:p-7 ${MODULE_SPANS[mod.id]}`}
    >
      <div className="flex items-start justify-between">
        <span className="grid h-11 w-11 place-items-center border border-line text-cyber transition-all duration-300 group-hover:border-cyber/60 group-hover:shadow-[0_0_24px_rgba(56,225,255,0.25)]">
          {MODULE_ICONS[mod.id]({ className: "h-5 w-5" })}
        </span>
        <div className="flex items-center gap-3">
          <span className="border border-pulse/40 bg-pulse/10 px-2 py-1 font-mono text-[9px] tracking-[0.18em] text-pulse">
            {mod.status}
          </span>
          <span className="font-mono text-[10px] tracking-[0.16em] text-fog-dim">{mod.code}</span>
        </div>
      </div>

      <h3 className="font-display mt-5 text-lg font-bold tracking-tight text-snow">{mod.title}</h3>
      <p className={`mt-2 text-sm leading-relaxed text-fog ${wide ? "max-w-3xl" : ""}`}>{mod.desc}</p>

      {mod.id === "firewall" && (
        <div className="mt-6 h-14 overflow-hidden border-t border-line pt-4">
          <div className="animate-wave flex w-max gap-0 text-cyber/70">
            {[0, 1].map((k) => (
              <svg key={k} viewBox="0 0 240 40" className="h-10 w-[240px] shrink-0" fill="none" stroke="currentColor" strokeWidth="1.4">
                <path d="M0 20h30l8-12 10 24 8-16 10 12 8-8h36l8-14 10 26 8-18 10 10 8-6h36l8-12 10 22 8-14 10 10 8-6h34" />
              </svg>
            ))}
          </div>
        </div>
      )}

      {wide && (
        <div className="mt-6 flex flex-wrap items-center gap-2 border-t border-line pt-5">
          {["ISOLER", "RÉVOQUER", "BLOQUER", "LEURRER", "JOURNALISER"].map((s, i) => (
            <span key={s} className="flex items-center gap-2">
              <span className="clip-tag bg-ink-700 px-3 py-1.5 font-mono text-[10px] tracking-[0.2em] text-fog transition-colors group-hover:text-cyber">
                {s}
              </span>
              {i < 4 && <IconBolt className="h-3 w-3 text-cyber/60" />}
            </span>
          ))}
        </div>
      )}

      <div className="mt-auto pt-5">
        <span className="font-mono text-[10px] tracking-[0.14em] text-fog-dim">
          ▸ <span className="text-fog">{mod.metric}</span>
        </span>
      </div>
    </div>
  );
}

export function Modules() {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <section id="modules" className="mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6">
      <div ref={ref} className={`reveal ${inView ? "reveal-in" : ""} flex flex-col justify-between gap-4 sm:flex-row sm:items-end`}>
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">ARSENAL DÉFENSIF</p>
          <h2 className="font-display mt-3 text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Six modules, <span className="text-cyber">un seul réflexe</span> : bloquer.
          </h2>
        </div>
        <p className="max-w-sm text-sm leading-relaxed text-fog">
          Chaque module tourne en permanence, alimenté par les flux OSINT Telegram et la vigie Tor.
        </p>
      </div>

      <div className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-12">
        {MODULES.map((m, i) => (
          <ModuleCard key={m.id} mod={m} index={i} />
        ))}
      </div>
    </section>
  );
}

/* ================================================================ */
/* Renseignement open source                                         */
/* ================================================================ */

const CAT_HEX: Record<string, string> = {
  "OSINT TELEGRAM": "#38e1ff",
  "TOR & DARKNET": "#b18cff",
  "BASE OFFENSIVE": "#ff4d5e",
  "IA DÉFENSIVE": "#43f08d",
  "INFRA & IA": "#ffb020",
};

export function Intel() {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <section id="renseignement" className="mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6">
      <div ref={ref} className={`reveal ${inView ? "reveal-in" : ""}`}>
        <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">FLUX DE RENSEIGNEMENT</p>
        <div className="mt-3 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <h2 className="font-display max-w-xl text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            22 sources open source, <span className="text-cyber">corrélées en continu</span>.
          </h2>
          <p className="max-w-md text-sm leading-relaxed text-fog">
            L'agent ingère la veille issue des dépôts publics — OSINT Telegram, exploration Tor,
            bases de payloads offensives et cadres IA défensifs — pour connaître l'adversaire mieux
            que lui-même.
          </p>
        </div>
      </div>

      <div className="mt-10 grid gap-5 lg:grid-cols-2">
        {INTEL_CATS.map((cat, ci) => {
          const sources = INTEL_SOURCES.filter((s) => s.cat === cat);
          return (
            <div key={cat} className="panel overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
                <h3 className="flex items-center gap-2.5 font-display text-xs font-bold tracking-[0.22em] text-snow">
                  <span className="h-2 w-2" style={{ background: CAT_HEX[cat] }} />
                  {cat}
                </h3>
                <span className="font-mono text-[10px] tracking-[0.16em] text-fog-dim">
                  {sources.length} SOURCE{sources.length > 1 ? "S" : ""} · SYNC 100%
                </span>
              </div>
              <ul className="divide-y divide-line/60">
                {sources.map((s, i) => (
                  <IntelRow key={s.name} name={s.name} url={s.url} desc={s.desc} hex={CAT_HEX[cat]} delay={(ci + i) * 40} />
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function IntelRow({ name, url, desc, hex, delay }: { name: string; url: string; desc: string; hex: string; delay: number }) {
  const { ref, inView } = useInView<HTMLLIElement>(0.08);
  return (
    <li ref={ref} style={{ transitionDelay: `${delay}ms` }} className={`reveal ${inView ? "reveal-in" : ""}`}>
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="group flex gap-4 border-l-2 border-transparent px-5 py-3.5 transition-all hover:border-l-cyber hover:bg-snow/[0.03]"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-mono text-xs font-medium text-snow transition-colors group-hover:text-cyber">
              {name}
            </span>
            <IconExternal className="h-3 w-3 shrink-0 text-fog-dim transition-colors group-hover:text-cyber" />
            <span className="ml-auto flex shrink-0 items-center gap-1.5 font-mono text-[9px] tracking-[0.18em] text-pulse">
              <span className="h-1.5 w-1.5 rounded-full animate-pulse-dot" /> ACTIF
            </span>
          </div>
          <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-fog-dim group-hover:text-fog">{desc}</p>
        </div>
        <span className="mt-0.5 hidden h-8 w-1 shrink-0 self-center sm:block" style={{ background: hex, opacity: 0.35 }} />
      </a>
    </li>
  );
}

/* ================================================================ */
/* Playbook de riposte                                               */
/* ================================================================ */

export function Playbook() {
  const { ref, inView } = useInView<HTMLDivElement>();
  const [sent, setSent] = useState(false);

  const simulate = () => {
    window.dispatchEvent(new CustomEvent("aegis-refresh"));
    setSent(true);
    setTimeout(() => setSent(false), 2400);
    document.getElementById("flux")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <section id="riposte" className="mx-auto max-w-7xl scroll-mt-24 px-4 py-24 sm:px-6">
      <div ref={ref} className="grid gap-10 lg:grid-cols-5">
        <div className={`reveal ${inView ? "reveal-in" : ""} lg:col-span-2`}>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">PROTOCOLE DE RIPOSTE</p>
          <h2 className="font-display mt-3 text-3xl font-bold leading-tight tracking-tight text-snow sm:text-4xl">
            Quand l'attaque passe,
            <br />
            <span className="text-alert">la réponse est déjà écrite.</span>
          </h2>
          <p className="mt-5 max-w-md text-sm leading-relaxed text-fog">
            Quatre phases, exécutées en moins de deux secondes. L'agent agit d'abord, vous lisez le
            rapport ensuite — chaque décision reste journalisée, explicable et réversible.
          </p>
          <button
            onClick={simulate}
            className={`group mt-8 flex items-center gap-3 border px-6 py-3.5 font-display text-xs font-bold tracking-[0.22em] transition-all duration-300 ${
              sent
                ? "border-pulse/70 bg-pulse/10 text-pulse"
                : "border-alert/60 bg-alert/10 text-alert hover:bg-alert hover:text-ink-950"
            }`}
          >
            {sent ? <IconCheck className="h-4 w-4" /> : <IconBolt className="h-4 w-4 transition-transform group-hover:scale-125" />}
            {sent ? "ACTUALISATION TRANSMISE" : "ACTUALISER LE FLUX RÉEL"}
          </button>
          <p className="mt-3 font-mono text-[10px] tracking-[0.14em] text-fog-dim">
            ▸ Les quatre référentiels publics sont réinterrogés immédiatement.
          </p>
        </div>

        <div className="relative lg:col-span-3">
          <div className="absolute bottom-6 left-[19px] top-6 w-px bg-gradient-to-b from-cyber/60 via-line to-transparent" />
          <ol className="space-y-5">
            {PHASES.map((ph, i) => (
              <PhaseRow key={ph.n} n={ph.n} title={ph.title} desc={ph.desc} detail={ph.detail} index={i} parentIn={inView} />
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}

function PhaseRow({ n, title, desc, detail, index, parentIn }: { n: string; title: string; desc: string; detail: string; index: number; parentIn: boolean }) {
  return (
    <li
      className={`reveal ${parentIn ? "reveal-in" : ""} relative flex gap-5`}
      style={{ transitionDelay: `${index * 140}ms` }}
    >
      <span className="z-10 grid h-10 w-10 shrink-0 place-items-center border border-cyber/50 bg-ink-900 font-display text-xs font-bold text-cyber">
        {n}
      </span>
      <div className="panel group flex-1 p-5 transition-all duration-300 hover:border-cyber/50 sm:p-6">
        <div className="flex items-baseline justify-between gap-4">
          <h3 className="font-display text-base font-bold tracking-wide text-snow">{title.toUpperCase()}</h3>
          <span className="font-display text-2xl font-bold text-ink-600 transition-colors group-hover:text-cyber/30">{n}</span>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-fog">{desc}</p>
        <p className="mt-3 border-t border-line/60 pt-3 font-mono text-[10px] tracking-[0.12em] text-fog-dim">
          ▸ {detail}
        </p>
      </div>
    </li>
  );
}

/* ================================================================ */
/* Icône utilitaire ré-exportée pour la bannière CTA                 */
/* ================================================================ */
export { IconWave };
