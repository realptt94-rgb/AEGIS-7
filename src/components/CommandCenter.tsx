import { useEffect, useMemo, useRef, useState } from "react";
import { ACTIONS, ATTACKS, ORIGINS, SEVERITY_META, TARGETS, type Severity } from "../data";
import { IconBolt, IconPause, IconPlay, IconRadar } from "./Icons";

interface Ev {
  id: number;
  time: string;
  kind: "atk" | "rip";
  sev: Severity;
  attack: string;
  target: string;
  ip: string;
  city: string;
  cc: string;
  action: string;
}

interface Blip {
  id: number;
  x: number;
  y: number;
  deg: number;
  dist: number;
  sev: Severity;
}

const LEVELS = [
  {
    name: "VEILLE",
    color: "text-pulse",
    hex: "#43f08d",
    border: "border-pulse/50",
    desc: "Trafic nominal. Surveillance passive, apprentissage continu des modèles.",
    tempo: 2600,
  },
  {
    name: "ÉLEVÉ",
    color: "text-warn",
    hex: "#ffb020",
    border: "border-warn/50",
    desc: "Recrudescence détectée. Honeypots renforcés, double authentification forcée.",
    tempo: 1500,
  },
  {
    name: "CRITIQUE",
    color: "text-alert",
    hex: "#ff4d5e",
    border: "border-alert/50",
    desc: "Attaque coordonnée en cours. Riposte SOAR armée, isolement automatique.",
    tempo: 850,
  },
] as const;

const SEV_HEX: Record<Severity, string> = { 0: "#43f08d", 1: "#ffb020", 2: "#ff4d5e" };

const fmtTime = (d: Date) =>
  [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");

let uid = 0;

function makeAttackEvent(criticalBoost: boolean): Ev {
  const atk = ATTACKS[Math.floor(Math.random() * ATTACKS.length)];
  const org = ORIGINS[Math.floor(Math.random() * ORIGINS.length)];
  const sev: Severity = criticalBoost && Math.random() < 0.45 ? 2 : atk.sev;
  return {
    id: ++uid,
    time: fmtTime(new Date()),
    kind: "atk",
    sev,
    attack: atk.label,
    target: TARGETS[Math.floor(Math.random() * TARGETS.length)],
    ip: org.ip,
    city: org.city,
    cc: org.cc,
    action: ACTIONS[Math.floor(Math.random() * ACTIONS.length)],
  };
}

const RIPOSTE_STEPS = [
  "RIPOSTE // canal C2 coupé — paquets blackholés",
  "RIPOSTE // sessions compromises révoquées (12 jetons)",
  "RIPOSTE // ASN hostile bloqué au pare-feu périmétrique",
  "RIPOSTE // honeypot HP-3 déployé — leurre actif",
  "RIPOSTE // dossier de preuve horodaté — prêt dépôt",
];

export default function CommandCenter() {
  const [level, setLevel] = useState<0 | 1 | 2>(1);
  const [paused, setPaused] = useState(false);
  const [events, setEvents] = useState<Ev[]>(() =>
    Array.from({ length: 7 }, () => makeAttackEvent(false))
  );
  const [blips, setBlips] = useState<Blip[]>([]);
  const [latency, setLatency] = useState(38);
  const scrollRef = useRef<HTMLDivElement>(null);

  const uniqueIps = useMemo(() => new Set(events.map((e) => e.ip)).size, [events]);
  const blocked = events.length;

  /* Flux d'attaques — tempo dicté par le niveau d'alerte */
  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      setEvents((prev) => [...prev.slice(-24), makeAttackEvent(level === 2)]);
    }, LEVELS[level].tempo);
    return () => clearInterval(id);
  }, [paused, level]);

  /* Blips radar */
  useEffect(() => {
    const id = setInterval(() => {
      const angle = Math.random() * Math.PI * 2;
      const r = Math.sqrt(Math.random()) * 138;
      const sevRoll = Math.random();
      const sev: Severity = level === 2 ? (sevRoll < 0.5 ? 2 : sevRoll < 0.8 ? 1 : 0) : sevRoll < 0.22 ? 2 : sevRoll < 0.55 ? 1 : 0;
      const blip: Blip = {
        id: ++uid,
        x: 160 + r * Math.sin(angle),
        y: 160 - r * Math.cos(angle),
        deg: Math.round(((angle * 180) / Math.PI + 360) % 360),
        dist: Math.round((r / 148) * 100),
        sev,
      };
      setBlips((prev) => [...prev.slice(-7), blip]);
      setTimeout(() => setBlips((prev) => prev.filter((b) => b.id !== blip.id)), 4800);
    }, 1700);
    return () => clearInterval(id);
  }, [level]);

  /* Latence de détection — marche aléatoire */
  useEffect(() => {
    const id = setInterval(() => {
      setLatency((v) => Math.max(21, Math.min(96, v + Math.round((Math.random() - 0.48) * 12))));
    }, 2000);
    return () => clearInterval(id);
  }, []);

  /* Écoute des simulations de riposte lancées depuis le playbook */
  useEffect(() => {
    const handler = () => {
      RIPOSTE_STEPS.forEach((step, i) => {
        setTimeout(() => {
          setEvents((prev) => [
            ...prev.slice(-24),
            { ...makeAttackEvent(false), id: ++uid, kind: "rip", attack: step, action: "EXÉCUTÉ", sev: 2, time: fmtTime(new Date()) },
          ]);
        }, i * 420);
      });
    };
    window.addEventListener("aegis-burst", handler);
    return () => window.removeEventListener("aegis-burst", handler);
  }, []);

  /* Auto-scroll du journal */
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events]);

  const lvl = LEVELS[level];

  return (
    <section id="console" className="relative mx-auto max-w-7xl scroll-mt-24 px-4 pt-28 sm:px-6">
      {/* En-tête de commandement */}
      <div className="flex flex-col justify-between gap-8 lg:flex-row lg:items-end">
        <div className="max-w-2xl">
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">
            UNITÉ DE COMMANDEMENT // AEGIS-7
          </p>
          <h1 className="font-display mt-4 text-4xl font-bold leading-[1.04] tracking-tight text-snow sm:text-5xl lg:text-[3.4rem]">
            Le crime ne dort jamais.
            <br />
            <span className="text-cyber text-glitch-shadow">L'agent non plus.</span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-relaxed text-fog">
            Un agent IA autonome qui patrouille vos réseaux 24/7, repère les attaques en
            millisecondes et les neutralise avant tout dégât. Vous supervisez, il encaisse.
          </p>
        </div>

        {/* Sélecteur de niveau d'alerte */}
        <div>
          <p className="mb-2 font-mono text-[10px] tracking-[0.28em] text-fog-dim">CONDITION DE DÉFENSE</p>
          <div className="flex border border-line bg-ink-900/80 p-1">
            {LEVELS.map((l, i) => (
              <button
                key={l.name}
                onClick={() => setLevel(i as 0 | 1 | 2)}
                className={`clip-tag px-4 py-2 font-display text-[11px] font-bold tracking-[0.18em] transition-all duration-300 sm:px-5 ${
                  level === i
                    ? i === 0
                      ? "bg-pulse text-ink-950"
                      : i === 1
                        ? "bg-warn text-ink-950"
                        : "bg-alert text-ink-950"
                    : "text-fog hover:text-snow"
                }`}
              >
                {l.name}
              </button>
            ))}
          </div>
          <p className={`mt-2 max-w-xs font-mono text-[10px] leading-relaxed tracking-wide ${lvl.color}`}>
            ▸ {lvl.desc}
          </p>
        </div>
      </div>

      {/* Grille console + radar */}
      <div className="mt-10 grid gap-5 lg:grid-cols-5">
        {/* ------- Journal de défense ------- */}
        <div className="panel panel-corner flex flex-col lg:col-span-3">
          <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-alert/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-warn/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-pulse/80" />
              </div>
              <h2 className="font-display text-xs font-bold tracking-[0.24em] text-snow">
                JOURNAL DE DÉFENSE <span className="text-fog-dim">— TEMPS RÉEL</span>
              </h2>
            </div>
            <button
              onClick={() => setPaused((p) => !p)}
              className="flex items-center gap-2 border border-line px-3 py-1.5 font-mono text-[10px] tracking-[0.18em] text-fog transition-colors hover:border-cyber/60 hover:text-cyber"
              aria-label={paused ? "Reprendre le flux" : "Mettre en pause"}
            >
              {paused ? <IconPlay className="h-3 w-3" /> : <IconPause className="h-3 w-3" />}
              {paused ? "REPRENDRE" : "PAUSE"}
            </button>
          </div>

          <div ref={scrollRef} className="h-[380px] overflow-y-auto px-2 py-3 font-mono text-xs">
            {events.map((e) =>
              e.kind === "rip" ? (
                <div key={e.id} className="animate-row-in flex items-center gap-3 border-b border-line/40 px-3 py-2 hover:bg-cyber/5">
                  <span className="shrink-0 text-fog-dim tabular-nums">{e.time}</span>
                  <IconBolt className="h-3.5 w-3.5 shrink-0 text-cyber" />
                  <span className="truncate text-cyber">{e.attack}</span>
                  <span className="ml-auto shrink-0 font-bold text-cyber">{e.action}</span>
                </div>
              ) : (
                <div key={e.id} className="animate-row-in group flex items-center gap-3 border-b border-line/40 px-3 py-2 hover:bg-snow/[0.03]">
                  <span className="shrink-0 text-fog-dim tabular-nums">{e.time}</span>
                  <span
                    className={`shrink-0 border px-1.5 py-0.5 text-[9px] font-bold tracking-wider ${SEVERITY_META[e.sev].bg} ${SEVERITY_META[e.sev].color}`}
                  >
                    {SEVERITY_META[e.sev].label}
                  </span>
                  <span className="truncate text-snow/90">
                    {e.attack} <span className="text-fog-dim">→</span>{" "}
                    <span className="text-fog">{e.target}</span>
                  </span>
                  <span className="ml-auto hidden shrink-0 items-center gap-2 sm:flex">
                    <span className="text-fog-dim">
                      {e.ip} <span className="text-fog">[{e.city}]</span>
                    </span>
                    <span className={`font-bold ${SEVERITY_META[e.sev].color}`}>{e.action}</span>
                  </span>
                </div>
              )
            )}
            {!paused && (
              <div className="flex items-center gap-2 px-3 py-2 text-fog-dim">
                <span className="animate-cursor inline-block h-3.5 w-2 bg-cyber" />
                <span className="text-[10px] tracking-[0.2em]">ÉCOUTE ACTIVE…</span>
              </div>
            )}
          </div>

          {/* Compteurs de session */}
          <div className="grid grid-cols-3 divide-x divide-line border-t border-line">
            {[
              { label: "MENACES TRAITÉES", value: String(blocked), cls: "text-snow" },
              { label: "IP HOSTILES", value: String(uniqueIps), cls: lvl.color },
              { label: "LATENCE DÉTECTION", value: `${latency} ms`, cls: "text-cyber" },
            ].map((s) => (
              <div key={s.label} className="px-4 py-3.5">
                <div className={`font-display text-xl font-bold tabular-nums ${s.cls}`}>{s.value}</div>
                <div className="mt-0.5 font-mono text-[9px] tracking-[0.18em] text-fog-dim">{s.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ------- Radar + niveau ------- */}
        <div className="flex flex-col gap-5 lg:col-span-2">
          <div className="panel panel-corner relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
              <h2 className="flex items-center gap-2.5 font-display text-xs font-bold tracking-[0.24em] text-snow">
                <IconRadar className="h-4 w-4 text-cyber" /> BALAYAGE PÉRIMÉTRIQUE — FR + MA
              </h2>
              <span className="font-mono text-[10px] tracking-[0.16em] text-fog-dim">
                {blips.length} CONTACT{blips.length > 1 ? "S" : ""}
              </span>
            </div>

            <div className="relative mx-auto my-4 aspect-square w-[86%] max-w-[320px]">
              <svg viewBox="0 0 320 320" className="h-full w-full">
                <defs>
                  <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stopColor={lvl.hex} stopOpacity="0.28" />
                    <stop offset="100%" stopColor={lvl.hex} stopOpacity="0.02" />
                  </linearGradient>
                </defs>

                {/* Graduation */}
                {Array.from({ length: 36 }, (_, i) => {
                  const a = (i * 10 * Math.PI) / 180;
                  const r1 = i % 9 === 0 ? 138 : 144;
                  return (
                    <line
                      key={i}
                      x1={160 + r1 * Math.sin(a)}
                      y1={160 - r1 * Math.cos(a)}
                      x2={160 + 148 * Math.sin(a)}
                      y2={160 - 148 * Math.cos(a)}
                      stroke="#1a2c47"
                      strokeWidth={i % 9 === 0 ? 1.6 : 1}
                    />
                  );
                })}
                <circle cx="160" cy="160" r="148" fill="none" stroke="#1a2c47" strokeWidth="1.4" />
                <circle cx="160" cy="160" r="99" fill="none" stroke="#142338" strokeDasharray="3 5" />
                <circle cx="160" cy="160" r="50" fill="none" stroke="#142338" strokeDasharray="3 5" />
                <line x1="160" y1="12" x2="160" y2="308" stroke="#142338" strokeWidth="1" />
                <line x1="12" y1="160" x2="308" y2="160" stroke="#142338" strokeWidth="1" />
                <text x="160" y="30" textAnchor="middle" fill="#5c7396" fontSize="9" fontFamily="JetBrains Mono">000</text>
                <text x="296" y="164" textAnchor="end" fill="#5c7396" fontSize="9" fontFamily="JetBrains Mono">090</text>
                <text x="160" y="302" textAnchor="middle" fill="#5c7396" fontSize="9" fontFamily="JetBrains Mono">180</text>
                <text x="24" y="164" textAnchor="start" fill="#5c7396" fontSize="9" fontFamily="JetBrains Mono">270</text>

                {/* Balayage */}
                <g>
                  <path d="M160 160 L160 12 A148 148 0 0 1 288.2 86 Z" fill="url(#sweepGrad)">
                    <animateTransform
                      attributeName="transform"
                      type="rotate"
                      from="0 160 160"
                      to="360 160 160"
                      dur="4.2s"
                      repeatCount="indefinite"
                    />
                  </path>
                  <line x1="160" y1="160" x2="160" y2="12" stroke={lvl.hex} strokeWidth="1.4" opacity="0.8">
                    <animateTransform
                      attributeName="transform"
                      type="rotate"
                      from="0 160 160"
                      to="360 160 160"
                      dur="4.2s"
                      repeatCount="indefinite"
                    />
                  </line>
                </g>

                {/* Contacts */}
                {blips.map((b) => (
                  <g key={b.id}>
                    <circle cx={b.x} cy={b.y} r="3.4" fill={SEV_HEX[b.sev]} />
                    <circle cx={b.x} cy={b.y} r="4" fill="none" stroke={SEV_HEX[b.sev]} strokeWidth="1.2">
                      <animate attributeName="r" from="4" to="16" dur="1.6s" repeatCount="indefinite" />
                      <animate attributeName="opacity" from="0.85" to="0" dur="1.6s" repeatCount="indefinite" />
                    </circle>
                  </g>
                ))}

                <circle cx="160" cy="160" r="4.5" fill={lvl.hex} />
                <circle cx="160" cy="160" r="9" fill="none" stroke={lvl.hex} opacity="0.5" />
              </svg>
            </div>

            {/* Liste des contacts */}
            <div className="border-t border-line px-5 py-3">
              <p className="font-mono text-[9px] tracking-[0.24em] text-fog-dim">DERNIERS CONTACTS</p>
              <div className="mt-2 space-y-1.5">
                {blips.slice(-3).reverse().map((b) => (
                  <div key={b.id} className="animate-row-in flex items-center justify-between font-mono text-[10px]">
                    <span className="flex items-center gap-2">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_HEX[b.sev] }} />
                      <span className="text-fog">
                        GÎTE {String(b.deg).padStart(3, "0")}° · PORTÉE {b.dist} KM
                      </span>
                    </span>
                    <span style={{ color: SEV_HEX[b.sev] }} className="font-bold">
                      {SEVERITY_META[b.sev].label}
                    </span>
                  </div>
                ))}
                {blips.length === 0 && (
                  <p className="font-mono text-[10px] text-fog-dim">Aucun contact — balayage en cours…</p>
                )}
              </div>
            </div>
          </div>

          {/* Jauge de niveau */}
          <div className={`panel border-l-2 px-5 py-4 ${lvl.border}`}>
            <div className="flex items-baseline justify-between">
              <span className="font-mono text-[10px] tracking-[0.24em] text-fog-dim">CONDITION ACTUELLE</span>
              <span className={`font-display text-2xl font-bold tracking-[0.12em] ${lvl.color}`}>{lvl.name}</span>
            </div>
            <div className="mt-3 flex gap-1">
              {LEVELS.map((l, i) => (
                <span
                  key={l.name}
                  className={`h-1.5 flex-1 transition-all duration-500 ${
                    i <= level ? (level === 0 ? "bg-pulse" : level === 1 ? "bg-warn" : "bg-alert") : "bg-ink-700"
                  }`}
                />
              ))}
            </div>
            <p className="mt-3 font-mono text-[10px] leading-relaxed text-fog">
              Tempo de patrouille : <span className="text-snow">{lvl.tempo / 1000} s</span> · Contre-mesures{" "}
              <span className={lvl.color}>{level === 2 ? "ARMÉES" : level === 1 ? "RENFORCÉES" : "STANDARD"}</span>
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
