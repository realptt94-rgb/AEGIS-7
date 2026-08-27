import { useEffect, useMemo, useReducer } from "react";
import { LIVE_SOURCES, type LiveSourceId } from "../data";
import { hashStr, setPaused, timeAgo, useFeed, type LiveEvent } from "../live";
import { useInView } from "../hooks";
import { IconPause, IconPlay, IconRadar } from "./Icons";

const SEV_HEX = ["#43f08d", "#ffb020", "#ff4d5e"];
const SEV_LABEL = ["FAIBLE", "MOYEN", "CRITIQUE"];
const SRC_HEX: Record<LiveSourceId, string> = {
  THREATFOX: "#38e1ff",
  FEODO: "#ff4d5e",
  URLHAUS: "#ffb020",
  MALWAREBAZAAR: "#b18cff",
};

function SourceCard({ id }: { id: LiveSourceId }) {
  const feed = useFeed();
  const s = feed.sources[id];
  const meta = LIVE_SOURCES[id];
  return (
    <div className="panel relative overflow-hidden p-4">
      <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: SRC_HEX[id], opacity: 0.7 }} />
      <div className="flex items-center justify-between pl-2">
        <h3 className="font-display text-xs font-bold tracking-[0.18em] text-snow">{meta.name.toUpperCase()}</h3>
        <span
          className={`h-2 w-2 rounded-full ${
            s.status === "ok" ? "animate-pulse-dot bg-pulse" : s.status === "loading" ? "animate-pulse bg-warn" : "bg-alert"
          }`}
        />
      </div>
      <p className="mt-1 pl-2 font-mono text-[9px] tracking-[0.14em] text-fog-dim">{meta.org}</p>
      <div className="mt-3 flex items-end justify-between pl-2">
        <span className="font-display text-2xl font-bold tabular-nums text-snow">{s.count}</span>
        <span className="font-mono text-[9px] tracking-[0.12em] text-fog-dim">
          {s.status === "error" ? (
            <span className="text-alert">INJOIGNABLE</span>
          ) : s.status === "loading" ? (
            <span className="text-warn">LECTURE…</span>
          ) : (
            <>
              {s.latency} ms · {s.updated ? timeAgo(s.updated) : "—"}
            </>
          )}
        </span>
      </div>
    </div>
  );
}

function EventRow({ e, index }: { e: LiveEvent; index: number }) {
  const frma = e.country === "FR" || e.country === "MA";
  return (
    <li
      className="animate-row-in group relative flex items-center gap-3 border-b border-line/50 py-2.5 pl-4 pr-3 transition-colors hover:bg-snow/[0.03]"
      style={{ animationDelay: `${Math.min(index, 20) * 30}ms` }}
    >
      <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: SEV_HEX[e.severity], opacity: 0.8 }} />
      <span className="w-14 shrink-0 font-mono text-[9px] tabular-nums text-fog-dim">
        {new Date(e.ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
      </span>
      <span
        className="w-[74px] shrink-0 border px-1.5 py-0.5 text-center font-mono text-[8px] tracking-[0.12em]"
        style={{ borderColor: SRC_HEX[e.source] + "55", color: SRC_HEX[e.source] }}
      >
        {e.source}
      </span>
      <span className="font-display w-32 shrink-0 truncate text-[11px] font-bold tracking-wide text-snow" title={e.malware}>
        {e.malware}
      </span>
      <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fog" title={e.ioc}>
        {e.ioc}
      </span>
      {e.tags.slice(0, 2).map((t) => (
        <span key={t} className="hidden shrink-0 border border-line px-1.5 py-0.5 font-mono text-[8px] text-fog-dim xl:block">
          {t}
        </span>
      ))}
      {frma ? (
        <span className="shrink-0 border border-cyber/60 bg-cyber/10 px-1.5 py-0.5 font-mono text-[8px] font-bold tracking-[0.14em] text-cyber">
          {e.country}
        </span>
      ) : e.country ? (
        <span className="hidden shrink-0 font-mono text-[9px] text-fog-dim sm:block">{e.country}</span>
      ) : null}
      <span className={`hidden shrink-0 font-mono text-[8px] tracking-[0.12em] sm:block`} style={{ color: SEV_HEX[e.severity] }}>
        {SEV_LABEL[e.severity]}
      </span>
    </li>
  );
}

function LiveRadar({ events }: { events: LiveEvent[] }) {
  const blips = useMemo(
    () =>
      events.slice(0, 26).map((e) => {
        const h = hashStr(e.ioc);
        const ang = ((h % 360) * Math.PI) / 180;
        const rad = 20 + ((h >> 4) % 70);
        return {
          x: 100 + Math.cos(ang) * rad,
          y: 100 + Math.sin(ang) * rad,
          sev: e.severity,
          label: `${e.malware} — ${e.ioc.slice(0, 42)}`,
          id: e.id,
        };
      }),
    [events]
  );
  return (
    <svg viewBox="0 0 200 200" className="mx-auto h-full max-h-[260px] w-auto">
      <circle cx="100" cy="100" r="92" fill="none" stroke="#22304d" strokeWidth="1" />
      <circle cx="100" cy="100" r="62" fill="none" stroke="#22304d" strokeWidth="0.8" strokeDasharray="3 4" />
      <circle cx="100" cy="100" r="32" fill="none" stroke="#22304d" strokeWidth="0.8" strokeDasharray="3 4" />
      <line x1="8" y1="100" x2="192" y2="100" stroke="#22304d" strokeWidth="0.6" />
      <line x1="100" y1="8" x2="100" y2="192" stroke="#22304d" strokeWidth="0.6" />
      <g style={{ transformOrigin: "100px 100px", animation: "sweep 4.5s linear infinite" }}>
        <path d="M100 100 L100 8 A92 92 0 0 1 146 16.5 Z" fill="rgba(56,225,255,0.10)" />
        <line x1="100" y1="100" x2="100" y2="8" stroke="#38e1ff" strokeWidth="1.4" />
      </g>
      {blips.map((b) => (
        <g key={b.id}>
          <circle cx={b.x} cy={b.y} r="6" fill="none" stroke={SEV_HEX[b.sev]} strokeWidth="0.7" className="animate-ping" style={{ transformOrigin: `${b.x}px ${b.y}px` }} />
          <circle cx={b.x} cy={b.y} r="2.4" fill={SEV_HEX[b.sev]}>
            <title>{b.label}</title>
          </circle>
        </g>
      ))}
      <circle cx="100" cy="100" r="3" fill="#38e1ff" />
    </svg>
  );
}

export default function LiveOps() {
  const feed = useFeed();
  const { ref, inView } = useInView<HTMLElement>();
  const [, tick] = useReducer((x: number) => x + 1, 0);

  useEffect(() => {
    const t = window.setInterval(tick, 1000);
    return () => window.clearInterval(t);
  }, []);

  const c2 = feed.events.filter((e) => e.source === "FEODO").length;
  const families = new Set(feed.events.map((e) => e.malware)).size;
  const okSources = (Object.keys(feed.sources) as LiveSourceId[]).filter((k) => feed.sources[k].status === "ok").length;
  const frma = feed.events.filter((e) => e.country === "FR" || e.country === "MA").length;

  const topFamilies = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of feed.events) counts.set(e.malware, (counts.get(e.malware) ?? 0) + 1);
    const arr = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = arr[0]?.[1] ?? 1;
    return arr.map(([name, n]) => ({ name, n, w: Math.round((n / max) * 100) }));
  }, [feed.events]);

  return (
    <section id="flux" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 sm:px-6`}>
      {/* En-tête */}
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">FLUX DE RENSEIGNEMENT — DONNÉES RÉELLES</p>
          <h2 className="font-display mt-3 text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            La toile, sous <span className="text-cyber">veille permanente</span>.
          </h2>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-fog">
            Quatre référentiels publics mondiaux alimentent ce mur en continu — aucun événement simulé.
            Les indicateurs liés à la France et au Maroc sont surlignés automatiquement.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            onClick={() => setPaused(!feed.paused)}
            className={`flex items-center gap-2 border px-4 py-2.5 font-display text-[10px] font-bold tracking-[0.2em] transition-all ${
              feed.paused ? "border-warn/60 bg-warn/10 text-warn" : "border-line text-fog hover:border-cyber/60 hover:text-cyber"
            }`}
          >
            {feed.paused ? <IconPlay className="h-3.5 w-3.5" /> : <IconPause className="h-3.5 w-3.5" />}
            {feed.paused ? "REPRENDRE LE FLUX" : "METTRE EN PAUSE"}
          </button>
          <button
            onClick={() => window.dispatchEvent(new CustomEvent("aegis-refresh"))}
            className="clip-tag bg-cyber px-5 py-2.5 font-display text-[10px] font-bold tracking-[0.2em] text-ink-950 transition-all hover:bg-snow"
          >
            ACTUALISER
          </button>
        </div>
      </div>

      {/* État des sources */}
      <div className="mt-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {(Object.keys(LIVE_SOURCES) as LiveSourceId[]).map((id) => (
          <SourceCard key={id} id={id} />
        ))}
      </div>

      {/* Corps principal */}
      <div className="mt-5 grid gap-5 lg:grid-cols-12">
        {/* Journal réel */}
        <div className="panel overflow-hidden lg:col-span-7">
          <div className="flex items-center gap-3 border-b border-line px-5 py-3.5">
            <h3 className="font-display text-xs font-bold tracking-[0.24em] text-snow">JOURNAL DES INDICATEURS</h3>
            <span className="ml-auto font-mono text-[9px] tracking-[0.16em] text-fog-dim">
              {feed.loading ? "LECTURE DES FLUX…" : `MAJ ${feed.lastRefresh ? timeAgo(feed.lastRefresh) : "—"} · AUTO 90 s`}
            </span>
            {feed.paused && <span className="border border-warn/50 bg-warn/10 px-2 py-0.5 font-mono text-[8px] tracking-[0.16em] text-warn">PAUSE</span>}
          </div>
          <ul className="max-h-[520px] overflow-y-auto">
            {feed.events.length === 0 && (
              <li className="px-6 py-16 text-center">
                {feed.loading ? (
                  <span className="font-mono text-xs text-fog-dim">
                    <span className="mr-2 inline-block h-3 w-3 animate-spin rounded-full border border-cyber border-t-transparent align-middle" />
                    Interrogation de ThreatFox, Feodo, URLhaus et MalwareBazaar…
                  </span>
                ) : (
                  <span className="font-mono text-xs text-alert">Flux injoignables — vérifiez la connexion réseau.</span>
                )}
              </li>
            )}
            {feed.events.slice(0, 60).map((e, i) => (
              <EventRow key={e.id} e={e} index={i} />
            ))}
          </ul>
        </div>

        {/* Colonne synthèse */}
        <div className="flex flex-col gap-5 lg:col-span-5">
          <div className="grid grid-cols-2 gap-4">
            <div className="panel p-4">
              <p className="font-display text-2xl font-bold tabular-nums text-snow">{feed.events.length}</p>
              <p className="mt-1 font-mono text-[9px] tracking-[0.18em] text-fog-dim">IOC RÉCENTS EN MÉMOIRE</p>
            </div>
            <div className="panel p-4">
              <p className="font-display text-2xl font-bold tabular-nums text-alert">{c2}</p>
              <p className="mt-1 font-mono text-[9px] tracking-[0.18em] text-fog-dim">C2 BOTNETS (FEODO)</p>
            </div>
            <div className="panel p-4">
              <p className="font-display text-2xl font-bold tabular-nums text-warn">{families}</p>
              <p className="mt-1 font-mono text-[9px] tracking-[0.18em] text-fog-dim">FAMILLES DISTINCTES</p>
            </div>
            <div className="panel p-4">
              <p className="font-display text-2xl font-bold tabular-nums text-cyber">{frma}</p>
              <p className="mt-1 font-mono text-[9px] tracking-[0.18em] text-fog-dim">IOC LIÉS FR / MA</p>
            </div>
          </div>

          {/* Radar réel */}
          <div className="panel relative flex-1 overflow-hidden p-4">
            <div className="flex items-center gap-2.5">
              <IconRadar className="h-4 w-4 text-cyber" />
              <h3 className="font-display text-xs font-bold tracking-[0.24em] text-snow">CARTE DES CONTACTS RÉELS</h3>
              <span className="ml-auto font-mono text-[9px] text-fog-dim">{Math.min(26, feed.events.length)} PLOT{feed.events.length > 1 ? "S" : ""}</span>
            </div>
            <div className="mt-2 h-[260px]">
              <LiveRadar events={feed.events} />
            </div>
          </div>

          {/* Top familles */}
          <div className="panel p-4">
            <h3 className="font-display text-[10px] font-bold tracking-[0.24em] text-fog">FAMILLES LES PLUS ACTIVES</h3>
            <ul className="mt-3 space-y-2">
              {topFamilies.length === 0 && <li className="font-mono text-[10px] text-fog-dim">En attente des flux…</li>}
              {topFamilies.map((f) => (
                <li key={f.name} className="flex items-center gap-3">
                  <span className="font-display w-32 shrink-0 truncate text-[11px] font-bold text-snow">{f.name}</span>
                  <span className="h-2 flex-1 overflow-hidden bg-ink-700">
                    <span className="block h-full bg-gradient-to-r from-cyber to-alert transition-all duration-700" style={{ width: `${f.w}%` }} />
                  </span>
                  <span className="w-8 shrink-0 text-right font-mono text-[10px] tabular-nums text-fog">{f.n}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <p className="mt-4 font-mono text-[9px] tracking-[0.14em] text-fog-dim">
        SOURCES PUBLIQUES : ABUSE.CH (THREATFOX · FEODO TRACKER · URLHAUS · MALWAREBAZAAR) — INDICATEURS TECHNIQUES UNIQUES, USAGE DÉFENSIF.
      </p>
    </section>
  );
}
