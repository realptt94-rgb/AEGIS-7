import { useEffect, useState } from "react";
import { LIVE_SOURCES, type LiveSourceId } from "../data";
import { getMaskMode, refreshFeed, setMaskMode, setPaused, timeAgo, useFeed, type LiveEvent } from "../live";
import { maskIoc } from "../sanitize";
import { useInView } from "../hooks";
import { IconCrosshair, IconExternal, IconLock, IconPause, IconPlay, IconRadar, IconWarning } from "./Icons";

const SEV_COLOR = ["text-pulse", "text-warn", "text-alert"];
const SEV_LABEL = ["FAIBLE", "MOYEN", "CRITIQUE"];

const SOURCE_CHIP: Record<LiveSourceId, string> = {
  THREATFOX: "text-cyber border-cyber/50 bg-cyber/10",
  FEODO: "text-alert border-alert/50 bg-alert/10",
  URLHAUS: "text-warn border-warn/50 bg-warn/10",
  MALWAREBAZAAR: "text-[#b18cff] border-[#b18cff]/50 bg-[#b18cff]/10",
  CVE: "text-snow border-line bg-snow/5",
};

const SOURCE_IDS = Object.keys(LIVE_SOURCES) as LiveSourceId[];

/* ------------------------------------------------------------------ */
/* Radar alimenté par les indicateurs réels                            */
/* ------------------------------------------------------------------ */

function RadarPanel({ events }: { events: LiveEvent[] }) {
  const blips = events.slice(0, 12).map((e, i) => ({
    id: e.id,
    x: 20 + (Math.abs(e.ioc.charCodeAt(0) * 7 + e.ioc.length * 13 + i * 37) % 160),
    y: 20 + (Math.abs(e.ioc.charCodeAt(e.ioc.length - 1) * 11 + i * 53) % 160),
    sev: e.severity,
    ioc: e.ioc,
    source: e.source,
  }));
  return (
    <div className="panel panel-corner relative overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
        <h2 className="flex items-center gap-2.5 font-display text-xs font-bold tracking-[0.24em] text-snow">
          <IconRadar className="h-4 w-4 text-cyber" /> BALAYAGE — INDICATEURS RÉELS
        </h2>
        <span className="font-mono text-[10px] tracking-[0.16em] text-fog-dim">
          {blips.length} CONTACT{blips.length > 1 ? "S" : ""}
        </span>
      </div>
      <div className="bg-grid-layer relative aspect-square max-h-[340px] w-full">
        <svg viewBox="0 0 200 200" className="absolute inset-0 h-full w-full">
          {[88, 62, 36].map((r) => (
            <circle key={r} cx="100" cy="100" r={r} fill="none" className="stroke-line" strokeWidth="1" />
          ))}
          <line x1="100" y1="12" x2="100" y2="188" className="stroke-line" strokeWidth="0.6" />
          <line x1="12" y1="100" x2="188" y2="100" className="stroke-line" strokeWidth="0.6" />
          <g className="animate-sweep" style={{ transformOrigin: "100px 100px" }}>
            <line x1="100" y1="100" x2="100" y2="14" stroke="#38e1ff" strokeWidth="1.4" opacity="0.9" />
            <path d="M100 100 L100 14 A86 86 0 0 1 143 26 Z" fill="#38e1ff" opacity="0.07" />
          </g>
          <circle cx="100" cy="100" r="2.5" fill="#38e1ff" />
          {blips.map((b) => (
            <g key={b.id}>
              <circle cx={b.x} cy={b.y} r="3" fill="none" className={SEV_COLOR[b.sev]} strokeWidth="1" opacity="0.85">
                <animate attributeName="r" values="3;9" dur="1.8s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.85;0" dur="1.8s" repeatCount="indefinite" />
              </circle>
              <circle cx={b.x} cy={b.y} r="2.2" className={b.sev === 2 ? "fill-alert" : b.sev === 1 ? "fill-warn" : "fill-pulse"} />
            </g>
          ))}
        </svg>
      </div>
      <div className="flex items-center justify-between border-t border-line px-5 py-3">
        <div className="flex gap-4 font-mono text-[9px] tracking-[0.16em] text-fog-dim">
          <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-pulse" />FAIBLE</span>
          <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-warn" />MOYEN</span>
          <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-alert" />CRITIQUE</span>
        </div>
        <span className="font-mono text-[9px] tracking-[0.16em] text-cyber">FLUX abuse.ch + CIRCL/NVD</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section                                                             */
/* ------------------------------------------------------------------ */

export default function LiveOps() {
  const feed = useFeed();
  const { ref, inView } = useInView<HTMLElement>();
  const [, setTick] = useState(0);

  useEffect(() => {
    const t = window.setInterval(() => setTick((v) => v + 1), 1000);
    return () => window.clearInterval(t);
  }, []);

  const nextIn = feed.lastRefresh ? Math.max(0, Math.round((feed.lastRefresh + 90_000 - Date.now()) / 1000)) : 0;
  const okCount = SOURCE_IDS.filter((s) => feed.sources[s].status === "ok").length;
  const allDead = !feed.loading && okCount === 0;
  const fams = [...new Map(feed.events.map((e) => [e.malware, e])).values()].slice(0, 6);

  return (
    <section id="flux" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-10 sm:px-6`}>
      {/* En-tête */}
      <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">SURVEILLANCE TOTALE — DONNÉES RÉELLES</p>
          <h2 className="font-display mt-3 text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Le web, <span className="text-cyber">écouté en direct</span>.
          </h2>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-fog">
            Cinq référentiels publics interrogés en continu : indicateurs de compromission, infrastructures de
            commande, URLs malveillantes, échantillons et vulnérabilités fraîchement publiées.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="border border-line bg-ink-900/70 px-3 py-2 text-right">
            <p className={`font-display text-[11px] font-bold tracking-[0.18em] ${okCount > 0 ? "text-pulse" : "text-alert"}`}>
              {okCount}/{SOURCE_IDS.length} RÉFÉRENTIELS EN LIGNE
            </p>
            <p className="mt-0.5 font-mono text-[9px] tracking-[0.14em] text-fog-dim">
              {feed.paused ? "FLUX EN PAUSE" : feed.lastRefresh ? `PROCHAINE ACTUALISATION : ${nextIn} s` : "CONNEXION…"}
            </p>
          </div>
          <button
            onClick={() => setPaused(!feed.paused)}
            className="grid h-10 w-10 place-items-center border border-line text-fog transition-colors hover:border-cyber/60 hover:text-cyber"
            title={feed.paused ? "Reprendre" : "Pause"}
          >
            {feed.paused ? <IconPlay className="h-4 w-4" /> : <IconPause className="h-4 w-4" />}
          </button>
          <button
            onClick={() => setMaskMode(!getMaskMode())}
            className={`flex h-10 items-center gap-2 border px-3.5 font-display text-[10px] font-bold tracking-[0.16em] transition-all ${
              getMaskMode()
                ? "border-warn/70 bg-warn/15 text-warn shadow-[0_0_16px_rgba(255,176,32,0.2)]"
                : "border-line text-fog hover:border-warn/60 hover:text-warn"
            }`}
            title="Pare-feu cognitif — masquer IP, ports et DNS du flux"
          >
            <IconLock className="h-3.5 w-3.5" />
            {getMaskMode() ? "MASQUÉ" : "MASQUER"}
          </button>
          <button
            onClick={() => { setPaused(false); refreshFeed(); }}
            className="clip-tag flex h-10 items-center gap-2 bg-cyber px-4 font-display text-[10px] font-bold tracking-[0.18em] text-ink-950 transition-all hover:bg-snow"
          >
            <IconRadar className={`h-3.5 w-3.5 ${feed.loading ? "animate-spin" : ""}`} />
            RÉESSAYER
          </button>
        </div>
      </div>

      {/* Cartes de sources */}
      <div className="mt-8 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        {SOURCE_IDS.map((id) => {
          const st = feed.sources[id];
          const meta = LIVE_SOURCES[id];
          return (
            <div key={id} className={`panel p-3.5 transition-all duration-300 ${st.status === "ok" ? "hover:border-cyber/50" : ""}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-display text-[10px] font-bold tracking-[0.16em] text-snow">{meta.name.toUpperCase()}</span>
                {st.status === "loading" ? (
                  <span className="shrink-0 border border-warn/50 bg-warn/10 px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] text-warn">
                    CONNEXION…
                  </span>
                ) : st.status === "ok" ? (
                  <span className="flex shrink-0 items-center gap-1 border border-pulse/50 bg-pulse/10 px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] text-pulse">
                    <span className="h-1 w-1 animate-pulse-dot rounded-full bg-pulse" /> EN LIGNE
                  </span>
                ) : (
                  <span className="shrink-0 border border-alert/50 bg-alert/10 px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] text-alert">
                    INJOIGNABLE
                  </span>
                )}
              </div>
              <p className="mt-1.5 truncate font-mono text-[9px] tracking-[0.08em] text-fog-dim" title={meta.org}>{meta.org}</p>
              <div className="mt-2.5 flex items-center gap-2 border-t border-line/60 pt-2 font-mono text-[9px] tracking-[0.1em]">
                <span className={st.status === "ok" ? "text-cyber" : "text-fog-dim"}>{st.count} IOC</span>
                <span className="text-fog-dim">·</span>
                <span className="text-fog-dim">{st.latency !== null ? `${st.latency} ms` : "—"}</span>
                {st.updated && <span className="ml-auto text-fog-dim">{timeAgo(st.updated)}</span>}
              </div>
              {st.status === "error" && (
                <p className="mt-1.5 truncate font-mono text-[8px] tracking-[0.08em] text-alert/80" title={st.error}>
                  ✕ {st.error ?? "erreur inconnue"}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {/* Exposition du visiteur */}
      <div className="panel mt-5 flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:gap-6 sm:px-5">
        <div className="flex items-center gap-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center border border-cyber/40 text-cyber">
            <IconCrosshair className="h-4 w-4" />
          </span>
          <p className="font-display text-[10px] font-bold tracking-[0.24em] text-snow">VOTRE EXPOSITION</p>
        </div>
        {feed.exposure ? (
          <div className="flex flex-1 flex-wrap items-center gap-x-6 gap-y-1 font-mono text-[11px]">
            <span className="text-snow">
              <span className="text-fog-dim">IP publique : </span>
              <span className="text-cyber">{getMaskMode() ? maskIoc(feed.exposure.ip) : feed.exposure.ip}</span>
            </span>
            <span className="text-fog">
              {feed.exposure.flag ?? ""} {feed.exposure.city ?? "?"}, {feed.exposure.country ?? "?"}
            </span>
            <span className="text-fog">
              <span className="text-fog-dim">ASN </span>
              {feed.exposure.asn ?? "?"} · {feed.exposure.org ?? "?"}
            </span>
            <span className={`ml-auto border px-2 py-1 text-[9px] tracking-[0.14em] ${feed.exposure.listed ? "border-alert/60 bg-alert/10 text-alert" : "border-pulse/60 bg-pulse/10 text-pulse"}`}>
              {feed.exposure.listed ? "RÉPERTORIÉE FEODO — COUPER" : "ABSENTE DES LISTES DE BLOCAGE"}
            </span>
          </div>
        ) : (
          <p className="flex-1 font-mono text-[10px] tracking-[0.1em] text-fog-dim">
            {feed.exposureError ? `Sonde injoignable — ${feed.exposureError}` : "Mesure de votre adresse publique en cours…"}
          </p>
        )}
      </div>

      {/* Diagnostic honnête si tout échoue */}
      {allDead && (
        <div className="panel mt-5 border-alert/50 p-6">
          <div className="flex items-center gap-3">
            <IconWarning className="h-6 w-6 text-alert" />
            <h3 className="font-display text-sm font-bold tracking-[0.22em] text-alert">RÉSEAU EXTERNE INJOIGNABLE DEPUIS CET ENVIRONNEMENT</h3>
          </div>
          <p className="mt-3 max-w-3xl text-sm leading-relaxed text-fog">
            Aucun des cinq référentiels ne répond. Causes probables : environnement de prévisualisation sans accès
            Internet, proxy ou pare-feu interceptant les requêtes, DNS filtré. Le système ne fabrique aucune donnée —
            il attend une connexion réelle. Testez ces points d'accès directement, puis relancez :
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {[
              ["Feodo (GET)", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"],
              ["Google DoH", "https://dns.google/resolve?name=example.com&type=A"],
              ["ipify", "https://api.ipify.org?format=json"],
              ["CIRCL CVE", "https://cve.circl.lu/api/last/5"],
            ].map(([label, url]) => (
              <a
                key={url}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 border border-line bg-ink-950/50 px-3 py-2 font-mono text-[10px] text-fog transition-colors hover:border-cyber/60 hover:text-cyber"
              >
                <IconExternal className="h-3 w-3" /> {label}
              </a>
            ))}
          </div>
          <button
            onClick={() => refreshFeed()}
            className="clip-tag mt-5 bg-alert px-6 py-3 font-display text-[11px] font-bold tracking-[0.22em] text-ink-950 transition-all hover:bg-snow"
          >
            RELANCER LA CONNEXION
          </button>
        </div>
      )}

      {/* Radar + journal */}
      {!allDead && (
        <>
          <div className="mt-5 grid gap-5 lg:grid-cols-12">
            <div className="lg:col-span-5">
              <RadarPanel events={feed.events} />
            </div>
            <div className="panel flex flex-col overflow-hidden lg:col-span-7">
              <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
                <h2 className="font-display text-xs font-bold tracking-[0.24em] text-snow">JOURNAL DES INDICATEURS RÉELS</h2>
                <span className="font-mono text-[10px] tracking-[0.16em] text-fog-dim">{feed.events.length} INDICATEURS</span>
              </div>
              <div className="max-h-[430px] flex-1 overflow-y-auto">
                {feed.loading && feed.events.length === 0 ? (
                  <div className="flex h-40 items-center justify-center">
                    <span className="h-5 w-5 animate-spin rounded-full border border-cyber border-t-transparent" />
                    <span className="ml-3 font-mono text-[11px] tracking-[0.16em] text-fog-dim">INTERROGATION DES RÉFÉRENTIELS…</span>
                  </div>
                ) : (
                  <ul className="divide-y divide-line/60">
                    {feed.events.slice(0, 60).map((e) => (
                      <li key={e.id} className="animate-row-in flex items-center gap-3 px-5 py-2.5 transition-colors hover:bg-snow/[0.03]">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${e.severity === 2 ? "bg-alert" : e.severity === 1 ? "bg-warn" : "bg-pulse"}`} />
                        <span className="w-24 shrink-0 font-mono text-[9px] tracking-[0.08em] text-fog-dim">
                          {new Date(e.ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                        </span>
                        <span className={`w-24 shrink-0 truncate border px-1.5 py-0.5 text-center font-mono text-[8px] tracking-[0.1em] ${SOURCE_CHIP[e.source]}`}>
                          {e.source}
                        </span>
                        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-snow" title={getMaskMode() ? "masqué par le pare-feu cognitif" : e.ioc}>
                          {getMaskMode() ? maskIoc(e.ioc) : e.ioc}
                        </span>
                        <span className="hidden w-28 shrink-0 truncate font-mono text-[10px] text-fog sm:block" title={e.malware}>
                          {e.malware}
                        </span>
                        <span className={`shrink-0 font-mono text-[9px] tracking-[0.1em] ${SEV_COLOR[e.severity]}`}>{SEV_LABEL[e.severity]}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="border-t border-line px-5 py-2.5 font-mono text-[9px] tracking-[0.12em] text-fog-dim">
                FLUX PUBLICS abuse.ch + CIRCL/NVD · Rafraîchissement automatique toutes les 90 s
              </div>
            </div>
          </div>

          {fams.length > 0 && (
            <div className="mt-5 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[9px] tracking-[0.22em] text-fog-dim">FAMILLES ACTIVES DANS LE FLUX :</span>
              {fams.map((f) => (
                <span key={f.ioc} className="border border-line bg-ink-900/60 px-2.5 py-1 font-mono text-[10px] text-cyber">
                  {f.malware}
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}
