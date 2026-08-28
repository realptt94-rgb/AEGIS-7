import { useEffect, useState } from "react";
import { TICKER_ITEMS } from "../data";
import { useFeed } from "../live";
import { IconShieldCore } from "./Icons";

const NAV = [
  { href: "#flux", label: "Flux réel" },
  { href: "#analyse", label: "Analyse" },
  { href: "#attribution", label: "Attribution" },
  { href: "#essaim", label: "Essaim IA" },
  { href: "#mem0", label: "Mem0 ×45" },
  { href: "#modules", label: "Modules" },
  { href: "#riposte", label: "Riposte" },
];

function useUptime() {
  const [s, setS] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setS((v) => v + 1), 1000);
    return () => clearInterval(id);
  }, []);
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const sec = String(s % 60).padStart(2, "0");
  return `${h}:${m}:${sec}`;
}

export function TopBar() {
  const uptime = useUptime();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-40 border-b transition-colors duration-300 ${
        scrolled ? "border-line bg-ink-950/85 backdrop-blur-md" : "border-transparent bg-transparent"
      }`}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
        <a href="#console" className="group flex items-center gap-3">
          <span className="relative grid h-9 w-9 place-items-center border border-cyber/40 bg-cyber/10 text-cyber clip-tag">
            <IconShieldCore className="h-5 w-5" />
            <span className="absolute inset-0 bg-cyber/0 transition-colors duration-300 group-hover:bg-cyber/10" />
          </span>
          <span className="leading-none">
            <span className="font-display text-lg font-bold tracking-[0.18em] text-snow">
              AEGIS<span className="text-cyber">-7</span>
            </span>
            <span className="mt-1 block font-mono text-[9px] tracking-[0.32em] text-fog">
              AGENT IA ANTI-HACKER
            </span>
          </span>
        </a>

        <nav className="hidden items-center gap-1 lg:flex">
          {NAV.map((n) => (
            <a
              key={n.href}
              href={n.href}
              className="group relative px-3 py-2 font-display text-[11px] font-semibold tracking-[0.22em] text-fog transition-colors hover:text-snow"
            >
              {n.label.toUpperCase()}
              <span className="absolute inset-x-3 bottom-1 h-px scale-x-0 bg-cyber transition-transform duration-300 group-hover:scale-x-100" />
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-4">
          <div className="hidden items-center gap-2 sm:flex">
            <span className="h-2 w-2 rounded-full bg-pulse animate-pulse-dot" />
            <span className="font-mono text-[10px] tracking-[0.2em] text-pulse">EN LIGNE</span>
          </div>
          <span className="hidden border border-cyber/40 bg-cyber/10 px-2 py-1 font-mono text-[9px] tracking-[0.2em] text-cyber md:block">
            FR + MA · MODE RÉEL 100%
          </span>
          <div className="hidden text-right md:block">
            <div className="font-mono text-xs text-snow tabular-nums">{uptime}</div>
            <div className="font-mono text-[9px] tracking-[0.18em] text-fog-dim">UPTIME SESSION</div>
          </div>
          <div className="hidden border-l border-line pl-4 lg:block">
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-16 overflow-hidden rounded-full bg-ink-700">
                <div className="h-full w-[99%] rounded-full bg-gradient-to-r from-cyber to-pulse" />
              </div>
              <span className="font-mono text-[10px] text-pulse">99,7%</span>
            </div>
            <div className="mt-1 font-mono text-[9px] tracking-[0.18em] text-fog-dim">INTÉGRITÉ BOUCLIER</div>
          </div>
        </div>
      </div>
    </header>
  );
}

export function Ticker() {
  const feed = useFeed();
  const items = feed.events.length
    ? feed.events.slice(0, 14).map((e) => `${e.malware.toUpperCase()} · ${e.ioc.length > 44 ? e.ioc.slice(0, 44) + "…" : e.ioc} [${e.source}]`)
    : TICKER_ITEMS;
  const row = (key: string) => (
    <div key={key} className="flex shrink-0 items-center">
      {items.map((item, i) => (
        <span key={i} className="flex items-center font-mono text-[11px] text-fog">
          <span className="px-5 whitespace-nowrap">{item}</span>
          <svg viewBox="0 0 8 8" className="h-1.5 w-1.5 text-cyber/70" fill="currentColor">
            <path d="M4 0l4 4-4 4-4-4z" />
          </svg>
        </span>
      ))}
    </div>
  );

  return (
    <div className="relative overflow-hidden border-y border-line bg-ink-900/80">
      <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-20 bg-gradient-to-r from-ink-950 to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-20 bg-gradient-to-l from-ink-950 to-transparent" />
      <div className="animate-ticker flex w-max py-2">
        {row("a")}
        {row("b")}
      </div>
    </div>
  );
}

export function Footer() {
  return (
    <footer className="relative border-t border-line bg-ink-900/70">
      <div className="mx-auto grid max-w-7xl gap-10 px-4 py-14 sm:px-6 md:grid-cols-3">
        <div>
          <div className="flex items-center gap-3">
            <span className="grid h-8 w-8 place-items-center border border-cyber/40 bg-cyber/10 text-cyber clip-tag">
              <IconShieldCore className="h-4 w-4" />
            </span>
            <span className="font-display text-base font-bold tracking-[0.18em] text-snow">
              AEGIS<span className="text-cyber">-7</span>
            </span>
          </div>
          <p className="mt-4 max-w-xs text-sm leading-relaxed text-fog">
            Agent autonome de cyberdéfense : détecte, isole et neutralise les attaques avant qu'elles
            n'atteignent vos systèmes. La chasse aux cybercriminels, industrialisée.
          </p>
        </div>

        <div>
          <h4 className="font-display text-[11px] font-bold tracking-[0.28em] text-fog-dim">SECTIONS</h4>
          <ul className="mt-4 space-y-2.5">
            {NAV.map((n) => (
              <li key={n.href}>
                <a
                  href={n.href}
                  className="group inline-flex items-center gap-2 font-mono text-xs text-fog transition-colors hover:text-cyber"
                >
                  <span className="h-px w-3 bg-line transition-all group-hover:w-5 group-hover:bg-cyber" />
                  {n.label.toUpperCase()}
                </a>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h4 className="font-display text-[11px] font-bold tracking-[0.28em] text-fog-dim">MENTIONS</h4>
          <p className="mt-4 text-xs leading-relaxed text-fog-dim">
            Démonstration interactive — les événements, adresses IP et statistiques affichés sont
            simulés localement dans votre navigateur. Aucune donnée réelle n'est collectée ni
            transmise. Flux de renseignement inspirés de dépôts open source (Telegram OSINT, projet
            Tor, bases Red Team, cadres IA défensifs).
          </p>
          <p className="mt-4 font-mono text-[10px] tracking-[0.14em] text-fog-dim">
            EN CAS D'ATTAQUE RÉELLE : CONTACTEZ CERT-FR — WWW.CERT.SSI.GOUV.FR
          </p>
        </div>
      </div>
      <div className="border-t border-line/60">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-2 px-4 py-5 font-mono text-[10px] tracking-[0.16em] text-fog-dim sm:flex-row sm:px-6">
          <span>AEGIS-7 © 2026 — UNITÉ DE CYBERDÉFENSE AUTONOME</span>
          <span className="text-cyber/70">BOUCLIER ACTIF // AUCUNE INTRUSION TOLÉRÉE</span>
        </div>
      </div>
    </footer>
  );
}
