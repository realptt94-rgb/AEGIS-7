import Attribution from "./components/Attribution";
import LiveOps from "./components/LiveOps";
import Scanner from "./components/Scanner";
import Swarm from "./components/Swarm";
import { Footer, Ticker, TopBar } from "./components/Chrome";
import { Intel, Modules, Playbook } from "./components/Sections";
import { useInView } from "./hooks";
import { IconShieldCore } from "./components/Icons";

function AmbientBackground() {
  return (
    <>
      {/* Fond de base */}
      <div className="pointer-events-none fixed inset-0 -z-20 bg-[radial-gradient(1200px_700px_at_75%_-10%,#0d2238_0%,#04070d_60%),radial-gradient(900px_600px_at_-10%_110%,#0a1a2c_0%,transparent_55%)]" />
      {/* Grille tactique */}
      <div className="bg-grid-layer pointer-events-none fixed inset-0 -z-10" />
      {/* Halos dérivants */}
      <div className="animate-glow-float pointer-events-none fixed -top-32 right-[-10%] -z-10 h-[480px] w-[480px] rounded-full bg-cyber/[0.07] blur-[110px]" />
      <div
        className="animate-glow-float pointer-events-none fixed bottom-[-15%] left-[-8%] -z-10 h-[420px] w-[420px] rounded-full bg-pulse/[0.05] blur-[110px]"
        style={{ animationDelay: "-7s" }}
      />
      <div className="pointer-events-none fixed inset-0 -z-10 bg-noise" />
      {/* Scanlines CRT au-dessus de tout */}
      <div className="bg-scanlines pointer-events-none fixed inset-0 z-[70]" />
    </>
  );
}

function ClosingBanner() {
  const { ref, inView } = useInView<HTMLDivElement>();
  return (
    <div ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl px-4 sm:px-6`}>
      <div className="panel panel-corner relative overflow-hidden px-6 py-12 text-center sm:px-12 sm:py-16">
        <div className="bg-grid-layer pointer-events-none absolute inset-0" />
        <div className="pointer-events-none absolute -top-24 left-1/2 h-48 w-[420px] -translate-x-1/2 rounded-full bg-cyber/10 blur-[80px]" />
        <div className="relative">
          <span className="mx-auto grid h-14 w-14 place-items-center border border-cyber/50 bg-cyber/10 text-cyber clip-tag">
            <IconShieldCore className="h-7 w-7" />
          </span>
          <h2 className="font-display mx-auto mt-6 max-w-2xl text-3xl font-bold leading-tight tracking-tight text-snow sm:text-4xl">
            Les cybercriminels automatisent leurs attaques.
            <br />
            <span className="text-cyber text-glitch-shadow">De Paris à Casablanca, automatisez la vôtre.</span>
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-sm leading-relaxed text-fog">
            AEGIS-7 concentre actuellement sa veille sur la France et le Maroc : faux sites Ameli,
            CAF et DGI, arnaques OTP Barid Bank, raids sur Telegram. Testez un artefact suspect ou
            interrogez l'essaim — l'agent s'occupe du reste.
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <a
              href="#analyse"
              className="clip-tag bg-cyber px-8 py-3.5 font-display text-xs font-bold tracking-[0.22em] text-ink-950 transition-all duration-300 hover:bg-snow hover:shadow-[0_0_32px_rgba(56,225,255,0.4)]"
            >
              ANALYSER UN ARTEFACT
            </a>
            <a
              href="#flux"
              className="border border-line px-8 py-3.5 font-display text-xs font-bold tracking-[0.22em] text-fog transition-all duration-300 hover:border-cyber/70 hover:text-cyber"
            >
              VOIR LA CONSOLE
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <div className="relative min-h-screen overflow-x-clip text-snow">
      <AmbientBackground />
      <TopBar />
      <main className="relative">
        <div className="h-16" />
        <Ticker />
        <LiveOps />
        <Scanner />
        <Attribution />
        <Swarm />
        <Modules />
        <Intel />
        <Playbook />
        <div className="pb-24">
          <ClosingBanner />
        </div>
      </main>
      <Footer />
    </div>
  );
}
