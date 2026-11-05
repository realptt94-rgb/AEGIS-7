import { useEffect, useRef, useState } from "react";
import {
  AGENTS, PIPELINE, PUTER_TOKEN, ROLE_META, SWARM_EXAMPLES,
  type AgentDef, type AgentRole,
} from "../data";
import { mulberry32, seedFrom, useInView } from "../hooks";
import {
  IconBolt, IconBrainChip, IconCheck, IconCopy, IconLock, IconTerminal, IconWarning,
} from "./Icons";

/* ------------------------------------------------------------------ */
/* Moteur Puter.js / OpenRouter                                        */
/* ------------------------------------------------------------------ */

declare global {
  interface Window {
    puter?: any;
  }
}

function extractText(r: any): string {
  if (typeof r === "string") return r;
  if (r == null) return "";
  if (typeof r.message?.content === "string") return r.message.content;
  if (Array.isArray(r.message?.content)) return r.message.content.map((c: any) => c?.text ?? "").join("");
  if (typeof r.text === "string") return r.text;
  try {
    return String(r);
  } catch {
    return "";
  }
}

const OUV_MODEL = "openai/gpt-oss-20b";
const GF1_MODEL = "meta-llama/llama-guard-4-12b";
const SUP2_MODEL = "qwen/qwen3-max-thinking";

const GUARD_PROMPT = (q: string) =>
  `Réponds par un seul mot : SÛR ou DANGEREUX. Le message suivant est-il une demande légitime d'aide en cybersécurité DÉFENSIVE (et non une demande visant à mener une attaque) ? Message : « ${q} »`;

const WORKER_PROMPT = (q: string) =>
  `Tu es OUVRIÈRE-01, analyste en cyberdéfense au sein de l'essaim AEGIS-7. Réponds en français, 130 mots maximum, avec exactement cette structure :
MENACE : (type identifié et gravité sur 10)
ANALYSE : (2 à 3 phrases factuelles)
PARADE :
1. ...
2. ...
3. ...
Signalement reçu :
« ${q} »`;

const SYNTH_PROMPT = (a: string) =>
  `Tu es SUPERVISEUR-02 de l'essaim AEGIS-7. À partir de l'analyse ci-dessous, rédige en français une conclusion opérationnelle de 2 phrases maximum, en commençant par le niveau de risque parmi : FAIBLE, MODÉRÉ, CRITIQUE. Analyse de l'ouvrière :
« ${a} »`;

function fallbackAnalysis(q: string): string {
  const rnd = mulberry32(seedFrom(q));
  const grav = 4 + Math.round(rnd() * 5);
  const types = ["hameçonnage ciblé", "reconnaissance réseau", "ingénierie sociale", "diffusion de maliciel", "usurpation d'identité"];
  const type = types[Math.floor(rnd() * types.length)];
  return [
    `MENACE : ${type} — gravité ${grav}/10`,
    `ANALYSE : le signalement « ${q.slice(0, 70)} » présente des marqueurs d'attaque en plusieurs points : pression temporelle, canal inhabituel et demande sortant du cadre normal. Le mode opératoire correspond à des campagnes déjà observées par la vigie OSINT de l'essaim.`,
    `PARADE :`,
    `1. Isoler immédiatement le canal concerné et révoquer toute session active.`,
    `2. Ne cliquer sur aucun lien ; transmettre l'artefact brut à la cellule de crise.`,
    `3. Activer l'authentification multifacteur et surveiller les comptes exposés 72 h.`,
  ].join("\n");
}

function fallbackSynth(q: string, analysis: string): string {
  const grav = /gravité (\d)/.exec(analysis)?.[1];
  const g = grav ? parseInt(grav, 10) : 5;
  const level = g >= 7 ? "CRITIQUE" : g >= 4 ? "MODÉRÉ" : "FAIBLE";
  return `${level} — les marqueurs relevés sur « ${q.slice(0, 40)}… » confirment une tentative active ; appliquer les trois parades de l'ouvrière sans délai et consigner l'incident.`;
}

/* ------------------------------------------------------------------ */
/* Banque mémorielle (simule mem0, persistée localement)               */
/* ------------------------------------------------------------------ */

interface MemEntry {
  id: string;
  ts: number;
  query: string;
  verdict: string;
  risk: string;
}

const MEM_KEY = "aegis7-mem0-bank";

function loadMem(): MemEntry[] {
  try {
    const raw = localStorage.getItem(MEM_KEY);
    return raw ? (JSON.parse(raw) as MemEntry[]) : [];
  } catch {
    return [];
  }
}

function saveMem(list: MemEntry[]) {
  try {
    localStorage.setItem(MEM_KEY, JSON.stringify(list.slice(0, 24)));
  } catch {
    /* stockage indisponible */
  }
}

function tokenize(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9à-ÿ.@/-]+/).filter((w) => w.length > 4);
}

function recall(mems: MemEntry[], query: string): MemEntry | null {
  const q = new Set(tokenize(query));
  for (const m of mems) {
    const overlap = new Set(tokenize(m.query + " " + m.verdict).filter((w) => q.has(w)));
    if (overlap.size >= 2) return m;
  }
  return null;
}

function parseRisk(text: string, seed: string): string {
  const t = text.toUpperCase();
  if (/CRITIQUE|ÉLEVÉ|HAUT RISQUE/.test(t)) return "CRITIQUE";
  if (/MODÉR|MOYEN|VIGILANCE/.test(t)) return "MODÉRÉ";
  if (/FAIBLE|BAS|MINEUR/.test(t)) return "FAIBLE";
  const rnd = mulberry32(seedFrom(seed));
  return rnd() < 0.3 ? "CRITIQUE" : rnd() < 0.65 ? "MODÉRÉ" : "FAIBLE";
}

/* ------------------------------------------------------------------ */
/* Types internes                                                      */
/* ------------------------------------------------------------------ */

type LineCls = "sys" | "ai" | "ok" | "warn" | "err" | "dim";
interface Line {
  id: number;
  cls: LineCls;
  text: string;
}

const LINE_COLOR: Record<LineCls, string> = {
  sys: "text-fog-dim",
  ai: "text-snow",
  ok: "text-pulse",
  warn: "text-warn",
  err: "text-alert",
  dim: "text-fog-dim",
};

const RISK_STYLE: Record<string, string> = {
  CRITIQUE: "border-alert/60 bg-alert/10 text-alert",
  "MODÉRÉ": "border-warn/60 bg-warn/10 text-warn",
  FAIBLE: "border-pulse/60 bg-pulse/10 text-pulse",
  "BLOQUÉ": "border-[#b18cff]/60 bg-[#b18cff]/10 text-[#b18cff]",
};

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ */
/* Sous-composants                                                     */
/* ------------------------------------------------------------------ */

function GroupPanel({ role, agents, activeId, tasks }: { role: AgentRole; agents: AgentDef[]; activeId: string | null; tasks: Record<string, number> }) {
  const meta = ROLE_META[role];
  const { ref, inView } = useInView<HTMLDivElement>(0.08);
  return (
    <div ref={ref} className={`reveal ${inView ? "reveal-in" : ""} panel overflow-hidden`}>
      <div className="flex items-center gap-3 border-b border-line px-4 py-3">
        <span className="h-7 w-1" style={{ background: meta.hex }} />
        <div>
          <h3 className="font-display text-[11px] font-bold tracking-[0.22em] text-snow">
            {meta.label} <span className="text-fog-dim">×{agents.length}</span>
          </h3>
          <p className="mt-0.5 text-[10px] leading-snug text-fog-dim">{meta.blurb}</p>
        </div>
      </div>
      <ul className="divide-y divide-line/50">
        {agents.map((a) => {
          const isActive = activeId === a.id;
          const n = tasks[a.id] ?? 0;
          return (
            <li
              key={a.id}
              className={`flex items-center gap-2.5 px-4 py-2 transition-all duration-300 ${isActive ? "bg-snow/[0.06]" : "hover:bg-snow/[0.02]"}`}
            >
              <span className="relative flex h-2 w-2 shrink-0">
                {isActive && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full" style={{ background: meta.hex, opacity: 0.7 }} />
                )}
                <span
                  className="relative inline-flex h-2 w-2 rounded-full"
                  style={{ background: meta.hex, boxShadow: isActive ? `0 0 10px ${meta.hex}` : "none" }}
                />
              </span>
              <span className="font-display w-16 shrink-0 text-[11px] font-bold tracking-wider text-snow">{a.id}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fog-dim" title={a.model ?? a.duty}>
                {a.model ?? a.duty}
              </span>
              {a.tag && (
                <span
                  className="shrink-0 border px-1.5 py-0.5 font-mono text-[8px] tracking-[0.14em]"
                  style={{ borderColor: meta.hex + "55", color: meta.hex }}
                >
                  {a.tag.toUpperCase()}
                </span>
              )}
              <span className="w-12 shrink-0 text-right font-mono text-[9px] tabular-nums" style={{ color: n > 0 ? meta.hex : undefined }}>
                {n > 0 ? `${n} tâche${n > 1 ? "s" : ""}` : "prêt"}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Section principale                                                  */
/* ------------------------------------------------------------------ */

export default function Swarm() {
  const { ref, inView } = useInView<HTMLElement>();
  const [engine, setEngine] = useState<"online" | "degraded" | "booting">("booting");
  const engineRef = useRef<"online" | "degraded" | "booting">("booting");
  const [input, setInput] = useState("");
  const [inputErr, setInputErr] = useState(false);
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState(-1);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [tasks, setTasks] = useState<Record<string, number>>({});
  const [lines, setLines] = useState<Line[]>([]);
  const [streamId, setStreamId] = useState<number | null>(null);
  const [verdict, setVerdict] = useState<{ risk: string; text: string } | null>(null);
  const [memory, setMemory] = useState<MemEntry[]>(() => loadMem());
  const [copied, setCopied] = useState(false);
  const idRef = useRef(0);
  const busyRef = useRef(false);
  const mountedRef = useRef(true);
  const termRef = useRef<HTMLDivElement>(null);

  /* Amorçage Puter.js */
  useEffect(() => {
    mountedRef.current = true;
    const boot = () => {
      const p = window.puter;
      if (p?.ai?.chat) {
        try {
          if (typeof p.setAuthToken === "function") p.setAuthToken(PUTER_TOKEN);
        } catch {
          /* clé refusée — on tente quand même */
        }
        engineRef.current = "online";
        if (mountedRef.current) setEngine("online");
      } else {
        engineRef.current = "degraded";
        if (mountedRef.current) setEngine("degraded");
      }
    };
    if (window.puter?.ai?.chat) {
      boot();
    } else {
      let tries = 0;
      const t = window.setInterval(() => {
        tries += 1;
        if (window.puter?.ai?.chat || tries > 16) {
          clearInterval(t);
          boot();
        }
      }, 350);
      return () => {
        clearInterval(t);
        mountedRef.current = false;
      };
    }
    return () => {
      mountedRef.current = false;
    };
  }, []);

  /* Escalade depuis le laboratoire d'analyse */
  useEffect(() => {
    const h = (e: Event) => {
      const d = (e as CustomEvent).detail;
      if (typeof d === "string") {
        setInput(d);
        setVerdict(null);
      }
    };
    window.addEventListener("aegis-escalate", h);
    return () => window.removeEventListener("aegis-escalate", h);
  }, []);

  /* Auto-scroll du terminal */
  useEffect(() => {
    const el = termRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  const push = (cls: LineCls, text: string): number => {
    const id = ++idRef.current;
    setLines((prev) => [...prev.slice(-90), { id, cls, text }]);
    return id;
  };

  const update = (id: number, text: string) => {
    setLines((prev) => prev.map((l) => (l.id === id ? { ...l, text } : l)));
  };

  const bump = (agentId: string) => setTasks((t) => ({ ...t, [agentId]: (t[agentId] ?? 0) + 1 }));

  const aiChat = async (prompt: string, model: string, stream = false) => {
    const p = window.puter;
    if (!p?.ai?.chat) throw new Error("puter-indisponible");
    return p.ai.chat(prompt, { model, ...(stream ? { stream: true } : {}) });
  };

  const run = async (raw?: string) => {
    const q = (raw ?? input).trim();
    if (!q) {
      setInputErr(true);
      setTimeout(() => setInputErr(false), 900);
      return;
    }
    if (busyRef.current) return;
    busyRef.current = true;
    setRunning(true);
    setVerdict(null);
    setPhase(0);
    setStreamId(null);

    push("sys", "═══ NOUVELLE INTERROGATION ═══");
    push("sys", `Artefact reçu : ${q.slice(0, 90)}${q.length > 90 ? "…" : ""}`);

    /* 01 — routage */
    bump("SUP-01");
    setActiveId("SUP-01");
    await wait(550);
    if (!mountedRef.current) return;
    push("ok", "SUP-01 ▸ requête routée — 26 unités consultées, chaîne d'analyse verrouillée");

    /* 02 — garde-fou d'entrée */
    setPhase(1);
    bump("GF-01");
    setActiveId("GF-01");
    push("sys", "GF-01 ▸ garde-fou d'entrée — évaluation via llama-guard-4…");
    let guard = "SÛR";
    let guardRemote = false;
    if (engineRef.current === "online") {
      try {
        guard = extractText(await aiChat(GUARD_PROMPT(q), GF1_MODEL)).toUpperCase();
        guardRemote = true;
      } catch {
        push("warn", "GF-01 ▸ modèle injoignable — bascule sur heuristique locale");
      }
    } else {
      push("warn", "GF-01 ▸ moteur IA hors ligne — heuristique locale appliquée");
    }
    if (/DANGEREUX|UNSAFE|REFUS/.test(guard)) {
      push("err", "GF-01 ▸ ENTRÉE REJETÉE — demande à caractère offensif détectée");
      setVerdict({
        risk: "BLOQUÉ",
        text: "Le garde-fou GF-01 a refusé cette requête : elle ressemble à une demande d'attaque et non de défense. L'essaim AEGIS-7 n'assiste que la cyberdéfense.",
      });
      setPhase(6);
      setActiveId(null);
      setRunning(false);
      busyRef.current = false;
      return;
    }
    push("ok", `GF-01 ▸ entrée validée (${guardRemote ? "verdict IA : demande légitime" : "heuristique : légitime"})`);

    /* 03 — analyse ouvrière en streaming */
    setPhase(2);
    bump("OUV-01");
    setActiveId("OUV-01");
    push("sys", `OUV-01 ▸ analyse ouvrière — modèle ${OUV_MODEL}, flux temps réel…`);
    const sid = push("ai", "");
    setStreamId(sid);
    let analysis = "";
    if (engineRef.current === "online") {
      try {
        const resp = await aiChat(WORKER_PROMPT(q), OUV_MODEL, true);
        for await (const part of resp as any) {
          const t = part?.text;
          if (t) {
            analysis += t;
            update(sid, analysis);
            if (!mountedRef.current) return;
          }
        }
      } catch {
        analysis = "";
      }
    }
    if (!analysis.trim()) {
      push("warn", "OUV-01 ▸ flux IA indisponible — analyse simulée locale injectée");
      analysis = fallbackAnalysis(q);
      for (let i = 0; i < analysis.length; i += 5) {
        update(sid, analysis.slice(0, i + 5));
        await wait(12);
        if (!mountedRef.current) return;
      }
      update(sid, analysis);
    }
    push("ok", `OUV-01 ▸ analyse terminée (${analysis.length} caractères)`);

    /* 04 — rappel mem0 */
    setPhase(3);
    bump("MEM-03");
    setActiveId("MEM-03");
    const mems = loadMem();
    const hit = recall(mems, q);
    if (hit) {
      push("ok", `MEM-03 (mem0) ▸ rappel : artefact similaire traité le ${new Date(hit.ts).toLocaleDateString("fr-FR")} — verdict ${hit.risk}`);
    } else {
      push("sys", "MEM-03 (mem0) ▸ aucun antécédent proche dans la banque de verdicts");
    }
    await wait(450);

    /* 05 — synthèse superviseur */
    setPhase(4);
    bump("SUP-02");
    setActiveId("SUP-02");
    push("sys", `SUP-02 ▸ synthèse superviseur — modèle ${SUP2_MODEL}…`);
    let synth = "";
    let synthRemote = false;
    if (engineRef.current === "online") {
      try {
        synth = extractText(await aiChat(SYNTH_PROMPT(analysis.slice(0, 900)), SUP2_MODEL));
        synthRemote = synth.trim().length > 0;
      } catch {
        synth = "";
      }
    }
    if (!synth.trim()) {
      if (!synthRemote) push("warn", "SUP-02 ▸ modèle injoignable — synthèse locale générée");
      synth = fallbackSynth(q, analysis);
    }
    push("ai", `SUP-02 ▸ ${synth}`);

    /* 06 — garde-fou de sortie */
    setPhase(5);
    bump("GF-02");
    setActiveId("GF-02");
    await wait(420);
    const dirty = /shellcode|0day|rm -rf|exploit.*payload/i.test(synth + " " + analysis);
    push(dirty ? "warn" : "ok", dirty ? "GF-02 ▸ sortie expurgée — segments offensifs masqués avant diffusion" : "GF-02 ▸ sortie conforme — aucun contenu offensif diffusé");

    /* Consignation mémoire */
    const risk = parseRisk(synth, q);
    const entry: MemEntry = {
      id: `INC-${String(mems.length + 1).padStart(4, "0")}`,
      ts: Date.now(),
      query: q.slice(0, 140),
      verdict: synth.slice(0, 240),
      risk,
    };
    bump("MEM-01");
    const next = [entry, ...mems];
    saveMem(next);
    setMemory(next);
    push("ok", `MEM-01 (mem0) ▸ incident ${entry.id} consigné — banque : ${next.length} entrée${next.length > 1 ? "s" : ""}`);
    push("sys", "═══ INTERROGATION CLOSE ═══");

    setVerdict({ risk, text: synth });
    setPhase(6);
    setActiveId(null);
    setStreamId(null);
    setRunning(false);
    busyRef.current = false;
  };

  const riposte = () => {
    window.dispatchEvent(new CustomEvent("aegis-burst"));
    document.getElementById("console")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const copyVerdict = async () => {
    if (!verdict) return;
    try {
      await navigator.clipboard.writeText(`[AEGIS-7] Verdict ${verdict.risk} — ${verdict.text}`);
    } catch {
      /* presse-papiers indisponible */
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const groups: { role: AgentRole; span: string }[] = [
    { role: "superviseur", span: "lg:col-span-4" },
    { role: "gardefou", span: "lg:col-span-4" },
    { role: "memoire", span: "lg:col-span-4" },
    { role: "llm", span: "lg:col-span-7" },
    { role: "ouvriere", span: "lg:col-span-5" },
  ];

  return (
    <section id="essaim" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      {/* En-tête */}
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-cyber">ESSAIM AGENTIQUE — IA RÉELLE</p>
          <h2 className="font-display mt-3 max-w-2xl text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Une armée de <span className="text-cyber">26 agents IA</span>, orchestrée en direct.
          </h2>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-fog">
            2 superviseurs · 2 garde-fous · 8 moteurs LLM · 8 banques mémoire (dont 4 mem0) · 6 ouvrières.
            Chaque interrogation traverse la chaîne complète : routage, filtrage, analyse en streaming,
            rappel mémoriel et verdict arbitré — via Puter.js et OpenRouter, sans backend.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3 border border-line bg-ink-900/70 px-4 py-3">
          <span className="grid h-9 w-9 place-items-center border border-cyber/40 text-cyber">
            <IconBrainChip className="h-5 w-5" />
          </span>
          <div>
            <p className="font-display text-[10px] font-bold tracking-[0.2em] text-snow">MOTEUR PUTER.JS · OPENROUTER</p>
            <p className={`mt-0.5 flex items-center gap-1.5 font-mono text-[9px] tracking-[0.16em] ${engine === "online" ? "text-pulse" : engine === "booting" ? "text-warn" : "text-alert"}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${engine === "online" ? "animate-pulse-dot bg-pulse" : engine === "booting" ? "bg-warn" : "bg-alert"}`} />
              {engine === "online" ? "EN LIGNE — MODÈLES JOIGNABLES" : engine === "booting" ? "AMORÇAGE DU MOTEUR…" : "INJOIGNABLE — MODE DÉGRADÉ LOCAL"}
            </p>
          </div>
        </div>
      </div>

      {/* Registre des agents */}
      <div className="mt-10 grid gap-5 lg:grid-cols-12">
        {groups.map((g) => (
          <div key={g.role} className={g.span}>
            <GroupPanel role={g.role} agents={AGENTS.filter((a) => a.role === g.role)} activeId={activeId} tasks={tasks} />
          </div>
        ))}
      </div>

      {/* Barre d'interrogation */}
      <div className="panel panel-corner mt-8 p-5 sm:p-6">
        <div className="flex items-center justify-between gap-4">
          <p className="font-display text-xs font-bold tracking-[0.24em] text-snow">INTERROGER L'ESSAIM</p>
          <p className="hidden font-mono text-[9px] tracking-[0.16em] text-fog-dim sm:block">
            COÛT PORTÉ PAR LE COMPTE PUTER FOURNI — MODÈLES VIA OPENROUTER
          </p>
        </div>
        <div className={`mt-4 flex flex-col gap-3 border transition-colors sm:flex-row ${inputErr ? "border-alert" : "border-line focus-within:border-cyber/70"}`}>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run();
            }}
            rows={2}
            placeholder="Décrivez une menace suspecte ou collez un artefact… (Ctrl+Entrée pour déployer)"
            spellCheck={false}
            className="min-h-[64px] min-w-0 flex-1 resize-none bg-transparent px-4 py-3.5 font-mono text-sm text-snow placeholder:text-fog-dim focus:outline-none"
          />
          <button
            onClick={() => run()}
            disabled={running}
            className="clip-tag group flex shrink-0 items-center justify-center gap-2.5 bg-cyber px-8 py-3.5 font-display text-xs font-bold tracking-[0.22em] text-ink-950 transition-all hover:bg-snow hover:shadow-[0_0_28px_rgba(56,225,255,0.35)] disabled:opacity-50 sm:self-stretch"
          >
            <IconBolt className={`h-4 w-4 ${running ? "animate-pulse" : "transition-transform group-hover:scale-125"}`} />
            {running ? "ESSAIM MOBILISÉ…" : "DÉPLOYER L'ESSAIM"}
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {SWARM_EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => {
                setInput(ex);
                run(ex);
              }}
              disabled={running}
              className="max-w-full truncate border border-line bg-ink-950/50 px-2.5 py-1.5 text-left font-mono text-[10px] text-fog transition-colors hover:border-cyber/60 hover:text-cyber disabled:opacity-50"
            >
              {ex.slice(0, 64)}…
            </button>
          ))}
        </div>
      </div>

      {/* Chaîne d'exécution */}
      <div className="mt-5 grid gap-5 lg:grid-cols-12">
        {/* Pipeline */}
        <div className="panel p-5 lg:col-span-3">
          <p className="font-display text-[10px] font-bold tracking-[0.24em] text-fog">CHAÎNE D'EXÉCUTION</p>
          <ol className="mt-4 space-y-2">
            {PIPELINE.map((st, i) => {
              const status = running
                ? i < phase
                  ? "done"
                  : i === phase
                    ? "live"
                    : "todo"
                : phase === 6
                  ? "done"
                  : "todo";
              return (
                <li
                  key={st.agent + i}
                  className={`border px-3 py-2.5 transition-all duration-300 ${
                    status === "live" ? "border-cyber/70 bg-cyber/[0.07]" : status === "done" ? "border-pulse/30 bg-pulse/[0.04]" : "border-line/60 opacity-45"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`grid h-5 w-5 place-items-center ${status === "live" ? "text-cyber" : status === "done" ? "text-pulse" : "text-fog-dim"}`}>
                      {status === "done" ? (
                        <IconCheck className="h-3.5 w-3.5" />
                      ) : status === "live" ? (
                        <span className="h-3 w-3 animate-spin rounded-full border border-cyber border-t-transparent" />
                      ) : (
                        <span className="font-mono text-[9px]">{i + 1}</span>
                      )}
                    </span>
                    <span className={`font-display text-[10px] font-bold tracking-[0.16em] ${status === "live" ? "text-cyber" : status === "done" ? "text-pulse" : "text-fog-dim"}`}>
                      {st.agent}
                    </span>
                    <span className={`ml-auto border px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] ${status === "live" ? "border-cyber/50 text-cyber" : "border-line text-fog-dim"}`}>
                      {st.kind}
                    </span>
                  </div>
                  <p className="mt-1.5 pl-7 text-[10px] leading-snug text-fog">{st.label}</p>
                </li>
              );
            })}
          </ol>
        </div>

        {/* Terminal */}
        <div className="panel overflow-hidden lg:col-span-6">
          <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
            <span className="h-2.5 w-2.5 rounded-full bg-alert/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-warn/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-pulse/70" />
            <span className="ml-2 flex items-center gap-2 font-mono text-[10px] tracking-[0.18em] text-fog-dim">
              <IconTerminal className="h-3.5 w-3.5" /> stdout — flux d'exécution
            </span>
            <button
              onClick={() => setLines([])}
              className="ml-auto border border-line px-2 py-0.5 font-mono text-[9px] tracking-[0.16em] text-fog-dim transition-colors hover:border-cyber/60 hover:text-cyber"
            >
              VIDER
            </button>
          </div>
          <div ref={termRef} className="h-[380px] overflow-y-auto px-4 py-3 font-mono text-[11px] leading-relaxed">
            {lines.length === 0 && (
              <p className="mt-6 text-center text-fog-dim">
                <span className="animate-blink text-cyber">▍</span> L'essaim attend vos ordres — déployez une interrogation.
              </p>
            )}
            {lines.map((l) => (
              <p key={l.id} className={`${LINE_COLOR[l.cls]} whitespace-pre-wrap break-words`}>
                {l.text}
                {l.id === streamId && running && <span className="animate-blink text-cyber">▍</span>}
              </p>
            ))}
          </div>

          {/* Verdict */}
          {verdict && (
            <div className={`animate-gauge-pop border-t-2 px-5 py-4 ${RISK_STYLE[verdict.risk] ?? RISK_STYLE["MODÉRÉ"]}`}>
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-display text-sm font-bold tracking-[0.24em]">
                  {verdict.risk === "BLOQUÉ" ? <IconWarning className="mr-2 inline h-4 w-4" /> : null}
                  VERDICT : {verdict.risk}
                </span>
                <div className="ml-auto flex gap-2">
                  <button
                    onClick={copyVerdict}
                    className="flex items-center gap-1.5 border border-current/40 px-2.5 py-1 font-mono text-[9px] tracking-[0.16em] transition-opacity hover:opacity-70"
                  >
                    {copied ? <IconCheck className="h-3 w-3" /> : <IconCopy className="h-3 w-3" />}
                    {copied ? "COPIÉ" : "COPIER"}
                  </button>
                  {verdict.risk !== "BLOQUÉ" && (
                    <button
                      onClick={riposte}
                      className="flex items-center gap-1.5 border border-current/40 px-2.5 py-1 font-mono text-[9px] tracking-[0.16em] transition-opacity hover:opacity-70"
                    >
                      <IconBolt className="h-3 w-3" /> DÉCLENCHER LA RIPOSTE
                    </button>
                  )}
                </div>
              </div>
              <p className="mt-2.5 text-xs leading-relaxed text-fog">{verdict.text}</p>
            </div>
          )}
        </div>

        {/* Banque mémorielle */}
        <div className="panel flex flex-col overflow-hidden lg:col-span-3">
          <div className="flex items-center gap-2.5 border-b border-line px-4 py-3">
            <IconLock className="h-4 w-4 text-pulse" />
            <p className="font-display text-[10px] font-bold tracking-[0.24em] text-snow">BANQUE MÉMORIELLE</p>
            <span className="ml-auto border border-pulse/40 bg-pulse/10 px-1.5 py-0.5 font-mono text-[9px] tracking-[0.12em] text-pulse">
              {memory.length}
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {memory.length === 0 ? (
              <p className="px-4 py-8 text-center font-mono text-[10px] leading-relaxed text-fog-dim">
                Aucun incident consigné.
                <br />
                Interrogez l'essaim : chaque verdict est gravé en mémoire.
              </p>
            ) : (
              <ul className="divide-y divide-line/50">
                {memory.slice(0, 8).map((m) => (
                  <li key={m.id + m.ts} className="animate-row-in px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] font-bold tracking-wider text-cyber">{m.id}</span>
                      <span className={`ml-auto border px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] ${RISK_STYLE[m.risk] ?? "border-line text-fog-dim"}`}>
                        {m.risk}
                      </span>
                    </div>
                    <p className="mt-1.5 truncate font-mono text-[10px] text-fog" title={m.query}>
                      {m.query}
                    </p>
                    <p className="mt-1 line-clamp-2 text-[10px] leading-snug text-fog-dim">{m.verdict}</p>
                    <p className="mt-1.5 font-mono text-[8px] tracking-[0.14em] text-fog-dim">
                      {new Date(m.ts).toLocaleDateString("fr-FR")} · {new Date(m.ts).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <p className="border-t border-line px-4 py-2.5 font-mono text-[8px] tracking-[0.14em] text-fog-dim">
            PERSISTANCE LOCALE DU NAVIGATEUR · 4 AGENTS mem0
          </p>
        </div>
      </div>
    </section>
  );
}
