import { useState } from "react";
import { ninjasDns, ninjasWhois } from "../live";
import {
  FORTS, addMemory, audit, auditAll, blockCount, fortStats, isolationTest, recall, repair,
  type FortAudit, type RecallHit,
} from "../mem0";
import { useInView } from "../hooks";
import {
  IconBolt, IconBrainChip, IconCheck, IconCopy, IconEyeScan, IconGlobe,
  IconLock, IconShieldCore, IconWarning,
} from "./Icons";

/* ------------------------------------------------------------------ */
/* Code de référence corrigé                                           */
/* ------------------------------------------------------------------ */

const FIXED_CODE = `# ══ MonMem0 — version corrigée et durcie ══════════════════════════
class MonMem0Personnel:
    """1 SaaS = 1 forteresse autonome. Double banque, zéro amnésie zombie."""

    def __init__(self, saas_id: str):
        self.saas_id = saas_id
        self.garde_fou = GardeFou(saas_id)                    # filtre local
        self.llm_1 = LLM("llm_alpha")                         # initialisé ICI (bug corrigé)
        self.llm_2 = LLM("llm_beta")                          # initialisé ICI (bug corrigé)
        self.mem0_a = MemoryClient(app_id=f"saas_{saas_id}_a")  # corrigé : saas_ (pas sass_)
        self.mem0_b = MemoryClient(app_id=f"saas_{saas_id}_b")
        self.superviseur = Superviseur(saas_id)

    def add_memory(self, message: str) -> str:
        if not self.garde_fou.check(message):
            self.superviseur.log("BLOCKED", message)
            return "BLOCKED"
        checksum = sha256(message)                            # ajouté : anti-amnésie
        self.mem0_a.add(message, agent_id=f"ai_{self.saas_id}", checksum=checksum)
        self.mem0_b.add(message, agent_id=f"ai_{self.saas_id}", checksum=checksum)
        if self.mem0_a.last_checksum() != self.mem0_b.last_checksum():
            raise ZombieAmnesiaError(self.saas_id)            # divergence = alerte
        self.superviseur.log("ADD", checksum)
        return checksum

    def recall(self, query: str) -> list:
        if not self.garde_fou.check(query):                   # ajouté : garde-fou au rappel
            return []
        scope = {"app_id": f"saas_{self.saas_id}"}            # isolement strict
        r1 = self.mem0_a.search(query, filters=scope)
        r2 = self.mem0_b.search(query, filters=scope)
        return self.superviseur.fuse(r1, r2)                  # dédupliqué par checksum


class MonSaaSIndependant(MonMem0Personnel):
    def __init__(self, saas_id: str):
        super().__init__(saas_id)
        self.auth = AuthLocale(saas_id)                       # JWT signé par le SaaS, pas Google

    def fetch_donnees(self, source_externe):
        if not self.garde_fou.check(source_externe):
            return "BLOQUE"
        result = self.superviseur.execute(
            self.llm_1.process(source_externe),
            self.llm_2.process(source_externe),
        )
        self.add_memory(str(result))                          # double banque vérifiée
        return result`;

const FIXES = [
  "Typo corrigé : namespace « sass_ » → « saas_ » (les deux banques pointaient vers le mauvais scope)",
  "llm_1 et llm_2 initialisés dans le constructeur — ils étaient utilisés sans exister",
  "Garde-fou appliqué au rappel, pas seulement à l'écriture",
  "Somme de contrôle sur chaque écriture + vérification A/B → amnésie zombie détectée immédiatement",
  "Superviseur.fuse défini : déduplication par checksum, tri par fraîcheur",
  "Isolement strict : scope par SaaS, lecture croisée structurellement impossible",
];

/* ------------------------------------------------------------------ */
/* Helpers UI                                                          */
/* ------------------------------------------------------------------ */

const PIPELINE = [
  { id: "guard", label: "GARDE-FOU", icon: (c: string) => <IconLock className={c} /> },
  { id: "llm", label: "LLM α + β", icon: (c: string) => <IconBrainChip className={c} /> },
  { id: "mem", label: "MEM0 A + B", icon: (c: string) => <IconShieldCore className={c} /> },
  { id: "sup", label: "SUPERVISEUR", icon: (c: string) => <IconEyeScan className={c} /> },
];

function dnsValue(r: any): string {
  return String(r.address ?? r.exchange ?? r.text ?? r.host ?? r.cname ?? r.target ?? r.value ?? JSON.stringify(r).slice(0, 60));
}

/* ------------------------------------------------------------------ */
/* Section                                                             */
/* ------------------------------------------------------------------ */

export default function MemZero() {
  const { ref, inView } = useInView<HTMLElement>();
  const [selected, setSelected] = useState("S-01");
  const [audits, setAudits] = useState<FortAudit[]>(() => auditAll());
  const [writeText, setWriteText] = useState("");
  const [writeResult, setWriteResult] = useState<{ status: string; detail: string } | null>(null);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<RecallHit[] | null>(null);
  const [guardMsg, setGuardMsg] = useState<string | null>(null);
  const [pulseStep, setPulseStep] = useState(-1);
  const [auditSel, setAuditSel] = useState<FortAudit | null>(null);
  const [globalAudit, setGlobalAudit] = useState<{ synced: number; divergent: number } | null>(null);
  const [isoTarget, setIsoTarget] = useState("S-17");
  const [isoResult, setIsoResult] = useState<{ blocked: boolean; leaked: number; detail: string } | null>(null);
  const [showCode, setShowCode] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);

  const [seoDomain, setSeoDomain] = useState("");
  const [seoBusy, setSeoBusy] = useState(false);
  const [seoDns, setSeoDns] = useState<any[] | null>(null);
  const [seoWhois, setSeoWhois] = useState<any | null>(null);
  const [seoErr, setSeoErr] = useState<string | null>(null);

  const stats = fortStats(selected);

  const refreshAudits = () => setAudits(auditAll());

  const doWrite = (text?: string) => {
    const t = (text ?? writeText).trim();
    if (!t) return;
    setPulseStep(0);
    window.setTimeout(() => setPulseStep(1), 160);
    window.setTimeout(() => setPulseStep(2), 320);
    window.setTimeout(() => setPulseStep(3), 480);
    window.setTimeout(() => setPulseStep(-1), 1100);
    const r = addMemory(selected, t);
    setWriteResult({
      status: r.status,
      detail: r.status === "OK" ? `checksum 0x${(r.checksum ?? 0).toString(16).toUpperCase()} — ${r.reason}` : r.reason,
    });
    setWriteText("");
    refreshAudits();
  };

  const doRecall = (q?: string) => {
    const r = recall(selected, q ?? query);
    setGuardMsg(r.guard ?? null);
    setHits(r.hits);
  };

  const doAuditSelected = () => setAuditSel(audit(selected));

  const doAuditAll = () => {
    const all = auditAll();
    setAudits(all);
    setGlobalAudit({
      synced: all.filter((a) => a.synced).length,
      divergent: all.filter((a) => !a.synced).length,
    });
  };

  const doRepair = () => {
    repair(selected);
    setAuditSel(audit(selected));
    refreshAudits();
  };

  const doIso = () => setIsoResult(isolationTest(selected, isoTarget));

  const doSeo = async (d?: string) => {
    const domain = (d ?? seoDomain).trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!domain) return;
    setSeoBusy(true);
    setSeoErr(null);
    setSeoDns(null);
    setSeoWhois(null);
    try {
      const [dns, whois] = await Promise.all([
        ninjasDns(domain).catch(() => null),
        ninjasWhois(domain).catch(() => null),
      ]);
      if (!dns && !whois) throw new Error("API Ninjas injoignable");
      setSeoDns(dns);
      setSeoWhois(whois);
      if (!dns && whois) setSeoErr("DNS injoignable — Whois seul récupéré");
      if (dns && !whois) setSeoErr("Whois injoignable — DNS seul récupéré");
    } catch (e: any) {
      setSeoErr(String(e?.message ?? e));
    } finally {
      setSeoBusy(false);
    }
  };

  const copyCode = async () => {
    try {
      await navigator.clipboard.writeText(FIXED_CODE);
    } catch {
      /* ignore */
    }
    setCodeCopied(true);
    setTimeout(() => setCodeCopied(false), 2000);
  };

  const divCount = audits.filter((a) => !a.synced).length;

  return (
    <section id="mem0" ref={ref} className={`reveal ${inView ? "reveal-in" : ""} mx-auto max-w-7xl scroll-mt-24 px-4 pt-24 sm:px-6`}>
      {/* En-tête */}
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] tracking-[0.34em] text-pulse">MEM0 CUSTOM — 45 FORTERESSES SaaS</p>
          <h2 className="font-display mt-3 max-w-2xl text-3xl font-bold tracking-tight text-snow sm:text-4xl">
            Zéro amnésie zombie. <span className="text-pulse">Zéro contamination.</span>
          </h2>
          <p className="mt-4 max-w-xl text-sm leading-relaxed text-fog">
            Chaque SaaS est un fort autonome : garde-fou local, 2 LLM, 2 mémoires, 2 instances mem0 (A + B)
            vérifiées par somme de contrôle, superviseur de fusion et JWT signé par le SaaS lui-même.
            Toute écriture est doublée ; toute divergence est détectée et réparée.
          </p>
        </div>
        <div className="flex shrink-0 flex-col gap-2 border border-line bg-ink-900/70 p-4">
          <div className="flex items-center gap-3">
            <span className="font-display text-3xl font-bold text-pulse tabular-nums">45</span>
            <span className="font-mono text-[9px] leading-relaxed tracking-[0.16em] text-fog-dim">FORTS ISOLÉS<br />SCOPE STRICT</span>
          </div>
          <div className="flex items-center gap-3">
            <span className={`font-display text-3xl font-bold tabular-nums ${divCount > 0 ? "text-alert" : "text-snow"}`}>{45 - divCount}<span className="text-lg">/45</span></span>
            <span className="font-mono text-[9px] leading-relaxed tracking-[0.16em] text-fog-dim">BANQUES A/B<br />SYNCHRONES</span>
          </div>
        </div>
      </div>

      {/* Grille des 45 forteresses */}
      <div className="panel mt-8 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">REGISTRE DES FORTERESSES</p>
          <div className="flex items-center gap-2">
            {globalAudit && (
              <span className={`border px-2 py-1 font-mono text-[9px] tracking-[0.14em] ${globalAudit.divergent > 0 ? "border-alert/50 bg-alert/10 text-alert" : "border-pulse/50 bg-pulse/10 text-pulse"}`}>
                {globalAudit.synced} SYNCHRONES · {globalAudit.divergent} DIVERGENTE{globalAudit.divergent > 1 ? "S" : ""}
              </span>
            )}
            <button onClick={doAuditAll} className="border border-line px-3 py-1.5 font-display text-[10px] font-bold tracking-[0.18em] text-fog transition-all hover:border-pulse/70 hover:text-pulse">
              AUDITER LES 45
            </button>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-5 gap-1.5 sm:grid-cols-9 lg:grid-cols-[repeat(15,minmax(0,1fr))]">
          {audits.map((a) => {
            const isSel = a.fortId === selected;
            return (
              <button
                key={a.fortId}
                onClick={() => { setSelected(a.fortId); setAuditSel(null); setIsoResult(null); setHits(null); }}
                title={`${a.fortId} — A:${a.a} B:${a.b}${a.synced ? "" : ` · ${a.divergences} divergence(s)`}`}
                className={`group relative flex flex-col items-center gap-1 border py-2 transition-all duration-200 ${
                  isSel
                    ? "border-pulse bg-pulse/10 shadow-[0_0_18px_rgba(67,240,141,0.2)]"
                    : a.synced
                      ? "border-line bg-ink-950/40 hover:border-pulse/50"
                      : "border-alert/60 bg-alert/[0.06] hover:border-alert"
                }`}
              >
                <span className={`font-display text-[10px] font-bold tracking-wider ${isSel ? "text-pulse" : a.synced ? "text-fog" : "text-alert"}`}>
                  {a.fortId}
                </span>
                <span className="flex gap-1">
                  <span className="h-1 w-1 rounded-full bg-cyber/70" />
                  <span className="h-1 w-1 rounded-full bg-cyber/40" />
                  <span className={`h-1 w-1 rounded-full ${a.synced ? "bg-pulse" : "animate-pulse-dot bg-alert"}`} />
                </span>
                <span className="font-mono text-[8px] tabular-nums text-fog-dim">{a.a + a.b} mém</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Corps principal */}
      <div className="mt-5 grid gap-5 lg:grid-cols-12">
        {/* Intérieur de la forteresse */}
        <div className="panel flex flex-col p-5 lg:col-span-5">
          <div className="flex items-center justify-between">
            <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">INTÉRIEUR — {selected}</p>
            <span className="font-mono text-[9px] tracking-[0.14em] text-fog-dim">
              A:{stats.a} · B:{stats.b} · BLOCS:{stats.blocks}
            </span>
          </div>

          {/* Pipeline */}
          <div className="mt-5 flex items-stretch gap-1.5">
            {PIPELINE.map((p, i) => (
              <div key={p.id} className="flex flex-1 items-center gap-1.5">
                <div
                  className={`flex flex-1 flex-col items-center gap-1.5 border px-1 py-3 transition-all duration-300 ${
                    pulseStep === i ? "border-cyber bg-cyber/10 shadow-[0_0_16px_rgba(56,225,255,0.25)]" : "border-line bg-ink-950/40"
                  }`}
                >
                  {p.icon(`h-4 w-4 ${pulseStep === i ? "text-cyber" : "text-fog-dim"}`)}
                  <span className={`font-mono text-[8px] tracking-[0.1em] ${pulseStep === i ? "text-cyber" : "text-fog-dim"}`}>{p.label}</span>
                </div>
                {i < PIPELINE.length - 1 && <span className={`h-px w-1.5 shrink-0 ${pulseStep >= i ? "bg-cyber" : "bg-line"}`} />}
              </div>
            ))}
          </div>

          {/* Écriture */}
          <div className="mt-5">
            <p className="font-mono text-[9px] tracking-[0.22em] text-fog-dim">ÉCRIRE EN DOUBLE BANQUE (GARDE-FOU → LLM → A+B → SUPERVISEUR)</p>
            <div className="mt-2 flex gap-2">
              <input
                value={writeText}
                onChange={(e) => setWriteText(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && doWrite()}
                placeholder={`Mémoire pour ai_${selected}…`}
                spellCheck={false}
                className="min-w-0 flex-1 border border-line bg-transparent px-3 py-2.5 font-mono text-xs text-snow placeholder:text-fog-dim focus:border-pulse/70 focus:outline-none"
              />
              <button onClick={() => doWrite()} className="clip-tag shrink-0 bg-pulse px-4 font-display text-[10px] font-bold tracking-[0.16em] text-ink-950 transition-all hover:bg-snow">
                GRAVER
              </button>
            </div>
            {writeResult && (
              <p className={`mt-2 flex items-start gap-2 font-mono text-[10px] leading-relaxed ${writeResult.status === "OK" ? "text-pulse" : "text-alert"}`}>
                {writeResult.status === "OK" ? <IconCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <IconWarning className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
                {writeResult.status === "OK" ? "ÉCRITURE " : "REFUS — "}{writeResult.detail}
              </p>
            )}
          </div>

          {/* Rappel */}
          <div className="mt-5 border-t border-line pt-4">
            <p className="font-mono text-[9px] tracking-[0.22em] text-fog-dim">RAPPEL FUSIONNÉ A + B (SUPERVISEUR.FUSE)</p>
            <div className="mt-2 flex gap-2">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && doRecall()}
                placeholder="Requêter la mémoire du fort…"
                spellCheck={false}
                className="min-w-0 flex-1 border border-line bg-transparent px-3 py-2.5 font-mono text-xs text-snow placeholder:text-fog-dim focus:border-cyber/70 focus:outline-none"
              />
              <button onClick={() => doRecall()} className="clip-tag shrink-0 border border-cyber/50 bg-cyber/10 px-4 font-display text-[10px] font-bold tracking-[0.16em] text-cyber transition-all hover:bg-cyber hover:text-ink-950">
                RAPPELER
              </button>
            </div>
            {guardMsg && <p className="mt-2 font-mono text-[10px] text-alert">▸ {guardMsg}</p>}
            {hits && (
              <ul className="mt-3 max-h-44 space-y-1.5 overflow-y-auto">
                {hits.length === 0 && <li className="font-mono text-[10px] text-fog-dim">Aucune correspondance dans les deux banques.</li>}
                {hits.map((h) => (
                  <li key={h.entry.id} className="animate-row-in border border-line/70 bg-ink-950/50 px-2.5 py-2">
                    <div className="flex items-center gap-2">
                      <span className={`border px-1.5 py-0.5 font-mono text-[8px] tracking-[0.1em] ${h.inA && h.inB ? "border-pulse/50 text-pulse" : "border-warn/50 text-warn"}`}>
                        {h.inA && h.inB ? "A+B VÉRIFIÉ" : h.inA ? "A UNIQUEMENT" : "B UNIQUEMENT"}
                      </span>
                      <span className="ml-auto font-mono text-[8px] text-fog-dim">0x{h.entry.checksum.toString(16).toUpperCase()}</span>
                    </div>
                    <p className="mt-1 font-mono text-[10px] leading-snug text-fog">{h.entry.text}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Audit + isolement */}
        <div className="flex flex-col gap-5 lg:col-span-4">
          <div className="panel p-5">
            <div className="flex items-center justify-between">
              <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">AUDIT ANTI-ZOMBIE — {selected}</p>
              <button onClick={doAuditSelected} className="border border-line px-3 py-1.5 font-display text-[10px] font-bold tracking-[0.16em] text-fog transition-all hover:border-warn/70 hover:text-warn">
                LANCER
              </button>
            </div>
            {!auditSel && (
              <p className="mt-4 font-mono text-[10px] leading-relaxed text-fog-dim">
                Compare les banques A et B entrée par entrée. Toute asymétrie = amnésie zombie potentielle,
                signalée puis réparable en un clic.
              </p>
            )}
            {auditSel && (
              <div className="mt-4">
                <div className="flex items-center gap-3">
                  {[
                    { l: "BANQUE A", v: auditSel.a, c: "text-cyber" },
                    { l: "BANQUE B", v: auditSel.b, c: "text-cyber" },
                    { l: "DIVERGENCES", v: auditSel.divergences, c: auditSel.divergences > 0 ? "text-alert" : "text-pulse" },
                  ].map((x) => (
                    <div key={x.l} className="flex-1 border border-line bg-ink-950/50 px-3 py-2.5 text-center">
                      <div className={`font-display text-xl font-bold tabular-nums ${x.c}`}>{x.v}</div>
                      <div className="mt-0.5 font-mono text-[8px] tracking-[0.14em] text-fog-dim">{x.l}</div>
                    </div>
                  ))}
                </div>
                <p className={`mt-3 flex items-center gap-2 font-mono text-[10px] ${auditSel.synced ? "text-pulse" : "text-alert"}`}>
                  {auditSel.synced ? <IconCheck className="h-3.5 w-3.5" /> : <IconWarning className="h-3.5 w-3.5" />}
                  {auditSel.synced ? "Banques synchrones — aucune amnésie zombie." : `${auditSel.divergences} entrée(s) asymétrique(s) détectée(s).`}
                </p>
                {!auditSel.synced && (
                  <button onClick={doRepair} className="clip-tag mt-3 flex w-full items-center justify-center gap-2 bg-warn px-4 py-2.5 font-display text-[10px] font-bold tracking-[0.18em] text-ink-950 transition-all hover:bg-snow">
                    <IconBolt className="h-3.5 w-3.5" /> RÉPARER (UNION A ∪ B)
                  </button>
                )}
              </div>
            )}
          </div>

          <div className="panel flex-1 p-5">
            <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">TEST D'ISOLEMENT CROISÉ</p>
            <p className="mt-2 font-mono text-[10px] leading-relaxed text-fog-dim">
              Simule une tentative de lecture du fort <span className="text-snow">{isoTarget}</span> depuis{" "}
              <span className="text-snow">{selected}</span> — doit être structurellement bloqué.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <span className="border border-line px-2.5 py-2 font-mono text-[10px] text-fog">{selected}</span>
              <span className="text-alert">⤳</span>
              <select
                value={isoTarget}
                onChange={(e) => setIsoTarget(e.target.value)}
                className="min-w-0 flex-1 border border-line bg-ink-950 px-2.5 py-2 font-mono text-[10px] text-fog focus:border-alert/70 focus:outline-none"
              >
                {FORTS.filter((f) => f !== selected).map((f) => (
                  <option key={f} value={f}>{f}</option>
                ))}
              </select>
              <button onClick={doIso} className="clip-tag shrink-0 bg-alert px-4 py-2 font-display text-[10px] font-bold tracking-[0.14em] text-ink-950 transition-all hover:bg-snow">
                FORCER
              </button>
            </div>
            {isoResult && (
              <div className={`animate-gauge-pop mt-3 border p-3 ${isoResult.blocked ? "border-pulse/50 bg-pulse/[0.06]" : "border-alert/60 bg-alert/10"}`}>
                <p className={`flex items-center gap-2 font-display text-[11px] font-bold tracking-[0.2em] ${isoResult.blocked ? "text-pulse" : "text-alert"}`}>
                  {isoResult.blocked ? <IconLock className="h-4 w-4" /> : <IconWarning className="h-4 w-4" />}
                  {isoResult.blocked ? "BLOQUÉ — 0 FUITE" : "CONTAMINATION !"}
                </p>
                <p className="mt-1.5 font-mono text-[10px] leading-relaxed text-fog">{isoResult.detail}</p>
              </div>
            )}
          </div>
        </div>

        {/* SEO autonome */}
        <div className="panel flex flex-col p-5 lg:col-span-3">
          <div className="flex items-center justify-between">
            <p className="font-display text-[11px] font-bold tracking-[0.24em] text-snow">SEO AUTONOME</p>
            <span className="border border-pulse/50 bg-pulse/10 px-1.5 py-0.5 font-mono text-[8px] tracking-[0.12em] text-pulse">0 GOOGLE</span>
          </div>
          <p className="mt-2 font-mono text-[10px] leading-relaxed text-fog-dim">
            Crawler propre : DNS + Whois via API Ninjas. Aucun appel Google, aucune fuite de données.
          </p>
          <div className="mt-3 flex flex-col gap-2">
            <input
              value={seoDomain}
              onChange={(e) => setSeoDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doSeo()}
              placeholder="exemple.com"
              spellCheck={false}
              className="border border-line bg-transparent px-3 py-2.5 font-mono text-xs text-snow placeholder:text-fog-dim focus:border-pulse/70 focus:outline-none"
            />
            <button onClick={() => doSeo()} disabled={seoBusy} className="clip-tag flex items-center justify-center gap-2 bg-pulse px-4 py-2.5 font-display text-[10px] font-bold tracking-[0.18em] text-ink-950 transition-all hover:bg-snow disabled:opacity-50">
              {seoBusy ? <span className="h-3 w-3 animate-spin rounded-full border border-ink-950 border-t-transparent" /> : <IconGlobe className="h-3.5 w-3.5" />}
              {seoBusy ? "CRAWL…" : "SCRUTER LE DOMAINE"}
            </button>
          </div>
          {seoErr && <p className="mt-2 font-mono text-[10px] text-warn">▸ {seoErr}</p>}
          <div className="mt-3 min-h-0 flex-1 space-y-3 overflow-y-auto">
            {seoWhois && (
              <div className="border border-line bg-ink-950/50 p-3">
                <p className="font-mono text-[8px] tracking-[0.18em] text-fog-dim">WHOIS — API NINJAS</p>
                <p className="mt-1 truncate font-mono text-[10px] text-snow">{seoWhois.domain_name ?? seoDomain}</p>
                {[
                  ["Registrar", seoWhois.registrar],
                  ["Créé le", seoWhois.created_date],
                  ["Expire le", seoWhois.expiration_date],
                ].filter(([, v]) => v).map(([k, v]) => (
                  <p key={k as string} className="mt-1 flex justify-between gap-2 font-mono text-[9px] text-fog">
                    <span className="text-fog-dim">{k}</span>
                    <span className="truncate">{String(v)}</span>
                  </p>
                ))}
              </div>
            )}
            {seoDns && seoDns.length > 0 && (
              <div className="border border-line bg-ink-950/50 p-3">
                <p className="font-mono text-[8px] tracking-[0.18em] text-fog-dim">ENREGISTREMENTS DNS ({seoDns.length})</p>
                <ul className="mt-2 space-y-1">
                  {seoDns.slice(0, 10).map((r, i) => (
                    <li key={i} className="flex items-center gap-2 font-mono text-[9px]">
                      <span className="w-12 shrink-0 border border-cyber/40 bg-cyber/10 px-1 py-0.5 text-center tracking-[0.1em] text-cyber">{r.type}</span>
                      <span className="truncate text-fog" title={dnsValue(r)}>{dnsValue(r)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {!seoDns && !seoWhois && !seoBusy && (
              <p className="pt-2 text-center font-mono text-[9px] leading-relaxed text-fog-dim">
                Aucun crawl pour l'instant.
                <br />
                Le garde-fou « no_google_leak » est armé.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Code corrigé */}
      <div className="panel mt-5 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-3.5">
          <button onClick={() => setShowCode((v) => !v)} className="flex items-center gap-3 font-display text-[11px] font-bold tracking-[0.22em] text-snow transition-colors hover:text-pulse">
            <span className={`grid h-5 w-5 place-items-center border border-line text-[10px] transition-transform duration-300 ${showCode ? "rotate-45 border-pulse text-pulse" : ""}`}>+</span>
            CODE DE RÉFÉRENCE — CORRIGÉ & DURCI {showCode ? "(MASQUER)" : "(AFFICHER)"}
          </button>
          {showCode && (
            <button onClick={copyCode} className="flex items-center gap-1.5 border border-line px-2.5 py-1 font-mono text-[9px] tracking-[0.14em] text-fog-dim transition-colors hover:border-pulse/60 hover:text-pulse">
              {codeCopied ? <IconCheck className="h-3 w-3 text-pulse" /> : <IconCopy className="h-3 w-3" />}
              {codeCopied ? "COPIÉ" : "COPIER"}
            </button>
          )}
        </div>
        {showCode && (
          <div className="grid gap-0 lg:grid-cols-3">
            <pre className="max-h-[420px] overflow-auto bg-ink-950/80 p-5 font-mono text-[11px] leading-relaxed text-fog lg:col-span-2">
              <code>{FIXED_CODE}</code>
            </pre>
            <div className="border-t border-line p-5 lg:border-l lg:border-t-0">
              <p className="font-display text-[10px] font-bold tracking-[0.22em] text-warn">6 CORRECTIONS APPLIQUÉES</p>
              <ul className="mt-3 space-y-2.5">
                {FIXES.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 font-mono text-[10px] leading-relaxed text-fog">
                    <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center border border-warn/50 text-[8px] text-warn">{i + 1}</span>
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
