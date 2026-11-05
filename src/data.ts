export type Severity = 0 | 1 | 2;

export const SEVERITY_META: Record<Severity, { label: string; color: string; bg: string }> = {
  0: { label: "FAIBLE", color: "text-pulse", bg: "bg-pulse/10 border-pulse/30" },
  1: { label: "MOYEN", color: "text-warn", bg: "bg-warn/10 border-warn/30" },
  2: { label: "CRITIQUE", color: "text-alert", bg: "bg-alert/10 border-alert/40" },
};

export interface AttackDef {
  label: string;
  sev: Severity;
}

export const ATTACKS: AttackDef[] = [
  { label: "Hameçonnage (phishing)", sev: 1 },
  { label: "Force brute SSH", sev: 1 },
  { label: "Injection SQL", sev: 2 },
  { label: "Volumétrie DDoS", sev: 2 },
  { label: "Cheval de Troie RAT", sev: 2 },
  { label: "Scan de ports massif", sev: 0 },
  { label: "Credential stuffing", sev: 1 },
  { label: "Exfiltration de données", sev: 2 },
  { label: "XSS réfléchi", sev: 1 },
  { label: "Canal C2 botnet", sev: 2 },
  { label: "Campagne spam Telegram", sev: 0 },
  { label: "Usurpation DNS (spoofing)", sev: 1 },
  { label: "Ransomware signature connue", sev: 2 },
  { label: "OSINT hostile ciblé", sev: 1 },
];

export interface Origin {
  ip: string;
  city: string;
  cc: string;
}

export const ORIGINS: Origin[] = [
  { ip: "105.158.44.17", city: "Casablanca", cc: "MA" },
  { ip: "41.140.202.88", city: "Rabat", cc: "MA" },
  { ip: "196.200.132.5", city: "Marrakech", cc: "MA" },
  { ip: "105.159.77.210", city: "Tanger", cc: "MA" },
  { ip: "41.251.66.12", city: "Agadir", cc: "MA" },
  { ip: "160.176.35.90", city: "Oujda", cc: "MA" },
  { ip: "81.252.114.33", city: "Paris", cc: "FR" },
  { ip: "90.84.17.201", city: "Lyon", cc: "FR" },
  { ip: "37.166.45.9", city: "Marseille", cc: "FR" },
  { ip: "78.126.89.144", city: "Toulouse", cc: "FR" },
  { ip: "2.10.177.58", city: "Strasbourg", cc: "FR" },
  { ip: "176.152.66.27", city: "Lille", cc: "FR" },
];

export const ACTIONS = ["NEUTRALISÉ", "BLOQUÉ", "QUARANTAINE", "LEURRÉ (HONEYPOT)"] as const;

export const TARGETS = [
  "passerelle CB — Paris",
  "portail CAF",
  "SI hôpital — Lyon",
  "API Ameli",
  "banque centrale — Rabat",
  "CNSS — espace assuré",
  "Maroc Telecom — comptes",
  "Barid Bank — virements",
  "port 22 (SSH) — VPS Gravelines",
  "transfert de fonds — Casablanca",
];

/* ------------------------------------------------------------------ */
/* Sources de renseignement (dépôts GitHub fournis, catégorisés)       */
/* ------------------------------------------------------------------ */

export type IntelCat = "OSINT TELEGRAM" | "TOR & DARKNET" | "BASE OFFENSIVE" | "IA DÉFENSIVE" | "INFRA & IA";

export interface IntelSource {
  name: string;
  url: string;
  cat: IntelCat;
  desc: string;
}

export const INTEL_SOURCES: IntelSource[] = [
  { name: "LangBot", url: "https://github.com/langbot-app/LangBot", cat: "INFRA & IA", desc: "Moteur de bots conversationnels — canal de veille automatisée multi-plateformes." },
  { name: "node-telegram-bot-api", url: "https://github.com/yagop/node-telegram-bot-api", cat: "OSINT TELEGRAM", desc: "Connecteur Telegram — remonte les signaux d'arnaques diffusés via bots." },
  { name: "tdesktop", url: "https://github.com/telegramdesktop/tdesktop", cat: "OSINT TELEGRAM", desc: "Client Telegram Desktop — supervision des canaux à risque en continu." },
  { name: "TG-All-In-One-Tool", url: "https://github.com/CallToSta/TG-All-In-One-Tool", cat: "OSINT TELEGRAM", desc: "Boîte à outils Telegram — détection de raids et de campagnes de spam organisées." },
  { name: "TG-All-In-1-Tool", url: "https://github.com/somte/TG-All-In-1-Tool", cat: "OSINT TELEGRAM", desc: "Variante d'outillage Telegram — cartographie des groupes malveillants." },
  { name: "telegram-member-adder", url: "https://github.com/ETHx007/telegram-member-adder-kenzabyte", cat: "OSINT TELEGRAM", desc: "Analyse des ajouts massifs de membres — signature typique de campagnes frauduleuses." },
  { name: "telegram-channel-scraper", url: "https://github.com/mmahdium/simple-telegram-channel-scraper", cat: "OSINT TELEGRAM", desc: "Aspiration de canaux — indexation des offres illégales revendues sur Telegram." },
  { name: "bwscanner", url: "https://github.com/TheTorProject/bwscanner", cat: "TOR & DARKNET", desc: "Scanner de bande passante Tor — mesure la santé du réseau d'anonymisation." },
  { name: "tor-messenger-website", url: "https://github.com/TheTorProject/tor-messenger-website", cat: "TOR & DARKNET", desc: "Référence messagerie chiffrée sur Tor — durcissement des échanges internes." },
  { name: "gettorbrowser", url: "https://github.com/TheTorProject/gettorbrowser", cat: "TOR & DARKNET", desc: "Distribution Tor Browser — accès sécurisé aux zones censurées ou hostiles." },
  { name: "TorBot", url: "https://github.com/DedSecInside/TorBot", cat: "TOR & DARKNET", desc: "Crawler .onion — exploration contrôlée du darknet à des fins défensives." },
  { name: "Awesome-Hacking", url: "https://github.com/Hack-with-Github/Awesome-Hacking", cat: "BASE OFFENSIVE", desc: "Index mondial des outils offensifs — l'agent s'entraîne contre l'état de l'art." },
  { name: "PayloadsAllTheThings", url: "https://github.com/swisskyrepo/PayloadsAllTheThings", cat: "BASE OFFENSIVE", desc: "Bibliothèque de payloads — alimente le moteur de détection de motifs d'attaque." },
  { name: "h4cker", url: "https://github.com/The-Art-of-Hacking/h4cker", cat: "BASE OFFENSIVE", desc: "Ressources The Art of Hacking — scenarios d'entraînement adverses (TTPs)." },
  { name: "strix", url: "https://github.com/usestrix/strix", cat: "BASE OFFENSIVE", desc: "Agents IA offensifs open source — adversaires synthétiques pour tests de défense." },
  { name: "Anthropic-Cybersecurity-Skills", url: "https://github.com/mukul975/Anthropic-Cybersecurity-Skills", cat: "IA DÉFENSIVE", desc: "Compétences IA orientées cybersécurité — routines d'analyse et de réponse." },
  { name: "aidefend-mcp", url: "https://github.com/edward-playground/aidefend-mcp", cat: "IA DÉFENSIVE", desc: "Serveur MCP de défense IA — orchestration des outils de contre-attaque." },
  { name: "iFixAi", url: "https://github.com/ifixai-ai/iFixAi", cat: "IA DÉFENSIVE", desc: "Réparation assistée par IA — colmatage automatique des vulnérabilités." },
  { name: "unworldly", url: "https://github.com/DilawarShafiq/unworldly", cat: "IA DÉFENSIVE", desc: "Cadre expérimental de détection d'anomalies comportementales." },
  { name: "AI-TadPole-OS", url: "https://github.com/DDS-Solutions/AI-TadPole-OS", cat: "IA DÉFENSIVE", desc: "OS agentique — boucle autonome détection → décision → riposte." },
  { name: "ml-engineering", url: "https://github.com/stas00/ml-engineering", cat: "INFRA & IA", desc: "Ingénierie ML à l'échelle — entraînement des modèles de classification d'attaques." },
  { name: "llm-app (Pathway)", url: "https://github.com/pathwaycom/llm-app", cat: "INFRA & IA", desc: "Pipelines LLM temps réel — corrélation des flux de menaces en streaming." },
];

export const INTEL_CATS: IntelCat[] = ["OSINT TELEGRAM", "TOR & DARKNET", "BASE OFFENSIVE", "IA DÉFENSIVE", "INFRA & IA"];

/* ------------------------------------------------------------------ */
/* Modules de défense                                                  */
/* ------------------------------------------------------------------ */

export interface DefenseModule {
  id: string;
  title: string;
  code: string;
  desc: string;
  status: string;
  metric: string;
  span: string;
}

export const MODULES: DefenseModule[] = [
  {
    id: "firewall",
    title: "Pare-feu neuronal NX-2",
    code: "MOD-01",
    desc: "Filtrage profond piloté par un réseau de neurones récurrent. Chaque paquet est scoré en temps réel ; les signatures inconnues sont apprises puis généralisées à l'ensemble du périmètre.",
    status: "ARMÉ",
    metric: "2,4 M paquets/s inspectés",
    span: "lg:col-span-4 lg:row-span-2",
  },
  {
    id: "phishing",
    title: "Bouclier anti-hameçonnage",
    code: "MOD-02",
    desc: "Analyse sémantique des messages et des URL : domaines jumeaux, homoglyphes, leurres de marque. Les faux sites Ameli, CAF, impôts, DGI ou Maroc Telecom sont pré-détonnés en bac à sable avant diffusion.",
    status: "ACTIF",
    metric: "18 400 leurres FR & MA bloqués / 24 h",
    span: "lg:col-span-4",
  },
  {
    id: "ids",
    title: "IDS « Hydre » multi-têtes",
    code: "MOD-03",
    desc: "Détection d'intrusion distribuée sur sept sondes. Si une sonde est aveuglée, les six autres recalculent sa couverture en moins d'une seconde.",
    status: "7/7 SONDES",
    metric: "0 intrusion depuis 214 j",
    span: "lg:col-span-4",
  },
  {
    id: "torwatch",
    title: "Vigie Tor & darknet",
    code: "MOD-04",
    desc: "Crawlers TorBot surveillent les places de marché .onion où se revendent les bases françaises et marocaines volées. Alerte immédiate si des identifiants ou fichiers clients fuient.",
    status: "EN PATROUILLE",
    metric: "312 marchés scrutés — focus FR/MA",
    span: "lg:col-span-4",
  },
  {
    id: "tgwatch",
    title: "Écoute défensive Telegram",
    code: "MOD-05",
    desc: "Surveille les canaux et groupes francophones et marocains où s'organisent raids, fuites et ventes d'accès. Détecte les campagnes de membres forcés et les bots d'arnaque avant qu'ils ne frappent.",
    status: "1 024 CANAUX",
    metric: "46 campagnes détectées",
    span: "lg:col-span-4",
  },
  {
    id: "soar",
    title: "Riposte automatisée SOAR",
    code: "MOD-06",
    desc: "Orchestre la contre-mesure : isolement d'hôte, coupure de session, blocage ASN, dépôt de preuve horodatée. Chaque action est journalisée, réversible et alignée sur les procédures ANSSI (France) et DGSSI (Maroc).",
    status: "PRÊT",
    metric: "38 ms de latence moyenne",
    span: "lg:col-span-4",
  },
];

/* ------------------------------------------------------------------ */
/* Phases de riposte                                                   */
/* ------------------------------------------------------------------ */

export const PHASES = [
  {
    n: "01",
    title: "Détection",
    desc: "Les sondes corrèlent télémétrie réseau, journaux d'authentification et flux OSINT. Un score de risque est attribué en continu à chaque événement.",
    detail: "Moteur : corrélation Pathway + règles PayloadsAllTheThings",
  },
  {
    n: "02",
    title: "Isolement",
    desc: "L'hôte ou le compte compromis est mis en quarantaine réseau. Les sessions actives sont révoquées, les jetons invalidés, les ports fermés.",
    detail: "Impact utilisateur : < 2 s, notification automatique",
  },
  {
    n: "03",
    title: "Neutralisation",
    desc: "L'agent coupe le canal de commande (C2), bloque les ASN hostiles et déploie des honeypots pour absorber et étudier l'assaillant.",
    detail: "Leurre actif : honeypot haute interaction",
  },
  {
    n: "04",
    title: "Rapport & apprentissage",
    desc: "Dossier de preuve horodaté, prêt pour dépôt de plainte. L'attaque alimente l'entraînement des modèles : la même technique ne passera plus.",
    detail: "Dossier prêt pour dépôt : cybermalveillance.gouv.fr (FR) & DGSSI (MA) — export STIX/TAXII",
  },
];

/* ------------------------------------------------------------------ */
/* Bande défilante                                                     */
/* ------------------------------------------------------------------ */

export const TICKER_ITEMS = [
  "Campagne « Ameli-remboursement » — 2 400 leurres bloqués en France",
  "105.158.44.17 (Casablanca) — force brute sur portail CNSS neutralisée",
  "Faux site « DGI Maroc » repéré sur Telegram — 38 canaux signalés à la DGSSI",
  "Scan darknet terminé : 0 fuite de données d'entreprises françaises",
  "Vague « faux support Maroc Telecom » — signature vocale ajoutée au moteur",
  "Signalement synchronisé avec l'ANSSI — 12 IOCs partagés",
  "Hameçonnage CPF (Compte Formation) — domaine leurre en .xyz démantelé",
  "Honeypot Paris-2 : 9 attaquants piégés cette nuit",
  "Barid Bank : tentative de fraude au virement bloquée — 148 000 MAD",
  "Veille Telegram : groupes « Marocains du Monde » sous protection renforcée",
  "Essaim agentique : 26 unités IA en ligne — superviseurs, garde-fous, LLM, mémoires mem0, ouvrières",
  "OUV-01 disponible pour analyse en flux temps réel via OpenRouter",
  "Mem0 custom : 45 forteresses SaaS — double banque A/B, zéro amnésie zombie",
  "SEO autonome armé : 0 appel Google — DNS + Whois via API Ninjas",
  "Test d'isolement croisé : 0 contamination détectée sur les 45 forts",
  "Pare-feu cognitif armé : clés API, IP, ports, DNS et logs masqués avant toute sortie",
  "Règle active : 11 catégories de marqueurs neutralisées en un seul passage",
];

/* ------------------------------------------------------------------ */
/* Essaim d'agents IA — Puter.js / OpenRouter                          */
/* ------------------------------------------------------------------ */

export const PUTER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InYyIn0.eyJ0IjoidCIsInYiOiIyIiwidG9rZW5fdWlkIjoiYTlmZDk3OWItMDgzMy00ZTFlLWJkNzgtMTliY2Q1YzUxM2VhIiwidXUiOiJGeDA3UThEb1NSQ3hvNW9DbGpwMHZ3PT0iLCJzdSI6IjBJNmZGdUFBUkN5L1hxNk53bXQvbnc9PSIsImFpIjoiRngwN1E4RG9TUkN4bzVvQ2xqcDB2dz09IiwiZnVsbF9hY2Nlc3MiOnRydWUsImlhdCI6MTc4NDc1NTgxNH0.znY4DGWa0Tg7c-m4lLmoeLg3dVX27V24LAmerZuBKMg";

export type AgentRole = "superviseur" | "gardefou" | "llm" | "memoire" | "ouvriere";

export interface AgentDef {
  id: string;
  role: AgentRole;
  duty: string;
  model?: string;
  tag?: string;
}

export const ROLE_META: Record<AgentRole, { label: string; hex: string; blurb: string }> = {
  superviseur: { label: "SUPERVISEURS", hex: "#b18cff", blurb: "Orchestrent l'essaim, routent et arbitrent les verdicts." },
  gardefou: { label: "GARDE-FOUS", hex: "#ff4d5e", blurb: "Valident entrées et sorties — aucune dérive offensive tolérée." },
  llm: { label: "MOTEURS LLM", hex: "#38e1ff", blurb: "Huit modèles de fournisseurs différents, vote de consensus." },
  memoire: { label: "MÉMOIRE", hex: "#43f08d", blurb: "Huit banques, dont quatre adossées à mem0 — l'essaim n'oublie jamais." },
  ouvriere: { label: "OUVRIÈRES", hex: "#ffb020", blurb: "Exécutent le travail d'analyse : détonation, triage, extraction, rapport." },
};

export const AGENTS: AgentDef[] = [
  { id: "SUP-01", role: "superviseur", duty: "Dispatch & routage des requêtes", model: "x-ai/grok-4.20-multi-agent" },
  { id: "SUP-02", role: "superviseur", duty: "Synthèse, arbitrage & verdict final", model: "qwen/qwen3-max-thinking" },
  { id: "GF-01", role: "gardefou", duty: "Filtre d'entrée — refuse les demandes offensives", model: "meta-llama/llama-guard-4-12b" },
  { id: "GF-02", role: "gardefou", duty: "Filtre de sortie — bloque tout contenu offensif", model: "openai/gpt-oss-safeguard-20b" },
  { id: "LLM-01", role: "llm", duty: "Moteur généraliste n°1", model: "deepseek/deepseek-v3.2" },
  { id: "LLM-02", role: "llm", duty: "Moteur rapide basse latence", model: "google/gemini-2.5-flash" },
  { id: "LLM-03", role: "llm", duty: "Raisonnement court & triage", model: "anthropic/claude-3.5-haiku" },
  { id: "LLM-04", role: "llm", duty: "Moteur multilingue", model: "mistralai/mistral-small-3.2-24b-instruct" },
  { id: "LLM-05", role: "llm", duty: "Moteur open weights 70B", model: "meta-llama/llama-3.3-70b-instruct" },
  { id: "LLM-06", role: "llm", duty: "Analyse de code & scripts", model: "qwen/qwen3-coder-480b-a35b-instruct" },
  { id: "LLM-07", role: "llm", duty: "Longue fenêtre contextuelle", model: "nvidia/nemotron-3-super-120b-a12b" },
  { id: "LLM-08", role: "llm", duty: "Moteur de repli généraliste", model: "z-ai/glm-5.2" },
  { id: "MEM-01", role: "memoire", duty: "Banque d'incidents", model: "openai/gpt-5.4-nano", tag: "mem0" },
  { id: "MEM-02", role: "memoire", duty: "Référentiel d'IOC", model: "openai/gpt-5.4-nano", tag: "mem0" },
  { id: "MEM-03", role: "memoire", duty: "Historique de verdicts", tag: "mem0" },
  { id: "MEM-04", role: "memoire", duty: "Campagnes adverses connues", tag: "mem0" },
  { id: "MEM-05", role: "memoire", duty: "Graphe d'entités malveillantes", tag: "graphe" },
  { id: "MEM-06", role: "memoire", duty: "Cache LRU des artefacts vus", tag: "cache" },
  { id: "MEM-07", role: "memoire", duty: "Mémoire épisodique des ripostes", tag: "épisode" },
  { id: "MEM-08", role: "memoire", duty: "Playbooks & procédures appris", tag: "procédure" },
  { id: "OUV-01", role: "ouvriere", duty: "Analyste primaire (flux temps réel)", model: "openai/gpt-oss-20b" },
  { id: "OUV-02", role: "ouvriere", duty: "Pré-détonation d'URL", model: "google/gemma-4-31b-it" },
  { id: "OUV-03", role: "ouvriere", duty: "Triage phishing", model: "microsoft/phi-4" },
  { id: "OUV-04", role: "ouvriere", duty: "Extraction d'IOC", model: "moonshotai/kimi-k2.5" },
  { id: "OUV-05", role: "ouvriere", duty: "Rédaction de rapports", model: "stepfun/step-3.5-flash" },
  { id: "OUV-06", role: "ouvriere", duty: "Recoupement darknet", model: "tencent/hunyuan-a13b-instruct" },
];

export interface PipelineStep {
  agent: string;
  label: string;
  kind: "LOCAL" | "IA" | "IA · STREAM" | "MEM0";
}

export const PIPELINE: PipelineStep[] = [
  { agent: "SUP-01", label: "Routage de la requête vers la chaîne d'analyse", kind: "LOCAL" },
  { agent: "GF-01", label: "Garde-fou d'entrée — llama-guard 4 (12B)", kind: "IA" },
  { agent: "OUV-01", label: "Analyse ouvrière en flux temps réel", kind: "IA · STREAM" },
  { agent: "MEM-01", label: "Rappel mem0 puis écriture en banque", kind: "MEM0" },
  { agent: "SUP-02", label: "Synthèse superviseur & verdict", kind: "IA" },
  { agent: "GF-02", label: "Garde-fou de sortie — filtrage local", kind: "LOCAL" },
];

export const SWARM_EXAMPLES = [
  "E-mail « Ameli : remboursement de 284,90 € » — expéditeur ameli@cpam-remboursement.top",
  "Un compte Telegram « Barid Bank Support » me demande mon code OTP par message",
  "L'IP 105.158.44.17 scanne notre serveur de Casablanca toutes les 4 secondes depuis 2 h",
  "Notre boutique en ligne (Paris) redirige parfois les clients vers une page en .xyz",
];

/* ------------------------------------------------------------------ */
/* Mode réel — sources publiques de renseignement                      */
/* ------------------------------------------------------------------ */

export const BRAVE_API_KEY = "BSAq1DN5k0fnKRNudkcPittnCR0SuMV.";
export const API_NINJAS_KEY = "raGrcnzRKEm0mAwsmWsyrUuq25hfv1ouZH1h1FVq";

export type LiveSourceId = "THREATFOX" | "FEODO" | "URLHAUS" | "MALWAREBAZAAR" | "CVE";

export const LIVE_SOURCES: Record<LiveSourceId, { name: string; org: string }> = {
  THREATFOX: { name: "ThreatFox", org: "abuse.ch — IOC mondiaux" },
  FEODO: { name: "Feodo Tracker", org: "abuse.ch — C2 botnets" },
  URLHAUS: { name: "URLhaus", org: "abuse.ch — URLs malveillantes" },
  MALWAREBAZAAR: { name: "MalwareBazaar", org: "abuse.ch — échantillons" },
  CVE: { name: "CVE Watch", org: "CIRCL → NVD — vulnérabilités publiées" },
};
