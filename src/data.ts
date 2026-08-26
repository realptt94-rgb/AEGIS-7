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
  { ip: "185.220.101.47", city: "Francfort", cc: "DE" },
  { ip: "91.242.217.9", city: "Saint-Pétersbourg", cc: "RU" },
  { ip: "45.155.205.86", city: "Amsterdam", cc: "NL" },
  { ip: "103.75.190.11", city: "Hanoï", cc: "VN" },
  { ip: "196.251.72.140", city: "Lagos", cc: "NG" },
  { ip: "177.54.144.208", city: "São Paulo", cc: "BR" },
  { ip: "5.62.61.133", city: "Téhéran", cc: "IR" },
  { ip: "116.105.77.29", city: "Hô Chi Minh-Ville", cc: "VN" },
  { ip: "89.248.174.66", city: "Rotterdam", cc: "NL" },
  { ip: "62.76.188.12", city: "Moscou", cc: "RU" },
  { ip: "14.224.163.55", city: "Manille", cc: "PH" },
  { ip: "197.210.64.97", city: "Abuja", cc: "NG" },
  { ip: "31.210.20.184", city: "Izmir", cc: "TR" },
  { ip: "94.232.43.71", city: "Minsk", cc: "BY" },
  { ip: "36.92.111.18", city: "Jakarta", cc: "ID" },
  { ip: "175.111.181.6", city: "Dacca", cc: "BD" },
];

export const ACTIONS = ["NEUTRALISÉ", "BLOQUÉ", "QUARANTAINE", "LEURRÉ (HONEYPOT)"] as const;

export const TARGETS = [
  "passerelle-paiement",
  "serveur-auth",
  "api-utilisateurs",
  "port 443 (HTTPS)",
  "port 22 (SSH)",
  "base clients CRM",
  "boîte mail direction",
  "portail employés",
  "DNS interne",
  "coffre-fort secrets",
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
    desc: "Analyse sémantique des messages et des URL : domaines jumeaux, homoglyphes, leurres de marque. Les liens reçus sur Telegram et par mail sont pré-détonnés en bac à sable.",
    status: "ACTIF",
    metric: "18 400 leurrs bloqués / 24 h",
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
    desc: "Crawlers TorBot surveillent les places de marché .onion à la recherche de données volées vous concernant. Alerte immédiate si des identifiants fuient.",
    status: "EN PATROUILLE",
    metric: "312 marchés scrutés",
    span: "lg:col-span-4",
  },
  {
    id: "tgwatch",
    title: "Écoute défensive Telegram",
    code: "MOD-05",
    desc: "Surveille les canaux et groupes où s'organisent raids, fuites et ventes d'accès. Détecte les campagnes de membres forcés et les bots d'arnaque avant qu'ils ne frappent.",
    status: "1 024 CANAUX",
    metric: "46 campagnes détectées",
    span: "lg:col-span-4",
  },
  {
    id: "soar",
    title: "Riposte automatisée SOAR",
    code: "MOD-06",
    desc: "Orchestre la contre-mesure : isolement d'hôte, coupure de session, blocage ASN, dépôt de preuve horodatée. Chaque action est journalisée et réversible.",
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
    detail: "Export : PDF, STIX/TAXII, chaîne de custody",
  },
];

/* ------------------------------------------------------------------ */
/* Bande défilante                                                     */
/* ------------------------------------------------------------------ */

export const TICKER_ITEMS = [
  "185.220.101.47 (Tor exit node) — accès refusé ×3",
  "Campagne de phishing Telegram « FAKE-INVEST » détectée — 1 204 canaux signalés",
  "Signature ransomware « BlackLotus-7 » ajoutée au référentiel",
  "Scan darknet terminé : 0 fuite de données identifiée",
  "Mise à jour du modèle neuronal NX-2 — précision +0,8 %",
  "46 bots d'arnaque bannis via coordination OSINT",
  "Tentative d'injection SQL sur api-utilisateurs — requête neutralisée",
  "Honeypot HP-3 : 17 attaquants piégés cette nuit",
  "Rotation automatique des secrets effectuée (coffre-fort)",
  "Veille .onion : 312 marchés scrutés, 2 alertes remontées",
];
