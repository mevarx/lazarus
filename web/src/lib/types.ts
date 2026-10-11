// TypeScript types mirroring the Lazarus Python backend (app.py) EXACTLY.
// These are derived from the live API responses — do not invent fields.
// Backend routes: /api/findings, /api/cached, /api/graph, /api/skills,
//                 /api/narrate (POST), /api/run (SSE)

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type Ecosystem = 'npm' | 'pypi' | string

/** RDAP registration record for a domain. */
export interface Rdap {
  domain: string
  registered: boolean
  created: string | null // ISO timestamp
  expires: string | null
  status: string[]
  error: string | null
}

/** AI-generated (Gemma/Ollama/offline) explanation of a finding. */
export interface Narrative {
  verdict: string
  narrative: string
  recommendation: string
}

/**
 * A single domain-takeover risk finding.
 * Maintainer emails are MASKED server-side (ati****@domain) before they
 * reach the client — never assume a raw email is present.
 */
export interface Finding {
  domain: string
  ecosystem: Ecosystem
  packages: string[]
  maintainers: string[] // masked, e.g. "ati****@atlantis-software.net"
  dependents: number
  downloads_week: number
  maintainer_dormant: boolean | null
  last_publish: string | null
  mx_present: boolean | null
  rdap: Rdap
  /** Present only on the real node-ipc case. */
  incident?: {
    title: string
    date: string
    malicious_versions: string[]
    detail: string
  }
  /** Heuristic score 0-100. An ESTIMATE, not proof of takeover. */
  risk: number
  severity: Severity
  /** Human-readable strings describing which rules fired. */
  signals: string[]
  /** Point-by-point breakdown of the score. */
  reasoning: string[]
  /** Pre-written narrative for seeded runs; live runs narrate on demand. */
  narrative?: Narrative
}

export interface Stats {
  critical: number
  high: number
  medium: number
  low: number
  total: number
  avg_risk: number
  total_dependents: number
  domains: number
}

/** Whether the narration backend is live and which model. */
export interface JudgeStatus {
  live: boolean
  backend: string // e.g. "gemma-4-31b-it (live)", "ollama (live)", "offline-template"
  has_key: boolean
}

export type FindingsSource = 'last-run' | 'cached' | 'seed' | string

/** Blast radius — combined impact controlled by at-risk (HIGH+) domains. */
export interface BlastRadius {
  at_risk_domains: number
  at_risk_packages: number
  combined_weekly_downloads: number
  combined_dependents: number
  largest_single_domain: string | null
  largest_single_downloads: number
}

/** GET /api/findings and GET /api/cached response. */
export interface FindingsPayload {
  findings: Finding[]
  source: FindingsSource
  seeded: boolean
  count: number
  stats: Stats
  blast_radius?: BlastRadius
  updated_at?: string
  // judge status fields spread in
  live: boolean
  backend: string
  has_key: boolean
}

export type NodeType = 'domain' | 'maintainer' | 'package'

export interface GraphNode {
  id: string
  type: NodeType
  label: string
  risk: number
}

export interface GraphEdge {
  source: string
  target: string
  label: string // "hosts email" | "maintains"
}

/** GET /api/graph response. */
export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/** GET /api/skills response. */
export interface Skill {
  name: string
  description: string
}

export interface SkillsPayload {
  skills: Skill[]
}

/** POST /api/narrate response. */
export interface NarrateResponse extends Narrative {
  backend: string
}

// --- SSE events from GET /api/run ---

export interface RunStartEvent {
  mode: 'live' | 'demo'
  timestamp: string
  note: string
}

export interface RunProgressEvent {
  stage: string
  message: string
  done: number
  total: number
  elapsed: number
}

export interface RunFindingEvent {
  finding: Finding
  index: number
}

export interface RunDoneEvent {
  mode: string
  finished_at: string
  elapsed_s: number
  findings_count: number
  stats: Stats
  blast_radius?: BlastRadius
}

export interface RunFailedEvent {
  message: string
}

export type RunEvent =
  | { type: 'start'; data: RunStartEvent }
  | { type: 'progress'; data: RunProgressEvent }
  | { type: 'finding'; data: RunFindingEvent }
  | { type: 'done'; data: RunDoneEvent }
  | { type: 'failed'; data: RunFailedEvent }
