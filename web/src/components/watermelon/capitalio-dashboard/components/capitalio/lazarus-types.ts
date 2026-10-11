// Shared frontend state types for the Lazarus dashboard.
// These describe UI state only — the data shapes live in @/lib/types.

import type { Finding, JudgeStatus, Stats } from '@/lib/types'

export type ScanStatus = 'idle' | 'loading' | 'running' | 'done' | 'error'

export interface ScanState {
  status: ScanStatus
  /** ISO timestamp of the last completed scan, or null. */
  lastScanAt: string | null
  /** true when the current findings are the seeded replay, not a live scan. */
  seeded: boolean
  /** backend label, e.g. "gemma-4-31b-it (live)" / "ollama (live)" / "offline-template". */
  backend: string
  /** whether the narration model is live (vs the offline template). */
  modelLive: boolean
  /** current stage message while running. */
  stageMessage: string | null
  /** error message when status === 'error'. */
  error: string | null
}

/** Everything the dashboard needs from the backend, held at the app root. */
export interface DashboardData {
  findings: Finding[]
  stats: Stats
  judge: JudgeStatus
}
