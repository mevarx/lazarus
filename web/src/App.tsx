// Lazarus dashboard root.
// Wires the Capitalio shell (sidebar/topbar/layout) to the Python backend:
//   - loads findings + graph on mount (falls back to the seeded replay)
//   - Run Scan streams a live scan over SSE
//   - Explain with AI calls POST /api/narrate
// The scan engine, risk model, and backend are untouched — this is UI only.

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  DashboardNavigationProvider,
  useDashboardNavigation,
} from './components/watermelon/capitalio-dashboard/components/capitalio/navigation'
import DashboardLayout from './components/watermelon/capitalio-dashboard/dashboard-layout'
import { SecurityOverview } from './components/lazarus/SecurityOverview'
import { Findings } from './components/lazarus/Findings'
import { DependencyGraph } from './components/lazarus/DependencyGraph'
import { fetchCached, fetchFindings, fetchGraph, narrate, runScan } from './lib/api'
import type { Finding, Graph, Narrative } from './lib/types'
import type { ScanState } from './components/watermelon/capitalio-dashboard/components/capitalio/lazarus-types'

const EMPTY_STATS = {
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  total: 0,
  avg_risk: 0,
  total_dependents: 0,
  domains: 0,
}

function Dashboard() {
  const { pathname } = useDashboardNavigation()

  const [findings, setFindings] = useState<Finding[]>([])
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] })
  const [stats, setStats] = useState(EMPTY_STATS)
  const [seeded, setSeeded] = useState(true)
  const [backend, setBackend] = useState('offline-template')
  const [modelLive, setModelLive] = useState(false)
  const [lastScanAt, setLastScanAt] = useState<string | null>(null)

  const [selectedDomain, setSelectedDomain] = useState<string | null>(null)
  const [narratives, setNarratives] = useState<Record<string, Narrative>>({})
  const [narratingDomain, setNarratingDomain] = useState<string | null>(null)
  const [narrateErrors, setNarrateErrors] = useState<Record<string, string>>({})

  const [scan, setScan] = useState<ScanState>({
    status: 'idle',
    lastScanAt: null,
    seeded: true,
    backend: 'offline-template',
    modelLive: false,
    stageMessage: null,
    error: null,
  })

  const runningRef = useRef(false)

  // --- initial load: current findings, falling back to the seeded replay ---
  const loadInitial = useCallback(async () => {
    try {
      const payload = await fetchFindings()
      setFindings(payload.findings)
      setStats(payload.stats)
      setSeeded(payload.seeded)
      setBackend(payload.backend)
      setModelLive(payload.live)
      setLastScanAt(payload.updated_at ?? null)
      setScan((s) => ({
        ...s,
        status: 'done',
        seeded: payload.seeded,
        backend: payload.backend,
        modelLive: payload.live,
        lastScanAt: payload.updated_at ?? null,
      }))
    } catch {
      // backend unreachable — try the seeded replay so the UI still renders
      try {
        const cached = await fetchCached()
        setFindings(cached.findings)
        setStats(cached.stats)
        setSeeded(true)
        setBackend(cached.backend)
        setModelLive(cached.live)
        setScan((s) => ({ ...s, status: 'done', seeded: true, error: null }))
      } catch {
        setScan((s) => ({
          ...s,
          status: 'error',
          error: 'Cannot reach the Lazarus backend. Start it with: python app.py',
        }))
      }
    }
    try {
      setGraph(await fetchGraph())
    } catch {
      /* graph is optional */
    }
  }, [])

  useEffect(() => {
    void loadInitial()
  }, [loadInitial])

  // --- Run Scan: stream a live scan over SSE, prevent double-submits ---
  const handleRunScan = useCallback(() => {
    if (runningRef.current) return
    runningRef.current = true
    setSelectedDomain(null)
    setScan((s) => ({ ...s, status: 'running', stageMessage: 'starting…', error: null }))
    void runScan(
      (event) => {
        if (event.type === 'progress') {
          setScan((s) => ({ ...s, stageMessage: event.data.message }))
        } else if (event.type === 'finding') {
          setFindings((prev) => {
            const map = new Map(prev.map((f) => [f.domain, f]))
            map.set(event.data.finding.domain, event.data.finding)
            return [...map.values()]
          })
        } else if (event.type === 'done') {
          setStats(event.data.stats)
          setSeeded(event.data.mode !== 'live')
          const at = new Date().toISOString()
          setLastScanAt(at)
          setScan((s) => ({
            ...s,
            status: 'done',
            lastScanAt: at,
            seeded: event.data.mode !== 'live',
            stageMessage: null,
          }))
        } else if (event.type === 'failed') {
          setScan((s) => ({ ...s, status: 'error', error: event.data.message }))
        }
      },
      { limit: 25 },
    )
      .then(async () => {
        try {
          setGraph(await fetchGraph())
        } catch {
          /* optional */
        }
      })
      .finally(() => {
        runningRef.current = false
      })
  }, [])

  // --- Explain with AI ---
  const handleNarrate = useCallback(async (finding: Finding) => {
    setNarratingDomain(finding.domain)
    setNarrateErrors((e) => ({ ...e, [finding.domain]: '' }))
    try {
      const res = await narrate(finding.domain)
      setNarratives((n) => ({ ...n, [finding.domain]: res }))
    } catch (err) {
      setNarrateErrors((e) => ({
        ...e,
        [finding.domain]: err instanceof Error ? err.message : 'narration failed',
      }))
    } finally {
      setNarratingDomain(null)
    }
  }, [])

  const scanForTopbar: ScanState = {
    ...scan,
    lastScanAt: lastScanAt ?? scan.lastScanAt,
    seeded,
    backend,
    modelLive,
  }

  return (
    <DashboardLayout scan={scanForTopbar} onRunScan={handleRunScan}>
      {scan.status === 'error' && scan.error ? (
        <div className="mx-4 mt-3 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300 md:mx-6">
          {scan.error}
        </div>
      ) : null}
      {pathname === '/' ? (
        <SecurityOverview
          findings={findings}
          stats={stats}
          seeded={seeded}
          selectedDomain={selectedDomain}
          onSelect={(f) => setSelectedDomain(f.domain)}
          onNarrate={handleNarrate}
          narratingDomain={narratingDomain}
        />
      ) : pathname === '/findings' ? (
        <Findings
          findings={findings}
          seeded={seeded}
          backend={backend}
          selectedDomain={selectedDomain}
          onSelect={setSelectedDomain}
          narratives={narratives}
          narratingDomain={narratingDomain}
          narrateErrors={narrateErrors}
          onNarrate={handleNarrate}
        />
      ) : pathname === '/dependencies' ? (
        <DependencyGraph
          graph={graph}
          selectedDomain={selectedDomain}
          onSelectDomain={setSelectedDomain}
        />
      ) : pathname === '/about' ? (
        <div className="flex flex-col gap-3 p-6">
          <h2 className="text-lg font-semibold">About Lazarus</h2>
          <p className="max-w-2xl text-sm text-muted-foreground">
            Lazarus watches npm and PyPI maintainer email domains for expiry
            and re-registration — the precondition for the domain-takeover
            supply-chain attack that compromised{' '}
            <span className="font-mono">node-ipc</span> in May 2026. Risk
            scores are heuristic estimates, not proof of takeover. Maintainer
            emails are masked before they reach this UI.
          </p>
        </div>
      ) : (
        <div className="p-6 text-sm text-muted-foreground">Nothing here yet.</div>
      )}
    </DashboardLayout>
  )
}

export default function App() {
  return (
    <DashboardNavigationProvider>
      <Dashboard />
    </DashboardNavigationProvider>
  )
}
