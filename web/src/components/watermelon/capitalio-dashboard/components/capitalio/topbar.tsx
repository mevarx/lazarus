import { SidebarTrigger } from '@/components/ui/sidebar'
import { Button } from '@/components/ui/button'
import { useDashboardNavigation } from './navigation'
import { getPageTitle } from '../../data'
import type { ScanState } from './lazarus-types'

type TopbarProps = {
  scan: ScanState
  onRunScan: () => void
}

const STATUS_TONE: Record<ScanState['status'], { dot: string; label: string }> = {
  idle: { dot: 'bg-muted-foreground/50', label: 'Idle' },
  loading: { dot: 'bg-amber-400 animate-pulse', label: 'Loading' },
  running: { dot: 'bg-amber-400 animate-pulse', label: 'Scanning' },
  done: { dot: 'bg-emerald-400', label: 'Complete' },
  error: { dot: 'bg-red-400', label: 'Failed' },
}

export function DashboardTopbar({ scan, onRunScan }: TopbarProps) {
  const { pathname } = useDashboardNavigation()
  const title = getPageTitle(pathname)
  const tone = STATUS_TONE[scan.status]
  const running = scan.status === 'running' || scan.status === 'loading'

  return (
    <header className="flex shrink-0 flex-col gap-3 border-b border-border px-4 py-3 md:flex-row md:items-center md:justify-between md:px-8">
      <div className="flex min-w-0 items-center gap-3">
        <SidebarTrigger className="size-8.5 shrink-0 md:hidden [&_svg]:size-5!" />
        <div className="flex min-w-0 flex-1 flex-col gap-1.5">
          <h1 className="truncate text-lg font-semibold leading-none text-foreground md:text-xl">
            {title}
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {/* scan status + last scan timestamp */}
            <span className="flex items-center gap-1.5" data-testid="scan-status">
              <span className={`size-2 shrink-0 rounded-full ${tone.dot}`} />
              <span className="font-medium text-foreground">{tone.label}</span>
              {scan.lastScanAt ? (
                <span className="font-mono">· {scan.lastScanAt}</span>
              ) : null}
            </span>
            {/* data source: seeded replay vs live */}
            <span
              className="flex items-center gap-1.5"
              data-testid="source-badge"
              title={
                scan.seeded
                  ? 'Seeded replay (data/cached_run.json) — not a live scan. The atlantis-software.net case is real & RDAP-verified; companions are realistic.'
                  : 'Live scan — findings harvested and RDAP-resolved just now.'
              }
            >
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                  scan.seeded
                    ? 'bg-amber-400/15 text-amber-300'
                    : 'bg-emerald-400/15 text-emerald-300'
                }`}
              >
                {scan.seeded ? 'REPLAY · seeded' : 'LIVE · fresh scan'}
              </span>
            </span>
            {/* model / backend status */}
            <span className="flex items-center gap-1.5" data-testid="backend-badge">
              <span className="text-muted-foreground">model:</span>
              <span className="font-mono text-foreground">{scan.backend}</span>
              {!scan.modelLive ? (
                <span className="text-amber-300">(offline template)</span>
              ) : null}
            </span>
          </div>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <Button
          onClick={onRunScan}
          disabled={running}
          aria-busy={running}
          data-testid="run-scan"
          className="gap-2"
        >
          {running ? (
            <>
              <span className="size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
              Scanning…
            </>
          ) : (
            'Run scan'
          )}
        </Button>
      </div>
    </header>
  )
}
