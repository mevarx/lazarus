// Security overview — the top-level metrics and prioritized findings.
// All values come from real backend data (FindingsPayload). No invented
// numbers: when the backend is unreachable the cards show an explicit
// offline state rather than fabricated values.

import { useMemo, useState } from 'react'
import { DashboardCard, DetailHeader } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import { FindingRow } from './FindingRow'
import { SEVERITY_COLOR, SEVERITY_LABEL, byRiskDesc, formatNumber, totalFindings } from '@/lib/present'
import type { Finding, Severity, Stats } from '@/lib/types'

type OverviewProps = {
  findings: Finding[]
  stats: Stats
  seeded: boolean
  onSelect: (finding: Finding) => void
  selectedDomain: string | null
  onNarrate: (finding: Finding) => void
  narratingDomain: string | null
}

function MetricCard({
  label,
  value,
  color,
  hint,
}: {
  label: string
  value: string
  color?: string
  hint?: string
}) {
  return (
    <DashboardCard className="flex flex-col gap-1">
      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="font-mono text-2xl font-semibold leading-none" style={color ? { color } : undefined}>
        {value}
      </div>
      {hint ? <div className="text-xs text-muted-foreground">{hint}</div> : null}
    </DashboardCard>
  )
}

export function SecurityOverview({
  findings,
  stats,
  seeded,
  onSelect,
  selectedDomain,
  onNarrate,
  narratingDomain,
}: OverviewProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')

  const sorted = useMemo(() => findings.slice().sort(byRiskDesc), [findings])
  const shown = useMemo(
    () => (severityFilter === 'ALL' ? sorted : sorted.filter((f) => f.severity === severityFilter)),
    [sorted, severityFilter],
  )

  const total = totalFindings(stats)

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <DetailHeader
        title="Security overview"
        subtitle={
          seeded
            ? 'Seeded replay — heuristic estimates, not confirmed takeovers'
            : 'Live scan — heuristic estimates, not confirmed takeovers'
        }
      />

      {/* Overview metrics — all from real backend stats */}
      <section className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7" aria-label="Overview metrics">
        <MetricCard label="Total findings" value={formatNumber(total)} />
        <MetricCard label="Critical" value={formatNumber(stats.CRITICAL)} color={SEVERITY_COLOR.CRITICAL} />
        <MetricCard label="High" value={formatNumber(stats.HIGH)} color={SEVERITY_COLOR.HIGH} />
        <MetricCard label="Medium" value={formatNumber(stats.MEDIUM)} color={SEVERITY_COLOR.MEDIUM} />
        <MetricCard label="Low" value={formatNumber(stats.LOW)} color={SEVERITY_COLOR.LOW} />
        <MetricCard
          label="Avg risk"
          value={total ? stats.avg_risk.toFixed(1) : '—'}
          hint="heuristic 0–100"
        />
        <MetricCard label="Dependents" value={formatNumber(stats.total_dependents)} />
      </section>

      {/* Findings list with severity filter */}
      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-base font-semibold">Prioritized findings</h2>
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
              const active = severityFilter === sev
              const color = sev === 'ALL' ? undefined : SEVERITY_COLOR[sev]
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  aria-pressed={active}
                  className="rounded-md border px-2.5 py-1 text-xs font-medium transition-colors"
                  style={
                    active
                      ? {
                          borderColor: color ?? 'hsl(var(--primary))',
                          color: color ?? 'hsl(var(--primary-foreground))',
                          backgroundColor: color
                            ? `color-mix(in oklab, ${color} 18%, transparent)`
                            : 'hsl(var(--primary))',
                        }
                      : { borderColor: 'hsl(var(--border))', color: 'hsl(var(--muted-foreground))' }
                  }
                >
                  {sev === 'ALL' ? 'All' : SEVERITY_LABEL[sev]}
                </button>
              )
            })}
          </div>
        </div>

        {shown.length === 0 ? (
          <DashboardCard className="py-10 text-center text-sm text-muted-foreground">
            {findings.length === 0
              ? 'No findings yet. Run a scan to populate this list.'
              : `No ${SEVERITY_LABEL[severityFilter as Severity].toLowerCase()} findings.`}
          </DashboardCard>
        ) : (
          <div className="flex flex-col gap-2">
            {shown.map((f) => (
              <FindingRow
                key={f.domain}
                finding={f}
                selected={f.domain === selectedDomain}
                onSelect={() => onSelect(f)}
                onNarrate={() => onNarrate(f)}
                narrating={narratingDomain === f.domain}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
