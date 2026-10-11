// Security overview — the top-level metrics and prioritized findings.
// All values come from real backend data (FindingsPayload). No invented
// numbers: when the backend is unreachable the cards show an explicit
// offline state rather than fabricated values.

import { useMemo, useState } from 'react'
import { DashboardCard, DetailHeader } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import { FindingRow } from './FindingRow'
import { SEVERITY_COLOR, SEVERITY_LABEL, byRiskDesc, formatNumber, totalFindings } from '@/lib/present'
import type { BlastRadius, Finding, Severity, Stats } from '@/lib/types'

type OverviewProps = {
  findings: Finding[]
  stats: Stats
  blast: BlastRadius
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
    <DashboardCard
      className="flex flex-col gap-1.5 p-3.5"
      style={
        color
          ? { borderColor: `color-mix(in oklab, ${color} 35%, transparent)`, background: `color-mix(in oklab, ${color} 8%, hsl(var(--card)))` }
          : undefined
      }
    >
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className="font-mono text-2xl font-bold leading-none tabular-nums"
        style={color ? { color } : undefined}
      >
        {value}
      </div>
      {hint ? <div className="text-[11px] text-muted-foreground">{hint}</div> : null}
    </DashboardCard>
  )
}

export function SecurityOverview({
  findings,
  stats,
  blast,
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

      {/* Blast-radius banner — the headline: how much the at-risk domains control */}
      {blast.at_risk_domains > 0 ? (
        <DashboardCard
          className="flex flex-col gap-1 border-l-2 p-4"
          style={{ borderLeftColor: 'hsl(var(--risk-high))' }}
        >
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            Blast radius
          </div>
          <p className="text-sm leading-relaxed text-foreground">
            <span className="font-mono font-bold" style={{ color: 'hsl(var(--risk-high))' }}>
              {blast.at_risk_domains}
            </span>{' '}
            at-risk {blast.at_risk_domains === 1 ? 'domain controls' : 'domains control'}{' '}
            packages with{' '}
            <span className="font-mono font-bold" style={{ color: 'hsl(var(--risk-high))' }}>
              {formatNumber(blast.combined_weekly_downloads)}
            </span>{' '}
            combined weekly downloads across{' '}
            <span className="font-mono font-semibold">{blast.at_risk_packages}</span>{' '}
            {blast.at_risk_packages === 1 ? 'package' : 'packages'}.
            {blast.largest_single_domain ? (
              <>
                {' '}
                Largest:{' '}
                <span className="font-mono font-semibold">{blast.largest_single_domain}</span> (
                {formatNumber(blast.largest_single_downloads)} weekly downloads).
              </>
            ) : null}
          </p>
        </DashboardCard>
      ) : null}

      {/* Overview metrics — all from real backend stats */}
      <section className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7" aria-label="Overview metrics">
        <MetricCard label="Total findings" value={formatNumber(total)} />
        <MetricCard label="Critical" value={formatNumber(stats.critical)} color={SEVERITY_COLOR.CRITICAL} />
        <MetricCard label="High" value={formatNumber(stats.high)} color={SEVERITY_COLOR.HIGH} />
        <MetricCard label="Medium" value={formatNumber(stats.medium)} color={SEVERITY_COLOR.MEDIUM} />
        <MetricCard label="Low" value={formatNumber(stats.low)} color={SEVERITY_COLOR.LOW} />
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
