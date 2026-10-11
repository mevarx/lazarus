// Findings page — searchable, filterable, sortable list with the evidence
// panel alongside. All data is real backend data.

import { useMemo, useState } from 'react'
import { DashboardCard, DetailHeader } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import { FindingRow } from './FindingRow'
import { EvidencePanel } from './EvidencePanel'
import { SEVERITY_LABEL, byRiskDesc, formatNumber } from '@/lib/present'
import type { Finding, Narrative, Severity } from '@/lib/types'

type FindingsProps = {
  findings: Finding[]
  seeded: boolean
  backend: string
  selectedDomain: string | null
  onSelect: (domain: string | null) => void
  narratives: Record<string, Narrative>
  narratingDomain: string | null
  narrateErrors: Record<string, string>
  onNarrate: (finding: Finding) => void
}

type SortKey = 'risk' | 'domain' | 'dependents' | 'downloads'

export function Findings({
  findings,
  seeded,
  backend,
  selectedDomain,
  onSelect,
  narratives,
  narratingDomain,
  narrateErrors,
  onNarrate,
}: FindingsProps) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL')
  const [sort, setSort] = useState<SortKey>('risk')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    let list = findings.filter((f) => {
      const matchesQuery =
        !q ||
        f.domain.toLowerCase().includes(q) ||
        f.packages.some((p) => p.toLowerCase().includes(q)) ||
        f.maintainers.some((m) => m.toLowerCase().includes(q))
      const matchesSev = severity === 'ALL' || f.severity === severity
      return matchesQuery && matchesSev
    })
    list = list.sort((a, b) => {
      switch (sort) {
        case 'domain':
          return a.domain.localeCompare(b.domain)
        case 'dependents':
          return b.dependents - a.dependents
        case 'downloads':
          return b.downloads_week - a.downloads_week
        default:
          return byRiskDesc(a, b)
      }
    })
    return list
  }, [findings, query, severity, sort])

  const selected = selectedDomain
    ? findings.find((f) => f.domain === selectedDomain) ?? null
    : null

  return (
    <div className="grid flex-1 grid-cols-1 gap-4 p-4 md:p-6 xl:grid-cols-[1fr_22rem]">
      <div className="flex min-w-0 flex-col gap-3">
        <DetailHeader
          title="Findings"
          subtitle={`${formatNumber(filtered.length)} of ${formatNumber(findings.length)} shown${
            seeded ? ' · seeded replay' : ''
          }`}
        />

        {/* controls: search, severity, sort */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search domain, package, maintainer…"
            aria-label="Search findings"
            className="h-9 min-w-0 flex-1 rounded-md border border-border bg-background px-3 text-sm text-foreground"
          />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | 'ALL')}
            aria-label="Filter by severity"
            className="h-9 rounded-md border border-border bg-background px-2 text-sm text-foreground"
          >
            <option value="ALL">All severities</option>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABEL[s]}
              </option>
            ))}
          </select>
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as SortKey)}
            aria-label="Sort by"
            className="h-9 rounded-md border border-border bg-background px-2 text-sm text-foreground"
          >
            <option value="risk">Sort: risk</option>
            <option value="domain">Sort: domain</option>
            <option value="dependents">Sort: dependents</option>
            <option value="downloads">Sort: downloads</option>
          </select>
        </div>

        {filtered.length === 0 ? (
          <DashboardCard className="py-12 text-center text-sm text-muted-foreground">
            {findings.length === 0
              ? 'No findings. Run a scan to populate this list.'
              : 'No findings match your filters.'}
          </DashboardCard>
        ) : (
          <div className="flex flex-col gap-2">
            {filtered.map((f) => (
              <FindingRow
                key={f.domain}
                finding={f}
                selected={f.domain === selectedDomain}
                narrating={narratingDomain === f.domain}
                onSelect={() => onSelect(f.domain === selectedDomain ? null : f.domain)}
                onNarrate={() => onNarrate(f)}
              />
            ))}
          </div>
        )}
      </div>

      {/* evidence panel for the selected finding */}
      <aside className="min-w-0">
        {selected ? (
          <DashboardCard>
            <EvidencePanel
              finding={selected}
              narrative={narratives[selected.domain] ?? null}
              narrating={narratingDomain === selected.domain}
              narrateError={narrateErrors[selected.domain] ?? null}
              backend={backend}
            />
          </DashboardCard>
        ) : (
          <DashboardCard className="py-12 text-center text-sm text-muted-foreground">
            Select a finding to view its evidence and analysis.
          </DashboardCard>
        )}
      </aside>
    </div>
  )
}
