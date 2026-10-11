// A single prioritized finding card. Shows domain, risk/severity, ecosystem,
// creation/expiry, packages, dependents, downloads, masked maintainer,
// signals + RDAP status, and the View Analysis / Explain with AI actions.

import { DashboardCard } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import {
  SEVERITY_COLOR,
  SEVERITY_LABEL,
  daysUntil,
  formatNumber,
  shortDate,
} from '@/lib/present'
import type { Finding } from '@/lib/types'

type RowProps = {
  finding: Finding
  selected: boolean
  narrating: boolean
  onSelect: () => void
  onNarrate: () => void
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="font-mono text-xs text-foreground">{value}</span>
    </div>
  )
}

export function FindingRow({ finding, selected, narrating, onSelect, onNarrate }: RowProps) {
  const color = SEVERITY_COLOR[finding.severity]
  const expiryDays = daysUntil(finding.rdap?.expires ?? null)

  return (
    <DashboardCard
      className={
        'flex flex-col gap-3 transition-colors ' +
        (selected ? 'ring-1 ring-primary' : '')
      }
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex items-center gap-2">
            <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: color }} />
            <button
              type="button"
              onClick={onSelect}
              className="truncate font-mono text-base font-semibold text-foreground hover:underline"
            >
              {finding.domain}
            </button>
            <span
              className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
              style={{ color, backgroundColor: `color-mix(in oklab, ${color} 15%, transparent)` }}
            >
              {SEVERITY_LABEL[finding.severity]}
            </span>
            {finding.incident ? (
              <span
                className="rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-red-300"
                title={finding.incident.detail}
              >
                known incident
              </span>
            ) : null}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {finding.signals.slice(0, 4).map((s) => (
              <span
                key={s}
                className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground"
              >
                {s}
              </span>
            ))}
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-end gap-1">
          <div className="font-mono text-2xl font-semibold leading-none" style={{ color }}>
            {finding.risk}
          </div>
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
            risk / 100
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-6">
        <Field label="Ecosystem" value={finding.ecosystem} />
        <Field label="Created" value={shortDate(finding.rdap?.created)} />
        <Field
          label="Expires"
          value={
            expiryDays == null
              ? shortDate(finding.rdap?.expires)
              : `${shortDate(finding.rdap?.expires)} (${expiryDays}d)`
          }
        />
        <Field label="Dependents" value={formatNumber(finding.dependents)} />
        <Field label="Downloads/wk" value={formatNumber(finding.downloads_week)} />
        <Field label="Maintainer" value={finding.maintainers?.[0] ?? '—'} />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2">
        <div className="flex flex-wrap gap-1.5 text-xs text-muted-foreground">
          {finding.packages.slice(0, 4).map((p) => (
            <span key={p} className="rounded bg-secondary px-1.5 py-0.5 font-mono">
              {p}
            </span>
          ))}
          {finding.packages.length > 4 ? (
            <span className="self-center">+{finding.packages.length - 4} more</span>
          ) : null}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onSelect}
            className="rounded-md border border-border px-2.5 py-1 text-xs font-medium text-foreground hover:bg-secondary"
          >
            View analysis
          </button>
          <button
            type="button"
            onClick={onNarrate}
            disabled={narrating}
            className="rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-60"
          >
            {narrating ? 'Explaining…' : 'Explain with AI'}
          </button>
        </div>
      </div>
    </DashboardCard>
  )
}
