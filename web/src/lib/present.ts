// Presentation helpers for severity and risk. Colors match the design brief:
// green healthy / orange high / red critical, restrained amber accents.

import type { Finding, Severity, Stats } from './types'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

/** CSS custom-property color for a severity (defined in index.css). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: 'hsl(var(--risk-critical))',
  HIGH: 'hsl(var(--risk-high))',
  MEDIUM: 'hsl(var(--risk-medium))',
  LOW: 'hsl(var(--risk-low))',
}

export function severityOf(risk: number): Severity {
  if (risk >= 80) return 'CRITICAL'
  if (risk >= 60) return 'HIGH'
  if (risk >= 35) return 'MEDIUM'
  return 'LOW'
}

export function severityColor(sev: Severity | string): string {
  return SEVERITY_COLOR[(sev as Severity) in SEVERITY_COLOR ? (sev as Severity) : 'LOW']
}

/** Sort findings highest-risk first (stable on domain for ties). */
export function byRiskDesc(a: Finding, b: Finding): number {
  return b.risk - a.risk || a.domain.localeCompare(b.domain)
}

export function formatNumber(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '—'
  return n.toLocaleString('en-US')
}

/** "2026-05-07T11:49:33Z" -> "2026-05-07". Null-safe. */
export function shortDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return iso.slice(0, 10)
}

/** Days from now until an ISO date; negative = past. Null-safe. */
export function daysUntil(iso: string | null | undefined, now = new Date()): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return null
  return Math.round((t - now.getTime()) / 86_400_000)
}

export function totalFindings(stats: Stats): number {
  return stats.CRITICAL + stats.HIGH + stats.MEDIUM + stats.LOW
}
