// Evidence & analysis panel for a selected finding.
// Strictly separates: OBSERVED data (RDAP facts), CALCULATED risk (score +
// reasoning), INFERRED concerns (suggested steps), and AI EXPLANATION
// (Gemma/Ollama/offline narrative). Never presents an expiry warning as
// proof of takeover, and labels the score as a heuristic estimate.

import { DetailHeader } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import { SEVERITY_COLOR, SEVERITY_LABEL, daysUntil, shortDate } from '@/lib/present'
import type { Finding, Narrative } from '@/lib/types'

type PanelProps = {
  finding: Finding
  /** AI explanation when the user has clicked Explain with AI; else null. */
  narrative: Narrative | null
  narrating: boolean
  narrateError: string | null
  backend: string
}

function Section({
  title,
  tone,
  children,
}: {
  title: string
  tone: 'observed' | 'calculated' | 'inferred' | 'ai'
  children: React.ReactNode
}) {
  const toneStyle: Record<typeof tone, string> = {
    observed: 'border-sky-400/40 text-sky-300',
    calculated: 'border-amber-400/40 text-amber-300',
    inferred: 'border-border text-muted-foreground',
    ai: 'border-violet-400/40 text-violet-300',
  }
  return (
    <section className="flex flex-col gap-2">
      <h3 className={`text-xs font-semibold uppercase tracking-wide ${toneStyle[tone].split(' ')[1]}`}>
        {title}
      </h3>
      <div className="text-sm text-foreground">{children}</div>
    </section>
  )
}

export function EvidencePanel({
  finding,
  narrative,
  narrating,
  narrateError,
  backend,
}: PanelProps) {
  const color = SEVERITY_COLOR[finding.severity]
  const expiryDays = daysUntil(finding.rdap?.expires ?? null)

  return (
    <div className="flex flex-col gap-4">
      <DetailHeader
        title={finding.domain}
        subtitle={`${SEVERITY_LABEL[finding.severity]} · risk ${finding.risk}/100 (heuristic estimate)`}
      >
        <span
          className="rounded px-2 py-1 text-xs font-semibold"
          style={{ color, backgroundColor: `color-mix(in oklab, ${color} 15%, transparent)` }}
        >
          {finding.severity}
        </span>
      </DetailHeader>

      {/* OBSERVED — ground-truth RDAP facts */}
      <Section title="Observed data (RDAP)" tone="observed">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-3">
          <div><dt className="text-muted-foreground">registered</dt><dd>{String(finding.rdap?.registered)}</dd></div>
          <div><dt className="text-muted-foreground">created</dt><dd>{shortDate(finding.rdap?.created)}</dd></div>
          <div>
            <dt className="text-muted-foreground">expires</dt>
            <dd>{expiryDays == null ? shortDate(finding.rdap?.expires) : `${shortDate(finding.rdap?.expires)} (${expiryDays}d)`}</dd>
          </div>
          <div><dt className="text-muted-foreground">maintainer</dt><dd>{finding.maintainers?.[0] ?? '—'}</dd></div>
          <div><dt className="text-muted-foreground">dormant</dt><dd>{String(finding.maintainer_dormant ?? '—')}</dd></div>
          <div><dt className="text-muted-foreground">MX live</dt><dd>{String(finding.mx_present ?? '—')}</dd></div>
        </dl>
        {finding.rdap?.error ? (
          <p className="mt-2 text-xs text-amber-300">RDAP note: {finding.rdap.error}</p>
        ) : null}
      </Section>

      {/* CALCULATED — the deterministic score breakdown */}
      <Section title="Calculated risk (scorer)" tone="calculated">
        <ul className="flex list-disc flex-col gap-1 pl-4 text-xs">
          {finding.reasoning.length ? (
            finding.reasoning.map((r, i) => <li key={i}>{r}</li>)
          ) : (
            <li className="text-muted-foreground">No scoring rules fired.</li>
          )}
        </ul>
        <p className="mt-2 text-xs text-muted-foreground">
          A score is a triage signal, not proof. An expiring or recently
          registered domain is a <em>precondition</em> for takeover, not a
          confirmed one.
        </p>
      </Section>

      {/* INFERRED — suggested investigation, clearly not fact */}
      <Section title="Suggested investigation (inferred)" tone="inferred">
        <ol className="flex list-decimal flex-col gap-1 pl-4 text-xs text-muted-foreground">
          <li>Confirm whether the maintainer still controls the mailbox on this domain.</li>
          <li>Check whether the domain changed hands (compare creation date to the project&apos;s history).</li>
          <li>If control is lost, treat any credential tied to this email as compromised and rotate.</li>
        </ol>
      </Section>

      {/* AI EXPLANATION — only after the user asks */}
      <Section title={`AI explanation (${backend})`} tone="ai">
        {narrating ? (
          <p className="text-xs text-muted-foreground">Querying the model…</p>
        ) : narrateError ? (
          <p className="text-xs text-red-300">{narrateError}</p>
        ) : narrative ? (
          <div className="flex flex-col gap-2">
            <p className="font-medium">{narrative.verdict}</p>
            <p className="text-xs leading-relaxed text-muted-foreground">{narrative.narrative}</p>
            <p className="text-xs">
              <span className="text-muted-foreground">Recommendation: </span>
              {narrative.recommendation}
            </p>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            Click &ldquo;Explain with AI&rdquo; on the finding to generate an explanation.
          </p>
        )}
      </Section>
    </div>
  )
}
