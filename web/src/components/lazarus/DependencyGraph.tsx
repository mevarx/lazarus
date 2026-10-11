// Dependency graph panel — a focused radial view of ONE domain's blast radius:
// the domain at center, its maintainers in a ring, their packages in an outer
// ring. Uses the REAL graph from /api/graph (no fictional relationships).
// Hand-rolled SVG: zero extra dependencies. Fully responsive.

import { useMemo, useState } from 'react'
import { DashboardCard, DetailHeader } from '../watermelon/capitalio-dashboard/components/capitalio/shared'
import { SEVERITY_COLOR, severityOf } from '@/lib/present'
import type { Graph, GraphNode, NodeType } from '@/lib/types'

type GraphProps = {
  graph: Graph
  selectedDomain: string | null
  onSelectDomain: (domain: string | null) => void
}

const NODE_COLOR: Record<NodeType, string> = {
  domain: 'hsl(var(--primary))',
  maintainer: 'hsl(205 88% 62%)',
  package: 'hsl(275 78% 68%)',
}

interface Placed {
  id: string
  label: string
  type: NodeType
  risk: number
  x: number
  y: number
  r: number
}

// concentric placement: domains center, maintainers inner ring, packages outer
function place(nodes: GraphNode[], edges: Graph['edges'], w: number, h: number) {
  const cx = w / 2
  const cy = h / 2
  const domains = nodes.filter((n) => n.type === 'domain')
  const maint = nodes.filter((n) => n.type === 'maintainer')
  const pkgs = nodes.filter((n) => n.type === 'package')
  const unit = Math.min(w, h)

  const rings: { items: GraphNode[]; radius: number; base: number }[] = [
    { items: domains, radius: 0, base: 17 },
    { items: maint, radius: unit * 0.22, base: 9 },
    { items: pkgs, radius: unit * 0.4, base: 6 },
  ]
  const placed: Placed[] = []
  for (const ring of rings) {
    const n = ring.items.length
    ring.items.forEach((node, i) => {
      const angle = (i / Math.max(1, n)) * Math.PI * 2 - Math.PI / 2
      placed.push({
        id: node.id,
        label: node.label,
        type: node.type,
        risk: node.risk || 0,
        x: cx + Math.cos(angle) * ring.radius,
        y: cy + Math.sin(angle) * ring.radius,
        r: node.type === 'domain' ? ring.base : ring.base + Math.min(6, (node.risk || 0) / 16),
      })
    })
  }
  const byId = new Map(placed.map((p) => [p.id, p]))
  const links = edges
    .map((e) => ({ a: byId.get(e.source), b: byId.get(e.target), label: e.label }))
    .filter((l): l is { a: Placed; b: Placed; label: string } => !!l.a && !!l.b)
  return { placed, links }
}

function curve(a: Placed, b: Placed) {
  const mx = (a.x + b.x) / 2
  const my = (a.y + b.y) / 2
  const dx = b.x - a.x
  const dy = b.y - a.y
  // slight bow so overlapping edges separate visually
  const cx = mx - dy * 0.05
  const cy = my + dx * 0.05
  return `M ${a.x} ${a.y} Q ${cx} ${cy} ${b.x} ${b.y}`
}

export function DependencyGraph({ graph, selectedDomain, onSelectDomain }: GraphProps) {
  const [hover, setHover] = useState<string | null>(null)
  const W = 760
  const H = 500

  // focus subgraph: selected domain + its direct neighbours + one 'maintains' hop
  const focus = useMemo(() => {
    if (!selectedDomain) {
      const nodes = graph.nodes.slice(0, 48)
      const keep = new Set(nodes.map((n) => n.id))
      return {
        nodes,
        edges: graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
        title: 'Top domains — pick a finding below to focus its blast radius',
      }
    }
    const keep = new Set<string>([selectedDomain])
    for (const e of graph.edges) {
      if (e.source === selectedDomain) keep.add(e.target)
      if (e.target === selectedDomain) keep.add(e.source)
    }
    for (const e of graph.edges) {
      if (keep.has(e.source) && e.label === 'maintains') keep.add(e.target)
    }
    return {
      nodes: graph.nodes.filter((n) => keep.has(n.id)),
      edges: graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
      title: `${selectedDomain} — blast radius`,
    }
  }, [graph, selectedDomain])

  const { placed, links } = useMemo(
    () => place(focus.nodes, focus.edges, W, H),
    [focus],
  )
  const byId = useMemo(() => new Map(placed.map((p) => [p.id, p])), [placed])

  // focus-domain options = domain nodes sorted by risk (no extra prop needed)
  const domainOptions = useMemo(
    () =>
      graph.nodes
        .filter((n) => n.type === 'domain')
        .sort((a, b) => (b.risk || 0) - (a.risk || 0))
        .slice(0, 25),
    [graph.nodes],
  )

  const active = hover ?? selectedDomain

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <DetailHeader
        title="Dependency graph"
        subtitle="Real relationships from the scan — domain → maintainer → package"
      >
        <div className="flex items-center gap-2">
          <label htmlFor="focus-domain" className="sr-only">
            Focus domain
          </label>
          <select
            id="focus-domain"
            value={selectedDomain ?? ''}
            onChange={(e) => onSelectDomain(e.target.value || null)}
            className="h-8 max-w-[15rem] rounded-md border border-border bg-background px-2 text-sm text-foreground"
          >
            <option value="">— all domains —</option>
            {domainOptions.map((n) => (
              <option key={n.id} value={n.label}>
                {n.label} ({n.risk})
              </option>
            ))}
          </select>
        </div>
      </DetailHeader>

      <DashboardCard className="overflow-hidden p-0">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="xMidYMid meet"
          className="h-auto max-h-[58vh] w-full"
          role="img"
          aria-label={`Dependency graph: ${focus.title}`}
        >
          <defs>
            <radialGradient id="lz-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.10" />
              <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
            </radialGradient>
          </defs>
          <circle cx={W / 2} cy={H / 2} r={Math.min(W, H) * 0.45} fill="url(#lz-glow)" />

          {links.map((l, i) => (
            <path
              key={i}
              d={curve(l.a, l.b)}
              fill="none"
              stroke={l.label === 'maintains' ? 'hsl(var(--muted-foreground))' : 'hsl(var(--primary))'}
              strokeOpacity={l.label === 'maintains' ? 0.45 : 0.6}
              strokeWidth={1.2}
              strokeDasharray={l.label === 'maintains' ? '3 4' : undefined}
            />
          ))}

          {placed.map((p) => {
            const color =
              p.type === 'domain' ? SEVERITY_COLOR[severityOf(p.risk)] : NODE_COLOR[p.type]
            const isActive = active === p.id
            const fontSize = p.type === 'domain' ? 12 : 9
            return (
              <g
                key={p.id}
                transform={`translate(${p.x} ${p.y})`}
                className="cursor-pointer"
                onMouseEnter={() => setHover(p.id)}
                onMouseLeave={() => setHover(null)}
                onClick={() => p.type === 'domain' && onSelectDomain(p.label)}
              >
                {isActive && <circle r={p.r + 6} fill={color} fillOpacity="0.18" />}
                <circle
                  r={p.r}
                  fill={color}
                  fillOpacity={p.type === 'package' ? 0.8 : 1}
                  stroke={isActive ? 'hsl(var(--foreground))' : 'hsl(var(--background))'}
                  strokeWidth={isActive ? 2 : 1.5}
                />
                {p.type !== 'package' && (
                  <text
                    y={-p.r - 6}
                    textAnchor="middle"
                    className="fill-foreground"
                    style={{ fontSize, fontWeight: p.type === 'domain' ? 600 : 400 }}
                  >
                    {p.label.length > 26 ? p.label.slice(0, 25) + '…' : p.label}
                  </text>
                )}
              </g>
            )
          })}
        </svg>
      </DashboardCard>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="size-3 rounded-full" style={{ background: NODE_COLOR.domain }} />
          domain (sized/colored by risk)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-3 rounded-full" style={{ background: NODE_COLOR.maintainer }} />
          maintainer
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-3 rounded-full" style={{ background: NODE_COLOR.package }} />
          package
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0 w-4 border-t border-primary/60" />
          hosts email
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0 w-4 border-t border-dashed border-muted-foreground" />
          maintains
        </span>
      </div>

      {active && byId.get(active) ? (
        <DashboardCard>
          <DetailHeader
            title={byId.get(active)!.label}
            subtitle={`type: ${byId.get(active)!.type}`}
          />
          <div className="mt-2 text-xs text-muted-foreground">
            Connected to:{' '}
            {focus.edges
              .filter((e) => e.source === active || e.target === active)
              .map((e) => (e.source === active ? e.target : e.source))
              .map((id) => byId.get(id)?.label ?? id)
              .slice(0, 10)
              .join(', ') || 'nothing'}
          </div>
        </DashboardCard>
      ) : null}
    </div>
  )
}
