// Dependency graph panel — domain -> maintainer -> package.
// Uses the REAL graph from /api/graph (no fictional relationships).
// Hand-rolled SVG force layout: zero extra dependencies.

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
  maintainer: '#60a5fa',
  package: '#a78bfa',
}

const NODE_RADIUS: Record<NodeType, number> = { domain: 9, maintainer: 6, package: 5 }

interface Positioned {
  node: GraphNode
  x: number
  y: number
}

// deterministic force layout in a fixed box
function layout(nodes: GraphNode[], edges: Graph['edges'], w: number, h: number): Positioned[] {
  const pos = new Map<string, { x: number; y: number; vx: number; vy: number }>()
  nodes.forEach((n, i) => {
    const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2
    const r = Math.min(w, h) * 0.32
    pos.set(n.id, {
      x: w / 2 + Math.cos(angle) * r,
      y: h / 2 + Math.sin(angle) * r,
      vx: 0,
      vy: 0,
    })
  })
  for (let step = 0; step < 120; step++) {
    for (const a of pos.values())
      for (const b of pos.values()) {
        if (a === b) continue
        const dx = a.x - b.x
        const dy = a.y - b.y
        const d2 = dx * dx + dy * dy || 1
        const f = 900 / d2
        a.vx += (dx / Math.sqrt(d2)) * f
        a.vy += (dy / Math.sqrt(d2)) * f
      }
    for (const e of edges) {
      const a = pos.get(e.source)
      const b = pos.get(e.target)
      if (!a || !b) continue
      const dx = b.x - a.x
      const dy = b.y - a.y
      const d = Math.sqrt(dx * dx + dy * dy) || 1
      const f = (d - 70) * 0.02
      a.vx += (dx / d) * f
      a.vy += (dy / d) * f
      b.vx -= (dx / d) * f
      b.vy -= (dy / d) * f
    }
    for (const p of pos.values()) {
      p.vx += (w / 2 - p.x) * 0.005
      p.vy += (h / 2 - p.y) * 0.005
      p.vx *= 0.85
      p.vy *= 0.85
      p.x = Math.max(20, Math.min(w - 20, p.x + p.vx))
      p.y = Math.max(20, Math.min(h - 20, p.y + p.vy))
    }
  }
  return nodes.map((n) => ({ node: n, x: pos.get(n.id)!.x, y: pos.get(n.id)!.y }))
}

export function DependencyGraph({ graph, selectedDomain, onSelectDomain }: GraphProps) {
  const [hover, setHover] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const W = 760
  const H = 460

  const positioned = useMemo(() => layout(graph.nodes, graph.edges, W, H), [graph])
  const byId = useMemo(() => new Map(positioned.map((p) => [p.node.id, p])), [positioned])

  const related = useMemo(() => {
    if (!selectedDomain) return null
    const domId = selectedDomain
    const keep = new Set<string>([domId])
    for (const e of graph.edges) {
      if (e.source === domId) keep.add(e.target)
      if (e.target === domId) keep.add(e.source)
    }
    for (const e of graph.edges) {
      if (keep.has(e.source) && e.label === 'maintains') keep.add(e.target)
    }
    return keep
  }, [selectedDomain, graph.edges])

  const matchesQuery = (label: string) =>
    !query || label.toLowerCase().includes(query.toLowerCase())

  const active = hover ?? selectedDomain

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <DetailHeader
        title="Dependency graph"
        subtitle="Real relationships from the scan — domain → maintainer → package"
      >
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search nodes…"
          aria-label="Search graph nodes"
          className="h-8 rounded-md border border-border bg-background px-2.5 text-sm text-foreground"
        />
      </DetailHeader>

      <DashboardCard className="overflow-hidden p-0">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-[460px] w-full"
          role="img"
          aria-label="Dependency graph of domains, maintainers, and packages"
        >
          {graph.edges.map((e, i) => {
            const a = byId.get(e.source)
            const b = byId.get(e.target)
            if (!a || !b) return null
            const dim = related && !(related.has(e.source) && related.has(e.target))
            return (
              <line
                key={i}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={dim ? 'hsl(var(--border))' : 'hsl(var(--muted-foreground))'}
                strokeWidth={dim ? 1 : 1.5}
                strokeDasharray={e.label === 'maintains' ? undefined : '4 3'}
              />
            )
          })}
          {positioned.map(({ node, x, y }) => {
            const r = NODE_RADIUS[node.type]
            const isActive = active === node.id
            const dim = related && !related.has(node.id)
            const matches = matchesQuery(node.label)
            const color =
              node.type === 'domain' ? SEVERITY_COLOR[severityOf(node.risk)] : NODE_COLOR[node.type]
            return (
              <g
                key={node.id}
                transform={`translate(${x} ${y})`}
                opacity={dim ? 0.25 : matches ? 1 : 0.15}
                className="cursor-pointer"
                onMouseEnter={() => setHover(node.id)}
                onMouseLeave={() => setHover(null)}
                onClick={() => node.type === 'domain' && onSelectDomain(node.label)}
              >
                <circle
                  r={r}
                  fill={color}
                  stroke={isActive ? '#fff' : 'transparent'}
                  strokeWidth={2}
                />
                <text
                  y={-r - 4}
                  textAnchor="middle"
                  className="fill-foreground"
                  style={{ fontSize: 9, fontFamily: 'ui-monospace, monospace' }}
                >
                  {node.label.length > 22 ? node.label.slice(0, 21) + '…' : node.label}
                </text>
              </g>
            )
          })}
        </svg>
      </DashboardCard>

      <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="size-3 rounded-full" style={{ background: NODE_COLOR.domain }} />
          domain (colored by risk)
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
          <span className="inline-block h-0 w-4 border-t border-dashed border-muted-foreground" />
          hosts email
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-0 w-4 border-t border-muted-foreground" />
          maintains
        </span>
      </div>

      {active ? (
        <DashboardCard>
          <DetailHeader
            title={byId.get(active)?.node.label ?? active}
            subtitle={`type: ${byId.get(active)?.node.type}`}
          />
          <div className="mt-2 text-xs text-muted-foreground">
            Connected to:{' '}
            {graph.edges
              .filter((e) => e.source === active || e.target === active)
              .map((e) => (e.source === active ? e.target : e.source))
              .map((id) => byId.get(id)?.node.label ?? id)
              .join(', ') || 'nothing'}
          </div>
        </DashboardCard>
      ) : null}
    </div>
  )
}
