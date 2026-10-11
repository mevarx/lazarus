// API client for the Lazarus Python backend.
// All calls go through the Vite dev proxy (/api -> http://127.0.0.1:8741).
// No secrets here — the GEMINI_API_KEY lives only in the backend process.

import type {
  FindingsPayload,
  Graph,
  NarrateResponse,
  RunEvent,
  SkillsPayload,
} from './types'

const BASE = '/api'

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    signal,
    headers: { Accept: 'application/json' },
  })
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = body?.error ? `: ${body.error}` : ''
    } catch {
      /* non-JSON error body */
    }
    throw new Error(`${res.status} ${res.statusText}${detail}`)
  }
  return (await res.json()) as T
}

/** Last run (in-memory + persisted), falling back to the seeded run. */
export function fetchFindings(signal?: AbortSignal): Promise<FindingsPayload> {
  return getJson<FindingsPayload>('/findings', signal)
}

/** The seeded replay run — always available, no key/network needed. */
export function fetchCached(signal?: AbortSignal): Promise<FindingsPayload> {
  return getJson<FindingsPayload>('/cached', signal)
}

/** Domain -> maintainer -> package graph for the current findings. */
export function fetchGraph(signal?: AbortSignal): Promise<Graph> {
  return getJson<Graph>('/graph', signal)
}

/** Bundled agent skills. */
export function fetchSkills(signal?: AbortSignal): Promise<SkillsPayload> {
  return getJson<SkillsPayload>('/skills', signal)
}

/** Ask the live judge (Gemma/Ollama) to explain a specific domain. */
export async function narrate(
  domain: string,
  signal?: AbortSignal,
): Promise<NarrateResponse> {
  const res = await fetch(`${BASE}/narrate`, {
    method: 'POST',
    signal,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ domain }),
  })
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = body?.error ? `: ${body.error}` : ''
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status} ${res.statusText}${detail}`)
  }
  return (await res.json()) as NarrateResponse
}

/**
 * Stream a live scan over SSE. Calls onEvent for each parsed event and
 * resolves when the stream ends (done/failed/close). Never rejects on a
 * mid-stream failure — that arrives as a 'failed' event instead.
 */
export function runScan(
  onEvent: (event: RunEvent) => void,
  opts: { limit?: number; signal?: AbortSignal } = {},
): Promise<void> {
  const params = new URLSearchParams()
  if (opts.limit) params.set('limit', String(opts.limit))
  const url = `${BASE}/run${params.toString() ? `?${params}` : ''}`

  return new Promise((resolve) => {
    const es = new EventSource(url)
    let settled = false

    const finish = () => {
      if (settled) return
      settled = true
      es.close()
      resolve()
    }

    const onAbort = () => finish()
    opts.signal?.addEventListener('abort', onAbort)

    const handlers: Array<[string, (e: MessageEvent) => void]> = [
      ['start', (e) => onEvent({ type: 'start', data: JSON.parse(e.data) })],
      ['progress', (e) => onEvent({ type: 'progress', data: JSON.parse(e.data) })],
      ['finding', (e) => onEvent({ type: 'finding', data: JSON.parse(e.data) })],
      ['done', (e) => {
        onEvent({ type: 'done', data: JSON.parse(e.data) })
        finish()
      }],
      ['failed', (e) => {
        onEvent({ type: 'failed', data: JSON.parse(e.data) })
        finish()
      }],
    ]
    for (const [name, fn] of handlers) es.addEventListener(name, fn as EventListener)

    es.onerror = () => finish() // network drop / server closed — end quietly
  })
}
