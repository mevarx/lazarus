# Lazarus — web dashboard

React + TypeScript + Vite + Tailwind v4 + shadcn (Base UI) frontend for the
Lazarus expired-domain supply-chain watch. Built on the Capitalio dashboard
template, transformed into a security/threat-intelligence product.

## Architecture

- **Backend** (Python, `../app.py`) owns the scan engine, risk model, RDAP
  resolution, and Gemma narration. It is **not** modified by this frontend.
- **This app** is presentation only. It never recomputes risk or invents data.
- In dev, Vite proxies `/api/*` to the Python backend (`vite.config.ts`,
  default `http://127.0.0.1:8741`). Set `VITE_BACKEND` to override.

```
src/
  lib/
    types.ts     # TypeScript types mirroring the backend responses exactly
    api.ts       # fetch client + SSE scan stream (no secrets)
    present.ts   # severity/risk presentation helpers
  components/
    lazarus/     # SecurityOverview, Findings, DependencyGraph, EvidencePanel, FindingRow
    watermelon/capitalio-dashboard/   # reused shell: sidebar, layout, topbar, primitives
```

## Run

```bash
# 1. start the backend (from the repo root)
python app.py            # listens on :8741

# 2. start the frontend
cd web
npm install
npm run dev              # http://localhost:5173  (proxies /api to :8741)
```

> Vite binds to `::1` (IPv6) — open `http://localhost:5173`, not `127.0.0.1`.

## Build

```bash
npm run build      # tsc -b && vite build -> dist/
npm run preview    # serve the production build
```

## Notes

- Maintainer emails are masked server-side before they reach the browser.
- Seeded (replay) runs are labeled `REPLAY · seeded`; live runs `LIVE · fresh scan`.
- Risk scores are heuristic estimates, not proof of takeover — the UI says so.
- No `GEMINI_API_KEY` or other secret lives in frontend code; it stays in the
  backend process environment.
