import type { SVGProps } from 'react'
import { cn } from '@/lib/utils'

// Lazarus mark: a shield (defense) with a broken chain link (the lapsed
// domain) and a domain node — "we watch the link before it's taken over."
export function LazarusLogo({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('size-7', className)}
      {...props}
    >
      <path
        d="M16 2 4 6v9c0 7.2 5 11.6 12 15 7-3.4 12-7.8 12-15V6L16 2Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M11 13.5 13.5 11M20.5 21 18 18.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <rect x="9" y="11" width="5" height="4" rx="1.4" stroke="currentColor" strokeWidth="1.6" />
      <rect x="18" y="17" width="5" height="4" rx="1.4" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="16" cy="16" r="2.2" fill="currentColor" />
    </svg>
  )
}

// back-compat alias so any lingering import still resolves
export const CapitalioLogo = LazarusLogo
