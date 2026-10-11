import type { CSSProperties, ReactNode } from 'react'
import { DashboardSidebar } from './components/capitalio/sidebar'
import { DashboardTopbar } from './components/capitalio/topbar'
import { SidebarProvider } from '@/components/ui/sidebar'
import type { ScanState } from './components/capitalio/lazarus-types'
import './dashboard.css'

type DashboardLayoutProps = {
  children: ReactNode
  scan: ScanState
  onRunScan: () => void
}

export default function DashboardLayout({ children, scan, onRunScan }: DashboardLayoutProps) {
  return (
    <SidebarProvider
      defaultOpen
      className="capitalio-dashboard h-svh overflow-hidden no-scrollbar"
      style={
        {
          '--sidebar-width': '15.625rem',
        } as CSSProperties
      }
    >
      <DashboardSidebar />

      <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden p-0.5 pl-0">
        <div className="flex min-h-0 min-w-0 flex-1 flex-col bg-background shadow-custom">
          <DashboardTopbar scan={scan} onRunScan={onRunScan} />
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
        </div>
      </main>
    </SidebarProvider>
  )
}
