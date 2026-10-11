// Lazarus navigation + shell data.
// Replaces the Capitalio finance dataset. The shell components (sidebar,
// topbar, navigation) import from here; only Lazarus-relevant content remains.
// Finance chart payload (net-worth, holdings, returns) is intentionally gone.

import type { ComponentType, SVGProps } from 'react'
import {
  SidebarAnalyticsIcon,
  SidebarFolderIcon,
  SidebarHomeMutedIcon,
  SidebarLinkIcon,
  SidebarSettingsIcon,
} from './components/capitalio/icons'

export type NavIcon = ComponentType<SVGProps<SVGSVGElement>>

export type NavigationItem = {
  name: string
  href: string
  icon: NavIcon
  pageTitle?: string
}

export type NavigationSection = {
  label?: string
  collapsible?: boolean
  defaultOpen?: boolean
  items: NavigationItem[]
}

export const sidebarSections = {
  main: [
    {
      label: 'Monitoring',
      collapsible: false,
      items: [
        {
          name: 'Overview',
          href: '/',
          icon: SidebarHomeMutedIcon,
          pageTitle: 'Security overview',
        },
        {
          name: 'Findings',
          href: '/findings',
          icon: SidebarFolderIcon,
          pageTitle: 'Findings',
        },
        {
          name: 'Dependencies',
          href: '/dependencies',
          icon: SidebarAnalyticsIcon,
          pageTitle: 'Dependency graph',
        },
      ],
    },
    {
      label: 'Reference',
      collapsible: true,
      defaultOpen: false,
      items: [
        { name: 'About Lazarus', href: '/about', icon: SidebarLinkIcon },
        { name: 'Settings', href: '/settings', icon: SidebarSettingsIcon },
      ],
    },
  ],
  footer: {
    items: [{ name: 'Settings', href: '/settings', icon: SidebarSettingsIcon }],
  },
} satisfies {
  main: NavigationSection[]
  footer: NavigationSection
}

const navigationItems: NavigationItem[] = [
  ...sidebarSections.main.flatMap((section) => section.items),
  ...sidebarSections.footer.items,
]

export function getPageTitle(pathname: string) {
  const item = navigationItems.find((navItem) => navItem.href === pathname)
  return item?.pageTitle ?? item?.name ?? 'Lazarus'
}

export const currentUser = {
  name: 'Security Analyst',
  initials: 'SA',
  avatar: '',
}

// The Capitalio topbar had a finance period selector. Lazarus has no time
// period concept, so this is a single fixed option kept only to satisfy the
// shell's types; the Lazarus topbar does not render a period picker.
export const dashboardPeriods = [{ value: 'all', label: 'All time' }] as const
export type PeriodValue = (typeof dashboardPeriods)[number]['value']
export const defaultDashboardPeriod: PeriodValue = 'all'
