import { Collapsible } from '@base-ui/react/collapsible'
import { SidebarChevronIcon } from './icons'
import { LazarusLogo } from './logo'
import { DashboardLink, useDashboardNavigation } from './navigation'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar'
import { currentUser, sidebarSections, type NavigationItem, type NavigationSection } from '../../data'
import { cn } from '@/lib/utils'

function Brand() {
  return (
    <div className="flex min-w-0 flex-1 items-center gap-3">
      <div className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-primary/40 bg-primary/15 text-primary">
        <LazarusLogo className="size-6 shrink-0" />
      </div>
      <div className="flex min-w-0 flex-col">
        <span className="truncate text-lg font-semibold leading-tight tracking-tight text-foreground">
          Lazarus
        </span>
        <span className="truncate text-[11px] leading-tight text-muted-foreground">
          expired-domain supply-chain watch
        </span>
      </div>
    </div>
  )
}

function NavLinkButton({
  item,
}: {
  item: NavigationItem
}) {
  const { pathname } = useDashboardNavigation()
  const { isMobile, setOpenMobile } = useSidebar()
  const isActive =
    item.href === '/' ? pathname === '/' : pathname.startsWith(item.href)
  const Icon = item.icon

  function handleClick() {
    if (isMobile) setOpenMobile(false)
  }

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        tooltip={item.name}
        isActive={isActive}
        className={cn(
          'h-auto gap-2.5 rounded-lg px-3 py-2.5 text-sm leading-5 text-muted-foreground transition-colors',
          'hover:bg-secondary hover:text-foreground',
          'data-active:bg-primary/12 data-active:text-primary',
          '[&_svg]:size-[18px]!',
          isActive && 'active-sidebar-item',
        )}
      >
        <DashboardLink href={item.href} onClick={handleClick} aria-current={isActive ? 'page' : undefined}>
          <Icon />
          <span className="truncate font-medium">{item.name}</span>
        </DashboardLink>
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function SidebarSectionMenu({ items }: { items: NavigationItem[] }) {
  return (
    <SidebarGroupContent>
      <SidebarMenu className="gap-1">
        {items.map((item) => (
          <NavLinkButton key={item.name} item={item} />
        ))}
      </SidebarMenu>
    </SidebarGroupContent>
  )
}

function SidebarNavSection({ section }: { section: NavigationSection }) {
  if (section.collapsible) {
    return (
      <Collapsible.Root defaultOpen={section.defaultOpen ?? true}>
        <SidebarGroup className="gap-1 p-0">
          {section.label ? (
            <Collapsible.Trigger
              className="flex w-full cursor-pointer items-center justify-between px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70 transition-colors hover:text-muted-foreground [&>svg]:size-3! [&>svg]:transition-transform [&>svg]:duration-200 [&>svg]:ease-out data-panel-open:[&>svg]:rotate-180"
            >
              {section.label}
              <SidebarChevronIcon className="shrink-0" />
            </Collapsible.Trigger>
          ) : null}
          <Collapsible.Panel>
            <SidebarSectionMenu items={section.items} />
          </Collapsible.Panel>
        </SidebarGroup>
      </Collapsible.Root>
    )
  }

  return (
    <SidebarGroup className="gap-1 p-0">
      {section.label ? (
        <SidebarGroupLabel className="px-2 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
          {section.label}
        </SidebarGroupLabel>
      ) : null}
      <SidebarSectionMenu items={section.items} />
    </SidebarGroup>
  )
}

export function DashboardSidebar() {
  return (
    <Sidebar className="border-r border-border! p-0 lazarus-shell">
      <SidebarHeader className="flex-row items-center gap-2 border-b border-border px-4 py-4">
        <Brand />
      </SidebarHeader>

      <SidebarContent className="gap-4 px-3 py-4">
        {sidebarSections.main.map((section) => (
          <SidebarNavSection key={section.label} section={section} />
        ))}
      </SidebarContent>

      <SidebarFooter className="gap-3 border-t border-border px-4 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <Avatar className="size-9 rounded-lg after:rounded-lg">
            {currentUser.avatar ? (
              <AvatarImage src={currentUser.avatar} className="rounded-lg" />
            ) : null}
            <AvatarFallback className="rounded-lg bg-primary/15 text-primary">
              {currentUser.initials}
            </AvatarFallback>
          </Avatar>
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <span className="truncate text-sm font-medium leading-none text-foreground">
              {currentUser.name}
            </span>
            <span className="truncate text-[11px] leading-none text-muted-foreground">
              read-only analyst view
            </span>
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
