'use client'

import React from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { NAV_ITEMS } from '@/lib/constants'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip'
import { useAppShell } from '@/components/layout/app-shell-context'

export function Sidebar() {
  const pathname = usePathname()
  const { collapsed, toggleCollapsed, theme } = useAppShell()
  const iconLogo = theme === 'dark' ? '/images/logo-light.png' : '/images/logo-dark.png'
  const textLogo = theme === 'dark' ? '/images/full-text-light.png' : '/images/full-text-dark.png'

  return (
    <TooltipProvider delayDuration={0}>
      <aside
        className={cn(
          'fixed left-0 top-0 z-40 flex h-screen flex-col border-r border-border/70 bg-card/88 shadow-[18px_0_60px_rgba(15,23,42,0.08)] backdrop-blur-xl transition-all duration-300',
          collapsed ? 'w-[68px]' : 'w-[260px]'
        )}
      >
        {/* Logo */}
        <div className={cn('flex h-20 items-center border-b border-border/60 px-4', collapsed ? 'justify-center' : 'gap-3')}>
          <Image
            src={iconLogo}
            alt="ExposureScopeX"
            width={36}
            height={36}
            className="h-10 w-10 rounded-xl object-contain"
            priority
          />
          {!collapsed && (
            <div className="flex min-w-0 flex-1 flex-col">
              <Image
                src={textLogo}
                alt="ExposureScopeX"
                width={156}
                height={28}
                className="h-7 w-auto object-contain"
                priority
              />
              <span className="text-[10px] font-medium tracking-[0.22em] text-muted-foreground uppercase">
                Exposure Ops v2.2
              </span>
            </div>
          )}
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 py-2">
          <nav className="space-y-1 px-2">
            {NAV_ITEMS.map((section) => (
              <div key={section.title} className="mb-4">
                {!collapsed && (
                  <div className="mb-1 px-3 py-1">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                      {section.title}
                    </span>
                  </div>
                )}
                {collapsed && <div className="mx-auto mb-1 h-px w-6 bg-border" />}
                {section.items.map((item) => {
                  const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
                  const Icon = item.icon

                  const linkContent = (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                        'group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all',
                        isActive
                          ? 'bg-primary text-primary-foreground shadow-[0_10px_28px_rgba(220,91,33,0.22)]'
                          : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                        collapsed && 'justify-center px-2'
                      )}
                    >
                      <Icon className={cn('h-4 w-4 shrink-0', isActive ? 'text-primary-foreground' : 'text-muted-foreground group-hover:text-foreground')} />
                      {!collapsed && <span>{item.label}</span>}
                      {!collapsed && item.badge && item.badge > 0 && (
                        <span className={cn(
                          'ml-auto flex h-5 min-w-5 items-center justify-center rounded-full px-1.5 text-[10px] font-semibold',
                          isActive ? 'bg-primary-foreground/18 text-primary-foreground' : 'bg-primary/10 text-primary'
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </Link>
                  )

                  if (collapsed) {
                    return (
                      <Tooltip key={item.href}>
                        <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                        <TooltipContent side="right" className="flex items-center gap-2">
                          {item.label}
                          {item.badge && item.badge > 0 && (
                            <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-primary/10 px-1 text-[10px] font-semibold text-primary">
                              {item.badge}
                            </span>
                          )}
                        </TooltipContent>
                      </Tooltip>
                    )
                  }

                  return <React.Fragment key={item.href}>{linkContent}</React.Fragment>
                })}
              </div>
            ))}
          </nav>
        </ScrollArea>

        {/* Collapse Button */}
        <div className="border-t border-border/60 p-3">
          <button
            onClick={toggleCollapsed}
            className="flex w-full items-center justify-center rounded-xl border border-border/60 p-2.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            {!collapsed && <span className="ml-2 text-xs">Collapse</span>}
          </button>
        </div>
      </aside>
    </TooltipProvider>
  )
}
