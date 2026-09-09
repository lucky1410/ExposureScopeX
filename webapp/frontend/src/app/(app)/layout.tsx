'use client'

import { Sidebar } from '@/components/layout/sidebar'
import { Topbar } from '@/components/layout/topbar'
import { AppShellProvider, useAppShell } from '@/components/layout/app-shell-context'

function AppLayoutContent({ children }: { children: React.ReactNode }) {
  const { collapsed } = useAppShell()

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div
        className={`flex flex-1 flex-col transition-[padding] duration-300 ${
          collapsed ? 'pl-[68px]' : 'pl-[260px]'
        }`}
      >
        <Topbar />
        <main className="flex-1 p-4 sm:p-5 lg:p-6">
          <div className="min-h-full rounded-[1.75rem] border border-border/50 bg-background/66 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur sm:p-5 lg:p-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AppShellProvider>
      <AppLayoutContent>{children}</AppLayoutContent>
    </AppShellProvider>
  )
}
