'use client'

import Image from 'next/image'
import { useAppShell, AppShellProvider } from '@/components/layout/app-shell-context'

function AuthLayoutContent({ children }: { children: React.ReactNode }) {
  const { theme } = useAppShell()
  const iconLogo = theme === 'dark' ? '/images/logo-light.png' : '/images/logo-dark.png'
  const textLogo = theme === 'dark' ? '/images/full-text-light.png' : '/images/full-text-dark.png'

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-6 cyber-grid">
      <div className="brand-panel w-full max-w-5xl overflow-hidden">
        <div className="grid lg:grid-cols-[1.05fr_0.95fr]">
          <div className="hidden border-r border-border/60 bg-gradient-to-br from-primary/14 via-transparent to-transparent p-10 lg:block">
            <p className="metric-kicker">ExposureScopeX Platform</p>
            <h1 className="mt-5 text-4xl font-semibold tracking-[-0.04em]">
              External exposure intelligence, rendered like an operating system.
            </h1>
            <p className="mt-5 max-w-md text-sm leading-7 text-muted-foreground">
              Recon, ASM, findings, benchmarking, and scan orchestration in one warmer,
              more evidence-led workspace.
            </p>
            <div className="mt-10 space-y-4">
              {[
                'Profile-normalized assessments',
                'ASM inventory and cloud sync',
                'Recon, archived URLs, headers, and live findings',
              ].map((item) => (
                <div key={item} className="rounded-2xl border border-border/60 bg-background/60 px-4 py-3 text-sm text-muted-foreground">
                  {item}
                </div>
              ))}
            </div>
          </div>
          <div className="px-5 py-8 sm:px-8 sm:py-10">
        <div className="mb-8 flex flex-col items-center">
          <Image
            src="/images/full-logo.png"
            alt="ExposureScopeX shield logo"
            width={132}
            height={132}
            className="mb-4 h-28 w-28 object-contain drop-shadow-[0_0_22px_rgba(34,211,238,0.22)] sm:h-32 sm:w-32"
            priority
          />
          <Image
            src={iconLogo}
            alt="ExposureScopeX mark"
            width={48}
            height={48}
            className="mb-3 h-12 w-12 object-contain"
            priority
          />
          <Image
            src={textLogo}
            alt="ExposureScopeX"
            width={300}
            height={50}
            className="h-12 w-auto object-contain"
            priority
          />
          <p className="text-sm text-muted-foreground mt-1">Attack Surface Management Platform</p>
        </div>
        {children}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <AppShellProvider>
      <AuthLayoutContent>{children}</AuthLayoutContent>
    </AppShellProvider>
  )
}
