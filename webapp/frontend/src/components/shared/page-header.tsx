import React from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  children?: React.ReactNode
}

export function PageHeader({ title, description, children }: PageHeaderProps) {
  return (
    <div className="mb-8 flex flex-col gap-3 rounded-[1.6rem] border border-border/60 bg-card/70 px-5 py-5 shadow-[0_18px_60px_rgba(15,23,42,0.08)] backdrop-blur sm:flex-row sm:items-end sm:justify-between sm:px-6">
      <div>
        <p className="metric-kicker">Platform Module</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em]">{title}</h1>
        {description && <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p>}
      </div>
      {children && <div className="mt-2 flex items-center gap-2 sm:mt-0">{children}</div>}
    </div>
  )
}
