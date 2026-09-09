import { cn } from '@/lib/utils'

interface StatusIndicatorProps {
  status: 'running' | 'idle' | 'error' | 'success' | 'pending'
  label?: string
  className?: string
}

export function StatusIndicator({ status, label, className }: StatusIndicatorProps) {
  const dotColors = {
    running: 'bg-green-500',
    idle: 'bg-slate-500',
    error: 'bg-red-500',
    success: 'bg-green-500',
    pending: 'bg-yellow-500',
  }

  const animate = status === 'running'

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="relative flex h-2.5 w-2.5">
        {animate && (
          <span className={cn('absolute inline-flex h-full w-full animate-ping rounded-full opacity-75', dotColors[status])} />
        )}
        <span className={cn('relative inline-flex h-2.5 w-2.5 rounded-full', dotColors[status])} />
      </span>
      {label && <span className="text-xs text-muted-foreground capitalize">{label || status}</span>}
    </div>
  )
}
