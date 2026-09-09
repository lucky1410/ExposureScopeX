'use client'

import { Activity, CheckCircle, AlertTriangle, Plus, Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatRelativeTime } from '@/lib/utils'
import { cn } from '@/lib/utils'
import type { ActivityItem } from '@/lib/types'

interface ScanActivityProps {
  activities: ActivityItem[]
}

const activityIcons: Record<string, { icon: React.ElementType; color: string }> = {
  scan_started: { icon: Activity, color: 'text-primary' },
  scan_completed: { icon: CheckCircle, color: 'text-green-400' },
  finding_new: { icon: AlertTriangle, color: 'text-orange-400' },
  finding_confirmed: { icon: AlertTriangle, color: 'text-red-400' },
  asset_discovered: { icon: Plus, color: 'text-blue-400' },
}

export function ScanActivity({ activities }: ScanActivityProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Recent Activity</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {activities.slice(0, 8).map((activity) => {
          const iconConfig = activityIcons[activity.type] || { icon: Search, color: 'text-muted-foreground' }
          const Icon = iconConfig.icon
          return (
            <div
              key={activity.id}
              className="flex items-start gap-3 rounded-md px-2 py-2 hover:bg-muted/50 transition-colors"
            >
              <div className={cn('mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-muted', iconConfig.color)}>
                <Icon className="h-3 w-3" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{activity.title}</p>
                <p className="text-xs text-muted-foreground truncate">{activity.description}</p>
              </div>
              <span className="text-[11px] text-muted-foreground whitespace-nowrap mt-0.5">
                {formatRelativeTime(activity.timestamp)}
              </span>
            </div>
          )
        })}
      </CardContent>
    </Card>
  )
}
