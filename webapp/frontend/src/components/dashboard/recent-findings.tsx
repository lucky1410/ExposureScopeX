'use client'

import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { formatRelativeTime, truncate } from '@/lib/utils'
import type { Finding } from '@/lib/types'

interface RecentFindingsProps {
  findings: Finding[]
}

export function RecentFindings({ findings }: RecentFindingsProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Recent Findings</CardTitle>
          <Link href="/findings" className="text-xs text-primary hover:underline">
            View all
          </Link>
        </div>
      </CardHeader>
      <CardContent className="space-y-1">
        {findings.slice(0, 8).map((finding) => (
          <div
            key={finding.id}
            className="flex items-center gap-3 rounded-md px-2 py-2 hover:bg-muted/50 transition-colors"
          >
            <SeverityBadge severity={finding.severity} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{truncate(finding.title, 45)}</p>
              <p className="text-xs text-muted-foreground">{finding.asset_value}</p>
            </div>
            <span className="text-[11px] text-muted-foreground whitespace-nowrap">
              {formatRelativeTime(finding.found_at)}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
