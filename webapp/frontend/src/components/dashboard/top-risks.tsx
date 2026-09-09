'use client'

import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SeverityBadge } from '@/components/shared/severity-badge'
import type { Finding } from '@/lib/types'

interface TopRisksProps {
  findings: Finding[]
}

export function TopRisks({ findings }: TopRisksProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Top Risks</CardTitle>
          <Link href="/findings" className="text-xs text-primary hover:underline">
            View all
          </Link>
        </div>
      </CardHeader>
      <CardContent className="space-y-1">
        {findings.slice(0, 5).map((finding, index) => (
          <div
            key={finding.id}
            className="flex items-center gap-3 rounded-md px-2 py-2.5 hover:bg-muted/50 transition-colors"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-xs font-medium text-muted-foreground">
              {index + 1}
            </span>
            <SeverityBadge severity={finding.severity} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{finding.title}</p>
              <p className="text-xs text-muted-foreground">{finding.asset_value}</p>
            </div>
            {finding.cvss_score && (
              <span className="text-xs font-mono font-medium text-muted-foreground">
                CVSS {finding.cvss_score}
              </span>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
