'use client'

import { Server, Globe, ShieldAlert, AlertTriangle, Gauge, Activity } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { StatusIndicator } from '@/components/shared/status-indicator'
import type { DashboardStats } from '@/lib/types'

interface StatsCardsProps {
  stats: DashboardStats
}

export function StatsCards({ stats }: StatsCardsProps) {
  const cards = [
    {
      label: 'Total Assets',
      value: stats.total_assets,
      change: stats.assets_change_percent,
      icon: Server,
      color: 'text-primary',
      bgColor: 'bg-primary/10',
    },
    {
      label: 'Domains',
      value: stats.total_domains,
      icon: Globe,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
    },
    {
      label: 'Vulnerabilities',
      value: stats.total_vulnerabilities,
      change: stats.vulns_change_percent,
      icon: ShieldAlert,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
    },
    {
      label: 'Critical Findings',
      value: stats.critical_findings,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
    },
    {
      label: 'Risk Score',
      value: stats.risk_score.toFixed(1),
      icon: Gauge,
      color: stats.risk_score >= 7 ? 'text-red-400' : stats.risk_score >= 4 ? 'text-yellow-400' : 'text-green-400',
      bgColor: stats.risk_score >= 7 ? 'bg-red-500/10' : stats.risk_score >= 4 ? 'bg-yellow-500/10' : 'bg-green-500/10',
      isScore: true,
    },
    {
      label: 'Active Scans',
      value: stats.active_scans,
      icon: Activity,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
      isActive: stats.active_scans > 0,
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
      {cards.map((card) => {
        const Icon = card.icon
        return (
          <Card key={card.label} className="relative overflow-hidden">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg', card.bgColor)}>
                  <Icon className={cn('h-4 w-4', card.color)} />
                </div>
                {card.change !== undefined && (
                  <span className={cn('text-xs font-medium', card.change >= 0 ? 'text-green-400' : 'text-red-400')}>
                    {card.change >= 0 ? '+' : ''}{card.change}%
                  </span>
                )}
                {card.isActive && <StatusIndicator status="running" />}
              </div>
              <div className="mt-3">
                <p className="text-2xl font-bold">{card.value}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{card.label}</p>
              </div>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
