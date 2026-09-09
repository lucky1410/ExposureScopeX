'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowRight, Network } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PageHeader } from '@/components/shared/page-header'
import { StatsCards } from '@/components/dashboard/stats-cards'
import { SeverityBreakdown } from '@/components/dashboard/severity-breakdown'
import { VulnTrendChart } from '@/components/dashboard/vuln-trend-chart'
import { RiskScoreGauge } from '@/components/dashboard/risk-score-gauge'
import { RecentFindings } from '@/components/dashboard/recent-findings'
import { ScanActivity } from '@/components/dashboard/scan-activity'
import { TopRisks } from '@/components/dashboard/top-risks'
import {
  getChangeFeed,
  getDashboardRecentFindings,
  getDashboardStats,
  getDashboardTrends,
  getExposureMethodology,
  getExposureProfile,
  getNotableSignals,
} from '@/lib/api'
import type { ChangeFeedEvent, ExposureMethodology, ExposureProfile, NotableSignal } from '@/lib/types'

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null)
  const [profile, setProfile] = useState<ExposureProfile | null>(null)
  const [methodology, setMethodology] = useState<ExposureMethodology | null>(null)
  const [changeFeed, setChangeFeed] = useState<ChangeFeedEvent[]>([])
  const [signals, setSignals] = useState<NotableSignal[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const [statsData, trendsData, recentData, profileData, methodologyData, changeFeedData, signalsData] = await Promise.all([
          getDashboardStats() as Promise<any>,
          getDashboardTrends().catch(() => null),
          getDashboardRecentFindings().catch(() => []),
          getExposureProfile().catch(() => null),
          getExposureMethodology().catch(() => null),
          getChangeFeed(12).catch(() => []),
          getNotableSignals(6).catch(() => []),
        ])

        const mappedRecent = (recentData || []).map((f: any) => ({
          ...f,
          found_at: f.first_seen || f.found_at || f.created_at,
          cve_id: f.cve_id || null,
          category: f.category || f.source || 'vulnerability',
          cvss_score: f.cvss_score || null,
        }))

        const combined = {
          total_assets: statsData.total_assets || 0,
          total_domains: 0,
          total_vulnerabilities: statsData.total_findings || 0,
          critical_findings: statsData.critical_findings || 0,
          high_findings: statsData.high_findings || 0,
          medium_findings: statsData.medium_findings || 0,
          low_findings: statsData.low_findings || 0,
          info_findings: statsData.info_findings || 0,
          risk_score: Number(statsData.risk_score) || 0,
          active_scans: statsData.active_assessments || 0,
          completed_scans: 0,
          assets_change_percent: statsData.assets_change_pct || 0,
          vulns_change_percent: statsData.findings_change_pct || 0,
          severity_breakdown: [
            { name: 'Critical', value: statsData.critical_findings || 0, color: '#ef4444' },
            { name: 'High', value: statsData.high_findings || 0, color: '#f97316' },
            { name: 'Medium', value: statsData.medium_findings || 0, color: '#eab308' },
            { name: 'Low', value: statsData.low_findings || 0, color: '#22c55e' },
            { name: 'Info', value: statsData.info_findings || 0, color: '#3b82f6' },
          ],
          vuln_trend: trendsData?.findings_trend?.map((t: any) => ({
            date: t.date,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: t.value,
          })) || [],
          recent_findings: mappedRecent,
          top_risks: mappedRecent
            .filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
            .slice(0, 5),
          recent_activity: [],
        }

        setStats(combined)
        setProfile(profileData)
        setMethodology(methodologyData)
        setChangeFeed(changeFeedData)
        setSignals(signalsData)
      } catch (err) {
        console.error('Dashboard load error:', err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (loading || !stats) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Security Dashboard"
          description="Attack surface monitoring and vulnerability overview"
        />
        <div className="flex items-center justify-center py-24">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Exposure Dashboard"
        description="Benchmarked posture, live surface intelligence, and high-signal security drift."
      />

      <div className="grid gap-4 lg:grid-cols-[1.25fr_0.75fr]">
        <Card className="overflow-hidden border-border/60 bg-card/85">
          <CardContent className="p-6">
            <p className="metric-kicker">Current Exposure Index</p>
            <div className="mt-4 flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <p className="text-6xl font-semibold tracking-[-0.06em]">{profile?.overall_score ?? Math.round(stats.risk_score)}</p>
                <p className="mt-2 text-sm font-medium text-primary">{profile?.posture_tier ?? 'Benchmarked posture'} · {profile?.confidence ?? 'Signal building'}</p>
                <p className="mt-2 max-w-xl text-sm leading-7 text-muted-foreground">
                  {profile?.notable_signal ?? 'A normalized operating score derived from findings severity, active scans, asset count, and observed changes across the external surface.'}
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-3 lg:w-[320px] lg:grid-cols-1">
                <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                  <p className="metric-kicker">Critical</p>
                  <p className="mt-2 text-2xl font-semibold">{stats.critical_findings}</p>
                </div>
                <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                  <p className="metric-kicker">Assets</p>
                  <p className="mt-2 text-2xl font-semibold">{stats.total_assets}</p>
                </div>
                <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                  <p className="metric-kicker">Active Scans</p>
                  <p className="mt-2 text-2xl font-semibold">{stats.active_scans}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/60 bg-card/85">
          <CardContent className="p-6">
            <p className="metric-kicker">External Footprint</p>
            <div className="mt-4 grid grid-cols-2 gap-3">
              {Object.entries(profile?.external_footprint || {}).map(([key, value]) => (
                <div key={key} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                  <p className="metric-kicker">{key.replace('_', ' ')}</p>
                  <p className="mt-2 text-2xl font-semibold">{value}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Notable Signals</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {signals.map((signal) => (
              <div key={signal.id} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold">{signal.title}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{signal.detail}</p>
                  </div>
                  <span className="rounded-full bg-primary/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-primary">
                    {signal.severity}
                  </span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Benchmark Methodology</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {methodology?.categories.map((category) => (
              <div key={category.key} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <div className="flex items-center justify-between gap-4">
                  <p className="text-sm font-semibold">{category.label}</p>
                  <span className="metric-kicker">{category.weight}%</span>
                </div>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{category.summary}</p>
                <p className="mt-2 text-[11px] uppercase tracking-[0.2em] text-primary/80">
                  {category.evidence_sources.join(' · ')}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <StatsCards stats={stats} />

      <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Category Benchmarks</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {profile?.categories.map((category) => (
              <div key={category.key} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold">{category.label}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{category.summary}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-3xl font-semibold tracking-[-0.04em]">{category.score}</p>
                    <p className="metric-kicker">{category.weight}% weight</p>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Change Feed</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {changeFeed.map((event) => (
              <div key={event.id} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold">{event.title}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">{event.detail}</p>
                    <p className="mt-2 text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                      {new Date(event.timestamp).toLocaleString()}
                    </p>
                  </div>
                  {event.href ? (
                    <Link href={event.href} className="inline-flex items-center gap-1 text-xs font-semibold text-primary">
                      Open <ArrowRight className="h-3 w-3" />
                    </Link>
                  ) : null}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <SeverityBreakdown data={stats.severity_breakdown} />
        <VulnTrendChart data={stats.vuln_trend} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Overall Risk Score</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-center pt-4">
            <RiskScoreGauge score={stats.risk_score} />
          </CardContent>
        </Card>
        <TopRisks findings={stats.top_risks} />
        <ScanActivity activities={stats.recent_activity} />
      </div>

      <RecentFindings findings={stats.recent_findings} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" />
            Attack Surface Overview
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-border/50 bg-muted/20">
            <div className="text-center">
              <Network className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm font-medium text-muted-foreground">Asset Relationship Graph</p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                Interactive network visualization of discovered assets and their relationships
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
