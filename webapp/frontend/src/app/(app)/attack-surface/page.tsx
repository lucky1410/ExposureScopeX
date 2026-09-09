'use client'

import { useCallback, useEffect, useState } from 'react'
import { Activity, GitBranch, Network, RefreshCw } from 'lucide-react'
import { PageHeader } from '@/components/shared/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { getAssessments, getAssetDrift, getAssetGraph } from '@/lib/api'
import type { Assessment, AssetGraph, ExposureEvent } from '@/lib/types'
import { formatRelativeTime } from '@/lib/utils'

const ALL = '__all__'

export default function AttackSurfacePage() {
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [assessmentId, setAssessmentId] = useState(ALL)
  const [graph, setGraph] = useState<AssetGraph>({ nodes: [], edges: [], attack_paths: [] })
  const [events, setEvents] = useState<ExposureEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const scope = assessmentId === ALL ? undefined : assessmentId
      const [graphResult, driftResult] = await Promise.all([
        getAssetGraph({ assessment_id: scope }),
        getAssetDrift({ assessment_id: scope, page_size: 100 }),
      ])
      setGraph(graphResult)
      setEvents(driftResult.items)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load exposure graph')
    } finally {
      setLoading(false)
    }
  }, [assessmentId])

  useEffect(() => {
    getAssessments({ page_size: 100 }).then((result) => setAssessments(result.items)).catch(() => undefined)
  }, [])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-6">
      <PageHeader title="Exposure Graph" description="Canonical assets, discovery relationships, historical drift, and reachable attack paths.">
        <div className="flex gap-2">
          <Select value={assessmentId} onValueChange={setAssessmentId}>
            <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All assessments</SelectItem>
              {assessments.map((assessment) => <SelectItem key={assessment.id} value={assessment.id}>{assessment.name}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => void load()}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>
        </div>
      </PageHeader>

      {error && <div className="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">{error}</div>}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card><CardContent className="flex items-center gap-3 p-5"><Network className="h-5 w-5 text-blue-500" /><div><p className="text-2xl font-semibold">{graph.nodes.length}</p><p className="text-xs text-muted-foreground">Canonical asset nodes</p></div></CardContent></Card>
        <Card><CardContent className="flex items-center gap-3 p-5"><GitBranch className="h-5 w-5 text-emerald-500" /><div><p className="text-2xl font-semibold">{graph.edges.length}</p><p className="text-xs text-muted-foreground">Observed relationships</p></div></CardContent></Card>
        <Card><CardContent className="flex items-center gap-3 p-5"><Activity className="h-5 w-5 text-orange-500" /><div><p className="text-2xl font-semibold">{graph.attack_paths.length}</p><p className="text-xs text-muted-foreground">High-risk attack paths</p></div></CardContent></Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-base">Prioritized Attack Paths</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {loading ? <p className="text-sm text-muted-foreground">Calculating paths...</p> : graph.attack_paths.length === 0 ? <p className="text-sm text-muted-foreground">No high-risk paths have been calculated for this scope yet.</p> : graph.attack_paths.slice(0, 50).map((path) => (
              <div key={path.id} className="rounded-xl border p-3">
                <div className="flex items-start justify-between gap-3"><p className="text-sm font-medium">{path.title}</p><Badge variant={path.severity === 'CRITICAL' ? 'destructive' : 'secondary'}>{path.severity}</Badge></div>
                <p className="mt-2 text-xs text-muted-foreground">Risk {path.risk_score.toFixed(1)} · {path.nodes.length} nodes · {path.edges.length} edges</p>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-base">Exposure Drift</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {loading ? <p className="text-sm text-muted-foreground">Loading history...</p> : events.length === 0 ? <p className="text-sm text-muted-foreground">Run or repeat an assessment to establish historical drift.</p> : events.map((event) => (
              <div key={event.id} className="flex items-start justify-between gap-3 rounded-xl border p-3">
                <div><p className="text-sm font-medium">{event.event_type.replaceAll('.', ' ')}</p><p className="mt-1 max-w-xl truncate font-mono text-xs text-muted-foreground">{String(event.payload.asset || event.asset_id || '')}</p></div>
                <span className="whitespace-nowrap text-xs text-muted-foreground">{formatRelativeTime(event.observed_at)}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
