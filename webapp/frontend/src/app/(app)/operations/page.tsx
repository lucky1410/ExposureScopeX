'use client'

import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, Clock3, Layers3, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { getOperationsSummary } from '@/lib/api'
import type { OperationsSummary } from '@/lib/types'

export default function OperationsPage() {
  const [summary, setSummary] = useState<OperationsSummary | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      setSummary(await getOperationsSummary())
      setError('')
    } catch (reason) {
      const detail = (reason as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || 'Operational telemetry is temporarily unavailable.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), 15000)
    return () => window.clearInterval(timer)
  }, [])

  const active = (summary?.scans.running || 0) + (summary?.scans.queued || 0)
  const queued = Object.values(summary?.queue_depths || {}).reduce<number>((total, value) => total + (value || 0), 0)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operations"
        description="Live scan capacity, queue routing, stale execution detection, and worker health signals."
      >
        <Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Refresh</Button>
      </PageHeader>
      {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">{error}</div>}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Card><CardContent className="p-5"><Activity className="h-5 w-5 text-primary" /><p className="mt-3 text-2xl font-semibold">{active}</p><p className="text-xs text-muted-foreground">Active scans</p></CardContent></Card>
        <Card><CardContent className="p-5"><Layers3 className="h-5 w-5 text-sky-500" /><p className="mt-3 text-2xl font-semibold">{queued}</p><p className="text-xs text-muted-foreground">Queued tasks</p></CardContent></Card>
        <Card><CardContent className="p-5"><AlertTriangle className="h-5 w-5 text-amber-500" /><p className="mt-3 text-2xl font-semibold">{summary?.stale_active_scans || 0}</p><p className="text-xs text-muted-foreground">Stale active scans</p></CardContent></Card>
        <Card><CardContent className="p-5"><Clock3 className="h-5 w-5 text-emerald-500" /><p className="mt-3 text-sm font-semibold">{summary ? new Date(summary.generated_at).toLocaleTimeString() : 'Waiting'}</p><p className="text-xs text-muted-foreground">Last telemetry refresh</p></CardContent></Card>
        <Card><CardContent className="p-5"><Layers3 className="h-5 w-5 text-cyan-500" /><p className="mt-3 text-2xl font-semibold">{summary?.capacity.active_available ?? 0}</p><p className="text-xs text-muted-foreground">Tenant slots available</p></CardContent></Card>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card><CardHeader><CardTitle className="text-base">Queue Depths</CardTitle></CardHeader><CardContent className="space-y-3">{Object.entries(summary?.queue_depths || {}).map(([queue, depth]) => <div key={queue} className="flex items-center justify-between rounded-lg border p-3"><span className="font-mono text-xs">{queue}</span><Badge variant={depth ? 'default' : 'secondary'}>{depth == null ? 'unavailable' : depth}</Badge></div>)}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-base">Scan States</CardTitle></CardHeader><CardContent className="space-y-3">{Object.entries(summary?.scans || {}).map(([status, count]) => <div key={status} className="flex items-center justify-between rounded-lg border p-3"><span className="text-sm capitalize">{status.replaceAll('_', ' ')}</span><Badge variant="outline">{count}</Badge></div>)}{summary && Object.keys(summary.scans).length === 0 && <p className="text-sm text-muted-foreground">No scans have been recorded.</p>}</CardContent></Card>
      </div>
      <Card>
        <CardHeader><CardTitle className="text-base">Worker Capabilities</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {(summary?.workers || []).map((worker) => <div key={worker.name} className="rounded-xl border p-4"><div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between"><div><p className="font-mono text-sm font-medium">{worker.name}</p><p className="mt-1 text-xs text-muted-foreground">{worker.image_identity} · seen {new Date(worker.last_seen_at).toLocaleTimeString()}</p></div><Badge variant={worker.status === 'online' ? 'default' : 'destructive'}>{worker.status}</Badge></div><p className="mt-3 text-xs text-muted-foreground"><span className="font-medium text-foreground">Queues:</span> {worker.queues.join(' · ') || 'none'}</p><div className="mt-2 flex flex-wrap gap-1.5">{worker.capabilities.map((capability) => <Badge key={capability} variant="outline" className="font-mono text-[10px]">{capability}{worker.versions[capability] ? ` ${worker.versions[capability].slice(0, 24)}` : ''}</Badge>)}</div></div>)}
          {summary && summary.workers.length === 0 && <p className="text-sm text-muted-foreground">No worker has advertised capabilities yet. Restart the worker after applying the database migration.</p>}
        </CardContent>
      </Card>
      {summary && <Card><CardHeader><CardTitle className="text-base">Production Adapters</CardTitle></CardHeader><CardContent className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Scan executor</p><p className="mt-1 font-medium capitalize">{summary.deployment.scan_executor}</p></div><div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Artifact storage</p><p className="mt-1 font-medium uppercase">{summary.deployment.artifact_storage}</p></div><div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Mobile dynamic</p><Badge className="mt-2" variant={summary.deployment.mobile_dynamic ? 'default' : 'secondary'}>{summary.deployment.mobile_dynamic ? 'Configured' : 'Not configured'}</Badge></div><div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Kubernetes runtime</p><Badge className="mt-2" variant={summary.deployment.kubernetes_runtime ? 'default' : 'secondary'}>{summary.deployment.kubernetes_runtime ? 'Configured' : 'Not configured'}</Badge></div></CardContent></Card>}
    </div>
  )
}
