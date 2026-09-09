'use client'

import { useCallback, useEffect, useState } from 'react'
import { Activity, CheckCircle2, CircleAlert, RefreshCw, Save, Trash2 } from 'lucide-react'
import { PageHeader } from '@/components/shared/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/components/ui/use-toast'
import { cleanupStorageRetention, configureRuntimeIntegration, getExecutionPolicy, getRuntimeIntegrations, getRuntimeStatus, getStorageStatus, previewStorageRetention, testRuntimeIntegration, updateExecutionPolicy, updateStoragePolicy } from '@/lib/api'
import type { ExecutionPolicy, RetentionPreview, RuntimeAdapterState, RuntimeIntegration, RuntimeStatus, StorageStatus } from '@/lib/types'

function StateBadge({ state }: { state: RuntimeAdapterState }) {
  if (!state.configured) return <Badge variant="outline">Not configured</Badge>
  if (state.healthy === true) return <Badge variant="success"><CheckCircle2 className="mr-1 h-3 w-3" /> Ready</Badge>
  if (state.healthy === false) return <Badge variant="destructive"><CircleAlert className="mr-1 h-3 w-3" /> Unavailable</Badge>
  return <Badge variant="secondary">Configured</Badge>
}

export default function RuntimeSettingsPage() {
  const { toast } = useToast()
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null)
  const [policy, setPolicy] = useState<ExecutionPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [integrations, setIntegrations] = useState<RuntimeIntegration[]>([])
  const [storage, setStorage] = useState<StorageStatus | null>(null)
  const [retentionPreview, setRetentionPreview] = useState<RetentionPreview | null>(null)
  const [adapterForms, setAdapterForms] = useState({ mobile_dynamic: { name: 'Mobile Dynamic Lab', url: '', api_key: '' }, kubernetes_runtime: { name: 'Kubernetes Runtime', url: '', api_key: '' } })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [runtimeStatus, executionPolicy, configured, storageStatus] = await Promise.all([getRuntimeStatus(), getExecutionPolicy(), getRuntimeIntegrations(), getStorageStatus()])
      setRuntime(runtimeStatus)
      setPolicy(executionPolicy)
      setIntegrations(configured)
      setStorage(storageStatus)
    } catch (error) {
      toast({ title: 'Runtime status unavailable', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { void load() }, [load])

  const save = async () => {
    if (!policy) return
    setSaving(true)
    try {
      setPolicy(await updateExecutionPolicy(policy))
      toast({ title: 'Execution policy updated' })
    } catch (error) {
      toast({ title: 'Policy update failed', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    } finally {
      setSaving(false)
    }
  }

  const adapters: Array<[string, RuntimeAdapterState]> = runtime ? [
    ['Scan isolation', runtime.scan_executor],
    ['Artifact storage', runtime.artifact_storage],
    ['Mobile dynamic analyzer', runtime.mobile_dynamic],
    ['Kubernetes runtime analyzer', runtime.kubernetes_runtime],
    ['Cloud security posture', runtime.cspm],
    ['Metrics and monitoring', runtime.monitoring],
  ] : []

  const saveAdapter = async (provider: RuntimeIntegration['provider']) => {
    setSaving(true)
    try { await configureRuntimeIntegration(provider, adapterForms[provider]); await load(); toast({ title: 'Runtime adapter saved securely' }) }
    catch (error) { toast({ title: 'Adapter save failed', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' }) }
    finally { setSaving(false) }
  }

  const testAdapter = async (provider: RuntimeIntegration['provider']) => {
    const result = await testRuntimeIntegration(provider)
    toast({ title: result.healthy ? 'Adapter is ready' : 'Adapter unavailable', description: result.message })
    await load()
  }

  const previewRetention = async () => {
    try {
      setRetentionPreview(await previewStorageRetention())
    } catch (error) {
      toast({ title: 'Retention preview failed', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    }
  }

  const cleanupRetention = async () => {
    if (!retentionPreview) return
    setSaving(true)
    try {
      const result = await cleanupStorageRetention(retentionPreview.confirmation_token)
      toast({ title: 'Retention cleanup completed', description: `${result.scan_artifacts_released} scan artifacts released and ${result.reports_deleted} reports deleted${result.errors.length ? `; ${result.errors.length} objects need attention` : ''}.` })
      setRetentionPreview(null)
      await load()
    } catch (error) {
      toast({ title: 'Retention cleanup stopped safely', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
      setRetentionPreview(null)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Runtime & Capacity" description="Deployment readiness and tenant-safe scan scheduling" />
      <div className="flex justify-end"><Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className="mr-2 h-4 w-4" /> Refresh health</Button></div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {adapters.map(([name, state]) => (
          <Card key={name}><CardHeader className="pb-2"><CardDescription>{name}</CardDescription><CardTitle className="text-sm">{state.mode || state.backend || name}</CardTitle></CardHeader><CardContent><StateBadge state={state} />{state.message && <p className="mt-2 text-xs text-muted-foreground">{state.message}</p>}</CardContent></Card>
        ))}
      </div>
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" /> Organization scheduling</CardTitle><CardDescription>Limits are enforced at dispatch and again through distributed execution leases.</CardDescription></CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-4">
          <div className="space-y-2"><Label>Concurrent scans</Label><Input type="number" min={1} max={100} value={policy?.max_active_scans ?? 2} onChange={event => setPolicy(current => current ? { ...current, max_active_scans: Number(event.target.value) } : current)} /></div>
          <div className="space-y-2"><Label>Queued scans</Label><Input type="number" min={1} max={1000} value={policy?.max_queued_scans ?? 25} onChange={event => setPolicy(current => current ? { ...current, max_queued_scans: Number(event.target.value) } : current)} /></div>
          <div className="space-y-2"><Label>Queue priority</Label><Input type="number" min={0} max={9} value={policy?.priority ?? 5} onChange={event => setPolicy(current => current ? { ...current, priority: Number(event.target.value) } : current)} /></div>
          <div className="flex items-end"><Button onClick={() => void save()} disabled={!policy || saving}><Save className="mr-2 h-4 w-4" /> Save policy</Button></div>
        </CardContent>
      </Card>
      {storage && <Card><CardHeader><CardTitle>Artifact storage</CardTitle><CardDescription>{storage.cache_accounting}</CardDescription></CardHeader><CardContent className="space-y-4"><div className="grid gap-3 md:grid-cols-4"><div><p className="text-xs text-muted-foreground">Used</p><p className="text-lg font-semibold">{(storage.used_bytes / 1024 ** 3).toFixed(2)} GiB</p></div><div><p className="text-xs text-muted-foreground">Quota</p><p className="text-lg font-semibold">{(storage.quota_bytes / 1024 ** 3).toFixed(0)} GiB</p></div><div><p className="text-xs text-muted-foreground">Scan artifacts</p><p className="text-lg font-semibold">{storage.scan_artifacts.count}</p></div><div><p className="text-xs text-muted-foreground">Reports</p><p className="text-lg font-semibold">{storage.reports.count}</p></div></div><div className="grid gap-3 md:grid-cols-4"><div className="space-y-2"><Label>Quota GiB</Label><Input type="number" min={1} value={Math.round(storage.quota_bytes / 1024 ** 3)} onChange={(event) => setStorage({ ...storage, quota_bytes: Number(event.target.value) * 1024 ** 3 })} /></div><div className="space-y-2"><Label>Scan retention days</Label><Input type="number" min={1} value={storage.retention.scan_days} onChange={(event) => setStorage({ ...storage, retention: { ...storage.retention, scan_days: Number(event.target.value) } })} /></div><div className="space-y-2"><Label>Report retention days</Label><Input type="number" min={1} value={storage.retention.report_days} onChange={(event) => setStorage({ ...storage, retention: { ...storage.retention, report_days: Number(event.target.value) } })} /></div><div className="flex items-end gap-2"><Button onClick={() => void updateStoragePolicy({ quota_gb: Math.round(storage.quota_bytes / 1024 ** 3), scan_retention_days: storage.retention.scan_days, report_retention_days: storage.retention.report_days }).then(load)}><Save className="mr-2 h-4 w-4" /> Save storage</Button><Button variant="outline" onClick={() => void previewRetention()}>Preview cleanup</Button></div></div>{retentionPreview && <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4"><div className="flex flex-col justify-between gap-3 md:flex-row md:items-center"><div><p className="font-medium">Safe cleanup preview</p><p className="text-sm text-muted-foreground">{retentionPreview.scan_artifacts.count} scan artifacts and {retentionPreview.reports.count} reports, {(retentionPreview.reclaimable_bytes / 1024 ** 2).toFixed(2)} MiB reclaimable. The confirmation expires in {Math.round(retentionPreview.expires_in_seconds / 60)} minutes.</p></div><div className="flex gap-2"><Button variant="outline" onClick={() => setRetentionPreview(null)}>Cancel</Button><Button variant="destructive" disabled={saving || retentionPreview.reclaimable_bytes === 0} onClick={() => void cleanupRetention()}><Trash2 className="mr-2 h-4 w-4" />Clean exact preview</Button></div></div></div>}</CardContent></Card>}
      <div className="grid gap-4 lg:grid-cols-2">{(['mobile_dynamic', 'kubernetes_runtime'] as const).map((provider) => { const existing = integrations.find(item => item.provider === provider); return <Card key={provider}><CardHeader><CardTitle className="capitalize">{provider.replaceAll('_', ' ')}</CardTitle><CardDescription>Encrypted tenant configuration. Existing keys are never returned to the browser.</CardDescription></CardHeader><CardContent className="space-y-3"><div className="space-y-2"><Label>Display name</Label><Input value={adapterForms[provider].name} onChange={event => setAdapterForms(current => ({ ...current, [provider]: { ...current[provider], name: event.target.value } }))} /></div><div className="space-y-2"><Label>Adapter URL</Label><Input placeholder="https://adapter.internal" value={adapterForms[provider].url} onChange={event => setAdapterForms(current => ({ ...current, [provider]: { ...current[provider], url: event.target.value } }))} /></div><div className="space-y-2"><Label>API key {existing?.configured && '(replace)'}</Label><Input type="password" autoComplete="new-password" value={adapterForms[provider].api_key} onChange={event => setAdapterForms(current => ({ ...current, [provider]: { ...current[provider], api_key: event.target.value } }))} /></div><div className="flex gap-2"><Button disabled={saving || !adapterForms[provider].url || !adapterForms[provider].api_key} onClick={() => void saveAdapter(provider)}>Save securely</Button><Button variant="outline" disabled={!existing?.configured} onClick={() => void testAdapter(provider)}>Test connection</Button></div>{existing?.last_error && <p className="text-xs text-destructive">{existing.last_error}</p>}</CardContent></Card> })}</div>
      {runtime && <Card><CardHeader><CardTitle>Deployment variables</CardTitle><CardDescription>Configure secrets outside the browser, then restart the affected service.</CardDescription></CardHeader><CardContent className="grid gap-4 md:grid-cols-2">{Object.entries(runtime.required_variables).map(([name, variables]) => <div key={name} className="rounded-lg border p-3"><p className="text-sm font-medium">{name.replaceAll('_', ' ')}</p><p className="mt-2 font-mono text-xs text-muted-foreground">{variables.join(', ')}</p></div>)}</CardContent></Card>}
    </div>
  )
}
