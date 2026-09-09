'use client'

import { useEffect, useRef, useState, useCallback } from 'react'
import {
  Plus, Upload, Trash2, Play, RefreshCw, Cloud, Server, Globe, Database,
  CheckCircle2, XCircle, Clock, AlertTriangle, Filter, ChevronDown, X,
  Loader2, Building2, Cpu, Square
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { PageHeader } from '@/components/shared/page-header'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { formatRelativeTime } from '@/lib/utils'
import { api, cancelAsmTargetScan, importAsmTargets } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AsmTarget {
  id: string
  name: string
  target_type: string
  target_value: string
  source_type: string
  cloud_region: string | null
  cloud_account_id: string | null
  tags: string[]
  scan_status: 'idle' | 'scanning' | 'completed' | 'failed' | 'cancelled'
  last_scanned: string | null
  last_scan_summary: Record<string, any> | null
  notes: string | null
  created_at: string
}

interface AsmFinding {
  id: string
  target_id: string
  severity: string
  title: string
  description: string | null
  source: string | null
  url: string | null
  evidence: string | null
  status: string
  first_seen: string
  last_seen: string
}

interface CloudSource {
  id: string
  name: string
  provider: string
  is_active: boolean
  last_sync: string | null
  status: string
  status_message: string | null
}

function summarizeImportResult(added: number, skipped: number, errors: string[]) {
  const totalProcessed = added + skipped + errors.length
  const noImportableRows = totalProcessed === 0
  const allFailed = added === 0 && skipped === 0 && errors.length > 0
  const firstErrors = errors.slice(0, 3).join(' | ')

  if (noImportableRows) {
    return {
      title: 'Nothing imported',
      description: 'No importable rows were found in the CSV. Make sure it includes at least one data row with a target, domain, URL, hostname, IP, or similar field.',
      variant: 'destructive' as const,
    }
  }

  if (allFailed) {
    return {
      title: 'Import failed',
      description: `All rows failed validation. ${firstErrors}${errors.length > 3 ? ` | +${errors.length - 3} more` : ''}`,
      variant: 'destructive' as const,
    }
  }

  return {
    title: 'Import complete',
    description: `Added ${added}, skipped ${skipped}${errors.length ? `, errors ${errors.length}` : ''}.${errors.length ? ` First issues: ${firstErrors}${errors.length > 3 ? ` | +${errors.length - 3} more` : ''}` : ''}`,
    variant: errors.length ? 'destructive' as const : 'default' as const,
  }
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function asmGet<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = `/api/v1/asm${path}${params ? '?' + new URLSearchParams(params).toString() : ''}`
  const r = await api.get<T>(url)
  return r.data
}
async function asmPost<T>(path: string, body?: unknown): Promise<T> {
  const r = await api.post<T>(`/api/v1/asm${path}`, body)
  return r.data
}
async function asmDelete(path: string): Promise<void> {
  await api.delete(`/api/v1/asm${path}`)
}
async function asmPatch<T>(path: string, body: unknown): Promise<T> {
  const r = await api.patch<T>(`/api/v1/asm${path}`, body)
  return r.data
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CLOUD_PROVIDERS = [
  {
    id: 'aws', label: 'Amazon AWS', icon: Cloud,
    fields: [
      { key: 'access_key_id', label: 'Access Key ID', placeholder: 'AKIAIOSFODNN7EXAMPLE' },
      { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '••••••••', type: 'password' },
      { key: 'region', label: 'Region', placeholder: 'us-east-1' },
      { key: 'account_id', label: 'Account ID (optional)', placeholder: '123456789012' },
    ],
  },
  {
    id: 'gcp', label: 'Google Cloud', icon: Globe,
    fields: [
      { key: 'project_id', label: 'Project ID', placeholder: 'my-project-123' },
      { key: 'service_account_key', label: 'Service Account JSON Key', placeholder: '{"type":"service_account",...}', type: 'password' },
    ],
  },
  {
    id: 'azure', label: 'Microsoft Azure', icon: Building2,
    fields: [
      { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_id', label: 'Client ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { key: 'client_secret', label: 'Client Secret', placeholder: '••••••••', type: 'password' },
      { key: 'subscription_id', label: 'Subscription ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    ],
  },
  {
    id: 'onprem', label: 'On-Premises / Other', icon: Server,
    fields: [
      { key: 'cmdb_url', label: 'CMDB / IPAM URL (optional)', placeholder: 'https://cmdb.internal/api/assets' },
      { key: 'api_key', label: 'API Key (optional)', placeholder: '••••••••', type: 'password' },
    ],
  },
]

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

const STATUS_BADGE: Record<string, { label: string; color: string }> = {
  idle:      { label: 'Idle', color: 'text-muted-foreground' },
  scanning:  { label: 'Scanning…', color: 'text-blue-400' },
  completed: { label: 'Done', color: 'text-green-400' },
  failed:    { label: 'Failed', color: 'text-red-400' },
  cancelled: { label: 'Cancelled', color: 'text-amber-400' },
}

// ── Components ────────────────────────────────────────────────────────────────

function ScanStatusIcon({ status }: { status: string }) {
  if (status === 'scanning')  return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
  if (status === 'completed') return <CheckCircle2 className="h-4 w-4 text-green-400" />
  if (status === 'failed')    return <XCircle className="h-4 w-4 text-red-400" />
  if (status === 'cancelled') return <Square className="h-4 w-4 text-amber-400" />
  return <Clock className="h-4 w-4 text-muted-foreground" />
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AsmPage() {
  const { toast } = useToast()
  const [tab, setTab] = useState<'sources' | 'assets' | 'findings'>('assets')
  const [targets, setTargets] = useState<AsmTarget[]>([])
  const [findings, setFindings] = useState<AsmFinding[]>([])
  const [cloudSources, setCloudSources] = useState<CloudSource[]>([])
  const [loading, setLoading] = useState(true)
  const [findingsLoading, setFindingsLoading] = useState(false)

  // filters
  const [sevFilter, setSevFilter] = useState('')
  const [srcFilter, setSrcFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [targetFilter, setTargetFilter] = useState('')

  // manual add form
  const [showAddForm, setShowAddForm] = useState(false)
  const [newTarget, setNewTarget] = useState({ name: '', target_value: '', target_type: 'auto', tags: '', notes: '' })
  const [addLoading, setAddLoading] = useState(false)

  // CSV upload
  const fileRef = useRef<HTMLInputElement>(null)
  const [csvLoading, setCsvLoading] = useState(false)

  // cloud source form
  const [showCloudForm, setShowCloudForm] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState<typeof CLOUD_PROVIDERS[0] | null>(null)
  const [cloudFields, setCloudFields] = useState<Record<string, string>>({})
  const [cloudName, setCloudName] = useState('')
  const [cloudLoading, setCloudLoading] = useState(false)

  const fetchAll = useCallback(async () => {
    setLoading(true)
    try {
      const [t, c] = await Promise.all([
        asmGet<AsmTarget[]>('/targets'),
        asmGet<CloudSource[]>('/cloud-sources'),
      ])
      setTargets(t)
      setCloudSources(c)
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchFindings = useCallback(async () => {
    setFindingsLoading(true)
    try {
      const params: Record<string, string> = { page_size: '200' }
      if (sevFilter)    params.severity = sevFilter
      if (srcFilter)    params.source = srcFilter
      if (statusFilter) params.finding_status = statusFilter
      if (targetFilter) params.target_id = targetFilter
      const res = await asmGet<{ items: AsmFinding[] }>('/findings', params)
      setFindings(res.items.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)))
    } finally {
      setFindingsLoading(false)
    }
  }, [sevFilter, srcFilter, statusFilter, targetFilter])

  useEffect(() => { fetchAll() }, [fetchAll])
  useEffect(() => { if (tab === 'findings') fetchFindings() }, [tab, fetchFindings])

  // Poll scanning targets every 4s
  useEffect(() => {
    const scanning = targets.some(t => t.scan_status === 'scanning')
    if (!scanning) return
    const id = setInterval(fetchAll, 4000)
    return () => clearInterval(id)
  }, [targets, fetchAll])

  async function handleAddTarget(e: React.FormEvent) {
    e.preventDefault()
    setAddLoading(true)
    try {
      const t = await asmPost<AsmTarget>('/targets', {
        name: newTarget.name,
        target_value: newTarget.target_value,
        target_type: newTarget.target_type === 'auto' ? undefined : newTarget.target_type,
        tags: newTarget.tags ? newTarget.tags.split(',').map(s => s.trim()).filter(Boolean) : [],
        notes: newTarget.notes || undefined,
      })
      setTargets(prev => [t, ...prev])
      setNewTarget({ name: '', target_value: '', target_type: 'auto', tags: '', notes: '' })
      setShowAddForm(false)
    } finally {
      setAddLoading(false)
    }
  }

  async function handleCsvUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setCsvLoading(true)
    try {
      const result = await importAsmTargets(file)
      await fetchAll()
      toast(summarizeImportResult(result.added, result.skipped, result.errors))
    } finally {
      setCsvLoading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  async function handleScan(id: string) {
    try {
      await asmPost(`/targets/${id}/scan`)
      setTargets(prev => prev.map(t => t.id === id ? { ...t, scan_status: 'scanning' } : t))
      toast({ title: 'Scan started', description: 'Target scan was queued successfully.' })
    } catch (err: any) {
      toast({
        title: 'Could not start scan',
        description: err?.response?.data?.detail ?? 'Scan failed',
        variant: 'destructive',
      })
    }
  }

  async function handleCancelScan(id: string) {
    try {
      await cancelAsmTargetScan(id)
      setTargets(prev => prev.map(t => t.id === id ? { ...t, scan_status: 'cancelled' } : t))
      toast({ title: 'Cancel requested', description: 'ASM scan is being stopped.' })
    } catch (err: any) {
      toast({
        title: 'Could not cancel scan',
        description: err?.response?.data?.detail ?? 'Cancel failed',
        variant: 'destructive',
      })
    }
  }

  async function handleScanAll() {
    try {
      await asmPost('/scan-all')
      setTargets(prev => prev.map(t => ({ ...t, scan_status: t.scan_status !== 'scanning' ? 'scanning' : t.scan_status })))
      toast({ title: 'Scans started', description: 'All eligible targets were queued for scanning.' })
    } catch (err: any) {
      toast({
        title: 'Could not start scans',
        description: err?.response?.data?.detail ?? 'Bulk scan failed',
        variant: 'destructive',
      })
    }
  }

  async function handleDeleteTarget(id: string) {
    if (!confirm('Delete this target?')) return
    try {
      await asmDelete(`/targets/${id}`)
      setTargets(prev => prev.filter(t => t.id !== id))
      toast({ title: 'Target deleted', description: 'ASM target was removed successfully.' })
    } catch (err: any) {
      toast({
        title: 'Could not delete target',
        description: err?.response?.data?.detail ?? 'Delete failed',
        variant: 'destructive',
      })
    }
  }

  async function handleAddCloudSource(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedProvider) return
    setCloudLoading(true)
    try {
      const s = await asmPost<CloudSource>('/cloud-sources', {
        name: cloudName || selectedProvider.label,
        provider: selectedProvider.id,
        config: cloudFields,
      })
      setCloudSources(prev => [s, ...prev])
      setShowCloudForm(false)
      setSelectedProvider(null)
      setCloudFields({})
      setCloudName('')
    } finally {
      setCloudLoading(false)
    }
  }

  async function handleDeleteCloudSource(id: string) {
    if (!confirm('Remove this cloud source?')) return
    try {
      await asmDelete(`/cloud-sources/${id}`)
      setCloudSources(prev => prev.filter(s => s.id !== id))
      toast({ title: 'Cloud source removed', description: 'Cloud source was deleted successfully.' })
    } catch (err: any) {
      toast({
        title: 'Could not remove cloud source',
        description: err?.response?.data?.detail ?? 'Delete failed',
        variant: 'destructive',
      })
    }
  }

  async function handleFindingStatus(id: string, status: string) {
    await asmPatch(`/findings/${id}/status`, { status })
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status } : f))
  }

  const tabs = [
    { id: 'sources', label: 'Sources' },
    { id: 'assets',  label: `Assets (${targets.length})` },
    { id: 'findings', label: `Findings (${findings.length || '…'})` },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Surface Monitor"
        description="Continuously discover and scan your external attack surface — cloud, on-prem, manual, or CSV."
      >
        <div className="flex gap-2">
          {tab === 'assets' && (
            <>
              <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={csvLoading}>
                {csvLoading ? <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> : <Upload className="mr-2 h-3.5 w-3.5" />}
                Import CSV
              </Button>
              <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden" onChange={handleCsvUpload} />
              <Button variant="outline" size="sm" onClick={handleScanAll} disabled={targets.length === 0}>
                <Play className="mr-2 h-3.5 w-3.5" /> Scan All
              </Button>
              <Button size="sm" onClick={() => setShowAddForm(v => !v)}>
                <Plus className="mr-2 h-3.5 w-3.5" /> Add Target
              </Button>
            </>
          )}
          {tab === 'sources' && (
            <Button size="sm" onClick={() => { setShowCloudForm(true); setSelectedProvider(null) }}>
              <Plus className="mr-2 h-3.5 w-3.5" /> Connect Source
            </Button>
          )}
          {tab === 'findings' && (
            <Button variant="outline" size="sm" onClick={fetchFindings}>
              <RefreshCw className="h-3.5 w-3.5 mr-2" /> Refresh
            </Button>
          )}
        </div>
      </PageHeader>

      {/* Tabs */}
      <div className="flex border-b border-border gap-1">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as any)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── SOURCES TAB ── */}
      {tab === 'sources' && (
        <div className="space-y-6">
          {/* Cloud provider cards */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {CLOUD_PROVIDERS.map(p => {
              const Icon = p.icon
              const connected = cloudSources.filter(s => s.provider === p.id)
              return (
                <Card
                  key={p.id}
                  className="cursor-pointer hover:border-primary/40 transition-colors"
                  onClick={() => { setSelectedProvider(p); setShowCloudForm(true); setCloudFields({}); setCloudName('') }}
                >
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                        <Icon className="h-5 w-5 text-primary" />
                      </div>
                      {connected.length > 0 && (
                        <Badge variant="secondary" className="text-[10px]">{connected.length} connected</Badge>
                      )}
                    </div>
                    <CardTitle className="text-sm mt-2">{p.label}</CardTitle>
                    <CardDescription className="text-xs">
                      {connected.length === 0 ? 'Not connected' : `${connected.length} source${connected.length > 1 ? 's' : ''}`}
                    </CardDescription>
                  </CardHeader>
                </Card>
              )
            })}
          </div>

          {/* Connected sources list */}
          {cloudSources.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium text-muted-foreground">Connected Sources</h3>
              {cloudSources.map(s => (
                <div key={s.id} className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full ${s.status === 'ok' ? 'bg-green-400' : s.status === 'error' ? 'bg-red-400' : 'bg-yellow-400'}`} />
                    <div>
                      <p className="text-sm font-medium">{s.name}</p>
                      <p className="text-xs text-muted-foreground capitalize">
                        {s.provider} · {s.last_sync ? `Last sync ${formatRelativeTime(s.last_sync)}` : 'Never synced'}
                      </p>
                    </div>
                  </div>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400" onClick={() => handleDeleteCloudSource(s.id)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}

          {cloudSources.length === 0 && !showCloudForm && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Cloud className="h-10 w-10 text-muted-foreground/40 mb-3" />
              <p className="text-sm text-muted-foreground">No cloud sources connected yet.</p>
              <p className="text-xs text-muted-foreground mt-1">Click a provider card above or use CSV/manual import.</p>
            </div>
          )}

          {/* Cloud source form */}
          {showCloudForm && (
            <Card className="border-primary/30">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-sm">
                      {selectedProvider ? `Connect ${selectedProvider.label}` : 'Connect Cloud Source'}
                    </CardTitle>
                    <CardDescription className="text-xs">
                      {!selectedProvider && 'Select a provider above first, or fill in manually.'}
                    </CardDescription>
                  </div>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setShowCloudForm(false)}>
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleAddCloudSource} className="space-y-3">
                  <div className="space-y-1">
                    <Label className="text-xs">Display Name</Label>
                    <Input
                      value={cloudName}
                      onChange={e => setCloudName(e.target.value)}
                      placeholder={selectedProvider ? `e.g. Production ${selectedProvider.label}` : 'My Cloud Source'}
                      className="h-8 text-sm"
                    />
                  </div>
                  {!selectedProvider && (
                    <div className="space-y-1">
                      <Label className="text-xs">Provider</Label>
                      <div className="flex flex-wrap gap-2">
                        {CLOUD_PROVIDERS.map(p => (
                          <Button key={p.id} type="button" variant="outline" size="sm" className="h-7 text-xs"
                            onClick={() => setSelectedProvider(p)}>
                            {p.label}
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedProvider?.fields.map(f => (
                    <div key={f.key} className="space-y-1">
                      <Label className="text-xs">{f.label}</Label>
                      <Input
                        type={f.type || 'text'}
                        value={cloudFields[f.key] || ''}
                        onChange={e => setCloudFields(prev => ({ ...prev, [f.key]: e.target.value }))}
                        placeholder={f.placeholder}
                        className="h-8 text-sm font-mono"
                      />
                    </div>
                  ))}
                  <div className="flex gap-2 pt-1">
                    <Button type="submit" size="sm" disabled={cloudLoading || !selectedProvider}>
                      {cloudLoading ? <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> : null}
                      Save Connection
                    </Button>
                    <Button type="button" variant="outline" size="sm" onClick={() => setShowCloudForm(false)}>Cancel</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          )}

          {/* CSV format hint */}
          <Card className="bg-muted/30 border-dashed">
            <CardContent className="pt-4">
              <p className="text-xs font-medium text-muted-foreground mb-2">CSV Import Format</p>
              <pre className="text-xs text-muted-foreground font-mono whitespace-pre-wrap">
{`name,target_value,target_type,tags,notes
Web Server,203.0.113.1,ip,"production,web",Main web server
API Gateway,api.example.com,domain,"api,production",
Office Range,192.168.1.0/24,cidr,,On-prem office network
Primary MCP,https://gateway.example.com/mcp,mcp,"ai,mcp",Public MCP endpoint
Corp GitHub,github.com/acme/platform,repository,"source,supply-chain",
Edge ASN,AS13335,asn,"network,edge",Provider-owned network seed`}
              </pre>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── ASSETS TAB ── */}
      {tab === 'assets' && (
        <div className="space-y-4">
          {/* Add form */}
          {showAddForm && (
            <Card className="border-primary/30">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">Add Target</CardTitle>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setShowAddForm(false)}>
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleAddTarget} className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                  <div className="space-y-1">
                    <Label className="text-xs">Name</Label>
                    <Input value={newTarget.name} onChange={e => setNewTarget(p => ({ ...p, name: e.target.value }))} placeholder="Production Web" className="h-8 text-sm" required />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Target</Label>
                    <Input value={newTarget.target_value} onChange={e => setNewTarget(p => ({ ...p, target_value: e.target.value }))} placeholder="example.com, AS13335, github.com/org/repo, https://host/mcp" className="h-8 text-sm font-mono" required />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Type</Label>
                    <select
                      value={newTarget.target_type}
                      onChange={e => setNewTarget(p => ({ ...p, target_type: e.target.value }))}
                      className="w-full h-8 rounded-md border border-input bg-background px-3 text-sm"
                    >
                      <option value="auto">Auto-detect</option>
                      <option value="ip">IP Address</option>
                      <option value="cidr">CIDR Range</option>
                      <option value="domain">Domain</option>
                      <option value="hostname">Hostname</option>
                      <option value="mcp">MCP Endpoint</option>
                      <option value="repository">Repository</option>
                      <option value="asn">ASN</option>
                      <option value="cloud_account">Cloud Account</option>
                      <option value="organization">Organization</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Tags (comma separated)</Label>
                    <Input value={newTarget.tags} onChange={e => setNewTarget(p => ({ ...p, tags: e.target.value }))} placeholder="prod, aws, web" className="h-8 text-sm" />
                  </div>
                  <div className="col-span-2 lg:col-span-4 flex gap-2">
                    <Button type="submit" size="sm" disabled={addLoading}>
                      {addLoading ? <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" /> : <Plus className="mr-2 h-3.5 w-3.5" />}
                      Add
                    </Button>
                    <Button type="button" variant="outline" size="sm" onClick={() => setShowAddForm(false)}>Cancel</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : targets.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <Database className="h-10 w-10 text-muted-foreground/40 mb-3" />
              <p className="text-sm text-muted-foreground">No targets yet.</p>
              <p className="text-xs text-muted-foreground mt-1">Add a target manually, import a CSV, or connect a cloud source.</p>
            </div>
          ) : (
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Name / Target</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Type</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Source</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Tags</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Last Scan</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Status</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Findings</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {targets.map(t => {
                    const summary = t.last_scan_summary
                    return (
                      <tr key={t.id} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3">
                          <p className="font-medium text-sm">{t.name}</p>
                          <p className="text-xs text-muted-foreground font-mono">{t.target_value}</p>
                          {summary?.scan_strategy ? (
                            <p className="mt-1 text-[11px] text-muted-foreground">
                              {summary.scan_strategy} pipeline · {(summary.pipeline || []).slice(0, 4).join(' • ')}
                            </p>
                          ) : null}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant="outline" className="text-[10px] capitalize">{t.target_type}</Badge>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs text-muted-foreground capitalize">{t.source_type}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {(t.tags || []).slice(0, 3).map(tag => (
                              <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {t.last_scanned ? formatRelativeTime(t.last_scanned) : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <ScanStatusIcon status={t.scan_status} />
                            <span className={`text-xs ${STATUS_BADGE[t.scan_status]?.color}`}>
                              {STATUS_BADGE[t.scan_status]?.label}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {summary && summary.findings != null ? (
                            <div className="flex items-center gap-2 text-xs">
                              {summary.critical > 0 && <span className="text-red-400 font-medium">{summary.critical}C</span>}
                              {summary.high > 0 && <span className="text-orange-400 font-medium">{summary.high}H</span>}
                              {summary.medium > 0 && <span className="text-yellow-400 font-medium">{summary.medium}M</span>}
                              {summary.api_docs > 0 && <span className="text-cyan-400 font-medium">{summary.api_docs} API</span>}
                              {summary.open_ports > 0 && <span className="text-sky-400 font-medium">{summary.open_ports} Ports</span>}
                              {summary.findings === 0 && <span className="text-muted-foreground">0</span>}
                            </div>
                          ) : <span className="text-muted-foreground text-xs">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            {t.scan_status === 'scanning' ? (
                              <Button
                                variant="ghost" size="sm" className="h-7 w-7 p-0"
                                title="Cancel scan"
                                onClick={() => handleCancelScan(t.id)}
                              >
                                <Square className="h-3.5 w-3.5" />
                              </Button>
                            ) : (
                              <Button
                                variant="ghost" size="sm" className="h-7 w-7 p-0"
                                title="Scan"
                                onClick={() => handleScan(t.id)}
                              >
                                <Play className="h-3.5 w-3.5" />
                              </Button>
                            )}
                            <Button
                              variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                              title="Delete"
                              onClick={() => handleDeleteTarget(t.id)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── FINDINGS TAB ── */}
      {tab === 'findings' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-2 items-center">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
              className="h-8 rounded-md border border-input bg-background px-3 text-xs"
            >
              <option value="">All Severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              value={srcFilter}
              onChange={e => setSrcFilter(e.target.value)}
              className="h-8 rounded-md border border-input bg-background px-3 text-xs"
            >
              <option value="">All Sources</option>
              {['seed', 'dns', 'rdap', 'ssl', 'headers', 'subdomains', 'ports', 'http', 'api', 'wayback'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="h-8 rounded-md border border-input bg-background px-3 text-xs"
            >
              <option value="">All Statuses</option>
              {['new', 'confirmed', 'false_positive', 'remediated', 'approved_exception', 'accepted_risk', 'compensating_control', 'not_exploitable'].map(s => (
                <option key={s} value={s} className="capitalize">{s.replace('_', ' ')}</option>
              ))}
            </select>
            <select
              value={targetFilter}
              onChange={e => setTargetFilter(e.target.value)}
              className="h-8 rounded-md border border-input bg-background px-3 text-xs"
            >
              <option value="">All Targets</option>
              {targets.map(t => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            {(sevFilter || srcFilter || statusFilter || targetFilter) && (
              <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => { setSevFilter(''); setSrcFilter(''); setStatusFilter(''); setTargetFilter('') }}>
                <X className="h-3 w-3 mr-1" /> Clear
              </Button>
            )}
            <Button variant="outline" size="sm" className="h-8 text-xs ml-auto" onClick={fetchFindings}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Apply
            </Button>
          </div>

          {findingsLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <AlertTriangle className="h-10 w-10 text-muted-foreground/40 mb-3" />
              <p className="text-sm text-muted-foreground">No findings yet.</p>
              <p className="text-xs text-muted-foreground mt-1">Run a scan on your targets to discover issues.</p>
            </div>
          ) : (
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Severity</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Finding</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Target</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Source</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">First Seen</th>
                    <th className="px-4 py-2.5 text-left font-medium text-xs text-muted-foreground">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {findings.map(f => {
                    const target = targets.find(t => t.id === f.target_id)
                    return (
                      <tr key={f.id} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-4 py-3 max-w-xs">
                          <p className="font-medium text-sm leading-snug">{f.title}</p>
                          {f.description && (
                            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{f.description}</p>
                          )}
                          {f.evidence && (
                            <pre className="text-[10px] text-muted-foreground mt-1 font-mono bg-muted/50 px-2 py-1 rounded max-h-12 overflow-hidden">{f.evidence.slice(0, 200)}</pre>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground font-mono">
                          {target ? target.target_value : f.target_id.slice(0, 8)}
                        </td>
                        <td className="px-4 py-3">
                          {f.source && (
                            <Badge variant="outline" className="text-[10px] capitalize">{f.source}</Badge>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {formatRelativeTime(f.first_seen)}
                        </td>
                        <td className="px-4 py-3">
                          <select
                            value={f.status}
                            onChange={e => handleFindingStatus(f.id, e.target.value)}
                            className="h-7 rounded border border-input bg-background px-2 text-xs"
                          >
                            <option value="new">New</option>
                            <option value="confirmed">Confirmed</option>
                            <option value="false_positive">False Positive</option>
                            <option value="remediated">Remediated</option>
                            <option value="approved_exception">Approved Exception</option>
                            <option value="accepted_risk">Accepted Risk</option>
                            <option value="compensating_control">Compensating Control</option>
                            <option value="not_exploitable">Not Exploitable</option>
                          </select>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
