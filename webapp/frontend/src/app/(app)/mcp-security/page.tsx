'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, AlertTriangle, Ban, Braces, CheckCircle2, Clock3, Copy, Download, HelpCircle, KeyRound, Network, Play, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { PageHeader } from '@/components/shared/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/use-toast'
import { cancelMcpSecurityRun, createMcpSecurityRun, deleteMcpSecurityRun, getMcpSecurityRun, getMcpSecurityRuns } from '@/lib/api'
import type { McpExchange, McpFinding, McpSecurityRun } from '@/lib/types'
import { cn, formatRelativeTime } from '@/lib/utils'

const severityVariant = (severity: string) => severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'
const pretty = (value: unknown) => typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2)
const ALL = '__all__'

function downloadText(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

function ExchangeInspector({ exchanges, findings }: { exchanges: McpExchange[]; findings: McpFinding[] }) {
  const [selectedId, setSelectedId] = useState(exchanges[0]?.id || '')
  const detailPaneRef = useRef<HTMLDivElement | null>(null)
  const selectedButtonRef = useRef<HTMLButtonElement | null>(null)
  const selected = exchanges.find((item) => item.id === selectedId) || exchanges[0]
  useEffect(() => {
    detailPaneRef.current?.scrollTo({ top: 0 })
    selectedButtonRef.current?.scrollIntoView({ block: 'nearest' })
  }, [selectedId])
  if (!selected) return <p className="py-12 text-center text-sm text-muted-foreground">No protocol exchanges were captured.</p>
  const linked = findings.filter((finding) => finding.exchange_id === selected.id)

  return (
    <div className="grid min-h-[520px] max-h-[68vh] overflow-hidden rounded-2xl border bg-slate-950 text-slate-100 lg:grid-cols-[300px_1fr]">
      <div className="overflow-y-auto border-b border-slate-800 bg-slate-900/70 p-2 lg:border-b-0 lg:border-r">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-400">Command timeline</div>
        <div className="space-y-1">
          {exchanges.map((exchange, index) => (
            <button
              key={exchange.id}
              ref={selected.id === exchange.id ? selectedButtonRef : null}
              onClick={() => setSelectedId(exchange.id)}
              className={cn(
              'flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors',
              selected.id === exchange.id ? 'bg-cyan-400/10 text-cyan-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
            )}
            >
              <span className="font-mono text-[10px] text-slate-600">{String(index + 1).padStart(2, '0')}</span>
              <span className="min-w-0 flex-1 truncate text-xs font-medium">{exchange.name}</span>
              <span className={cn('font-mono text-[10px]', exchange.response.status && exchange.response.status < 400 ? 'text-emerald-400' : 'text-amber-400')}>
                {exchange.response.status || 'ERR'}
              </span>
            </button>
          ))}
        </div>
      </div>
      <div ref={detailPaneRef} className="min-w-0 overflow-y-auto">
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-5 py-4">
          <Badge className="border-cyan-400/20 bg-cyan-400/10 font-mono text-cyan-300">{selected.request.method}</Badge>
          <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">{selected.request.url}</span>
          <span className="flex items-center gap-1 text-xs text-slate-500"><Clock3 className="h-3 w-3" />{selected.duration_ms} ms</span>
        </div>
        <Tabs defaultValue="request" className="p-5">
          <TabsList className="bg-slate-900">
            <TabsTrigger value="request">Request</TabsTrigger>
            <TabsTrigger value="response">Response</TabsTrigger>
            <TabsTrigger value="issues">Issues ({linked.length})</TabsTrigger>
          </TabsList>
          <TabsContent value="request" className="space-y-4">
            <CodeBlock label="Headers" value={selected.request.headers} />
            <CodeBlock label="Body" value={selected.request.body} />
          </TabsContent>
          <TabsContent value="response" className="space-y-4">
            <CodeBlock label={`HTTP ${selected.response.status || 'error'} headers`} value={selected.response.headers} />
            {selected.response.header_values && Object.values(selected.response.header_values).some((values) => values.length > 1) && <CodeBlock label="Duplicate header values" value={selected.response.header_values} />}
            <CodeBlock label="Body" value={selected.response.error || selected.response.body} />
          </TabsContent>
          <TabsContent value="issues" className="space-y-3">
            {linked.length === 0 && <p className="py-8 text-center text-sm text-slate-500">No finding is directly linked to this exchange.</p>}
            {linked.map((finding) => <FindingCard key={finding.id} finding={finding} dark />)}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}

function CodeBlock({ label, value }: { label: string; value: unknown }) {
  return <div><p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-xl border border-slate-800 bg-black/30 p-4 font-mono text-xs leading-5 text-emerald-300">{pretty(value)}</pre></div>
}

function FindingCard({ finding, dark = false }: { finding: McpFinding; dark?: boolean }) {
  return <div className={cn('rounded-xl border p-4', dark ? 'border-slate-800 bg-slate-900/70' : 'bg-card')}>
    <div className="flex flex-wrap items-center gap-2"><Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge><span className="text-xs text-muted-foreground">{finding.category}</span>{finding.test_id && <span className="font-mono text-[10px] text-cyan-600">{finding.test_id}</span>}</div>
    <h3 className="mt-3 text-sm font-semibold">{finding.title}</h3>
    <p className={cn('mt-2 text-xs leading-5', dark ? 'text-slate-400' : 'text-muted-foreground')}>{finding.evidence}</p>
    <p className={cn('mt-3 border-t pt-3 text-xs leading-5', dark ? 'border-slate-800 text-cyan-200' : 'text-foreground')}>{finding.remediation}</p>
  </div>
}

export default function McpSecurityPage() {
  const { toast } = useToast()
  const [runs, setRuns] = useState<McpSecurityRun[]>([])
  const [selected, setSelected] = useState<McpSecurityRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [deleteRun, setDeleteRun] = useState<McpSecurityRun | null>(null)
  const [coverageStatus, setCoverageStatus] = useState('all')
  const [coverageQuery, setCoverageQuery] = useState('')
  const [historyQuery, setHistoryQuery] = useState('')
  const [historyStatus, setHistoryStatus] = useState(ALL)
  const [activeRunId, setActiveRunId] = useState<string | null>(null)
  const ignoredRunIds = useRef(new Set<string>())
  const [form, setForm] = useState({
    name: '', endpoint: '', bearer_token: '', secondary_bearer_token: '', audience_mismatch_token: '', issuer_mismatch_token: '',
    approved_tool_name: '', approved_tool_arguments: '{}', approved_resource_uri: '', approved_prompt_name: '', test_task_id: '',
    canary_url: '', cross_server_endpoint: '', cross_server_bearer_token: '', local_config_text: '', max_concurrency: 4,
    allow_private: false, protocol_tests: true, enable_deep_tests: false, allow_mutation_tests: false,
    authorization_confirmed: false, deep_authorization_confirmed: false,
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getMcpSecurityRuns()
      setRuns(data.items)
      setSelected((current) => data.items.find((item) => item.id === current?.id) || data.items[0] || null)
    } catch { toast({ title: 'MCP history unavailable', description: 'Check the API connection and try again.', variant: 'destructive' }) }
    finally { setLoading(false) }
  }, [toast])
  useEffect(() => { void load() }, [load])

  function updateRun(run: McpSecurityRun) {
    setRuns((items) => items.some((item) => item.id === run.id)
      ? items.map((item) => item.id === run.id ? run : item)
      : [run, ...items])
    setSelected((current) => !current || current.id === run.id ? run : current)
  }

  function loadRunIntoForm(run: McpSecurityRun) {
    const profile = run.inventory.execution_profile || {}
    const transport = (run.inventory as { transport_profile?: Record<string, unknown> }).transport_profile || {}
    setForm({
      name: `${run.name} retry`,
      endpoint: run.endpoint,
      bearer_token: '',
      secondary_bearer_token: '',
      audience_mismatch_token: '',
      issuer_mismatch_token: '',
      approved_tool_name: typeof profile.approved_tool_name === 'string' ? profile.approved_tool_name : '',
      approved_tool_arguments: JSON.stringify(profile.approved_tool_arguments || {}, null, 2),
      approved_resource_uri: typeof profile.approved_resource_uri === 'string' ? profile.approved_resource_uri : '',
      approved_prompt_name: typeof profile.approved_prompt_name === 'string' ? profile.approved_prompt_name : '',
      test_task_id: typeof profile.test_task_id === 'string' ? profile.test_task_id : '',
      canary_url: typeof profile.canary_url === 'string' ? profile.canary_url : '',
      cross_server_endpoint: typeof profile.cross_server_endpoint === 'string' ? profile.cross_server_endpoint : '',
      cross_server_bearer_token: '',
      local_config_text: typeof profile.local_config_text === 'string' ? profile.local_config_text : '',
      max_concurrency: typeof profile.max_concurrency === 'number' ? profile.max_concurrency : 4,
      allow_private: transport.allow_private === true,
      protocol_tests: transport.protocol_tests !== false,
      enable_deep_tests: profile.deep_tests === true,
      allow_mutation_tests: profile.mutation_tests === true,
      authorization_confirmed: false,
      deep_authorization_confirmed: false,
    })
    window.scrollTo({ top: 0, behavior: 'smooth' })
    toast({
      title: 'Run loaded into the form',
      description: 'Non-secret settings were copied. Re-enter any tokens before retrying.',
    })
  }

  async function watchRun(runId: string) {
    for (let attempt = 0; attempt < 2400; attempt += 1) {
      if (ignoredRunIds.current.has(runId)) return
      await new Promise((resolve) => window.setTimeout(resolve, 1500))
      if (ignoredRunIds.current.has(runId)) return
      const latest = await getMcpSecurityRun(runId)
      updateRun(latest)
      if (['completed', 'failed', 'cancelled'].includes(latest.status)) {
        toast({
          title: latest.status === 'completed' ? 'MCP assessment complete' : latest.status === 'cancelled' ? 'MCP assessment cancelled' : 'MCP assessment failed safely',
          description: latest.error_message || `${latest.exchanges.length} exchanges captured with ${latest.findings.length} findings.`,
          variant: latest.status === 'failed' ? 'destructive' : 'default',
        })
        return
      }
    }
    toast({ title: 'MCP assessment is still running', description: 'The job remains available in run history; refresh to continue monitoring it.' })
  }

  async function startRun(event: React.FormEvent) {
    event.preventDefault()
    if (!form.authorization_confirmed) {
      toast({ title: 'Authorization required', description: 'Confirm you are authorized to test this MCP endpoint.', variant: 'destructive' })
      return
    }
    setRunning(true)
    try {
      let approvedArguments: Record<string, unknown>
      try {
        approvedArguments = JSON.parse(form.approved_tool_arguments || '{}')
        if (!approvedArguments || Array.isArray(approvedArguments) || typeof approvedArguments !== 'object') throw new Error('not an object')
      } catch {
        throw new Error('Approved tool arguments must be a JSON object.')
      }
      const run = await createMcpSecurityRun({
        ...form,
        name: form.name || `MCP audit ${new URL(form.endpoint).hostname}`,
        approved_tool_arguments: approvedArguments,
        secondary_bearer_token: form.secondary_bearer_token || undefined,
        audience_mismatch_token: form.audience_mismatch_token || undefined,
        issuer_mismatch_token: form.issuer_mismatch_token || undefined,
        approved_tool_name: form.approved_tool_name || undefined,
        approved_resource_uri: form.approved_resource_uri || undefined,
        approved_prompt_name: form.approved_prompt_name || undefined,
        test_task_id: form.test_task_id || undefined,
        canary_url: form.canary_url || undefined,
        cross_server_endpoint: form.cross_server_endpoint || undefined,
        cross_server_bearer_token: form.cross_server_bearer_token || undefined,
        local_config_text: form.local_config_text || undefined,
      })
      updateRun(run)
      setActiveRunId(run.id)
      setForm((value) => ({
        ...value,
        bearer_token: '', secondary_bearer_token: '', audience_mismatch_token: '', issuer_mismatch_token: '',
        cross_server_bearer_token: '', approved_tool_arguments: '{}', local_config_text: '', test_task_id: '',
        deep_authorization_confirmed: false, allow_mutation_tests: false,
      }))
      toast({ title: 'MCP assessment queued', description: 'Progress and the current protocol step will update automatically.' })
      await watchRun(run.id)
    } catch (error: any) {
      toast({ title: 'Could not start MCP assessment', description: error.response?.data?.detail || error.message || 'Review the endpoint and authorization settings.', variant: 'destructive' })
    } finally { setRunning(false); setActiveRunId(null) }
  }

  async function cancelActiveRun() {
    if (!activeRunId) return
    try {
      const run = await cancelMcpSecurityRun(activeRunId)
      updateRun(run)
      toast({ title: 'Cancellation requested', description: 'The worker will stop before the next protocol exchange.' })
    } catch (error: any) {
      toast({ title: 'Could not cancel assessment', description: error.response?.data?.detail || 'The run may already be complete.', variant: 'destructive' })
    }
  }

  async function confirmDelete() {
    if (!deleteRun) return
    try {
      ignoredRunIds.current.add(deleteRun.id)
      await deleteMcpSecurityRun(deleteRun.id)
      const remaining = runs.filter((item) => item.id !== deleteRun.id)
      setRuns(remaining)
      if (selected?.id === deleteRun.id) setSelected(remaining[0] || null)
      if (activeRunId === deleteRun.id) { setActiveRunId(null); setRunning(false) }
      setDeleteRun(null)
      toast({ title: 'MCP assessment deleted' })
    } catch { toast({ title: 'Delete failed', description: 'The assessment was not changed. Try again.', variant: 'destructive' }) }
  }

  const inventory = selected?.inventory || {}
  const protocolChecks = inventory.protocol_checks || []
  const canonicalCoverage = inventory.test_coverage || []
  const negotiation = inventory.negotiation || {}
  const manualTests = inventory.recommended_manual_tests || []
  const executionProfile = inventory.execution_profile || {}
  const transportProfile = (inventory as { transport_profile?: Record<string, unknown> }).transport_profile || {}
  const visibleCoverage = canonicalCoverage.filter((test) => {
    const matchesStatus = coverageStatus === 'all' || test.status === coverageStatus
    const query = coverageQuery.trim().toLowerCase()
    return matchesStatus && (!query || `${test.test_id} ${test.title} ${test.reason || ''}`.toLowerCase().includes(query))
  })
  const visibleRuns = useMemo(() => {
    const query = historyQuery.trim().toLowerCase()
    return runs.filter((run) => {
      const matchesStatus = historyStatus === ALL || run.status === historyStatus
      const matchesQuery = !query || `${run.name} ${run.endpoint} ${run.id}`.toLowerCase().includes(query)
      return matchesStatus && matchesQuery
    })
  }, [historyQuery, historyStatus, runs])
  const metrics: Array<[string, number, LucideIcon]> = selected ? [
    ['Risk score', selected.risk_score, ShieldCheck],
    ['Tools', selected.summary.tools || 0, Braces],
    ['Resources', selected.summary.resources || 0, Network],
    ['Exchanges', selected.summary.exchanges || 0, CheckCircle2],
  ] : []
  return <div>
    <PageHeader title="MCP Security" description="Inventory MCP servers, exercise protocol and identity boundaries, and inspect every exchange. Tool or resource invocation remains opt-in for disposable targets.">
      <Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className={cn('mr-2 h-4 w-4', loading && 'animate-spin')} />Refresh</Button>
    </PageHeader>

    <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
      <div className="space-y-6">
        <Card className="overflow-hidden border-cyan-500/20">
          <div className="h-1 bg-gradient-to-r from-cyan-400 via-emerald-400 to-amber-300" />
          <CardHeader><CardTitle className="flex items-center gap-2 text-lg"><Network className="h-5 w-5 text-cyan-500" />New assessment</CardTitle></CardHeader>
          <CardContent><form onSubmit={startRun} className="space-y-4">
            <div><Label htmlFor="mcp-name">Name</Label><Input id="mcp-name" className="mt-1.5" placeholder="Production agent gateway" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div><Label htmlFor="mcp-endpoint">MCP endpoint</Label><Input id="mcp-endpoint" className="mt-1.5 font-mono text-xs" type="url" required placeholder="https://mcp.example.com/mcp" value={form.endpoint} onChange={(e) => setForm({ ...form, endpoint: e.target.value })} /><p className="mt-1 text-[11px] text-muted-foreground">Supports both legacy `initialize` MCP and newer `server/discover` MCP.</p></div>
                <div><Label htmlFor="mcp-token" className="flex items-center gap-2"><KeyRound className="h-3.5 w-3.5" />Bearer token (optional)</Label><Input id="mcp-token" className="mt-1.5" type="password" autoComplete="off" value={form.bearer_token} onChange={(e) => setForm({ ...form, bearer_token: e.target.value })} /><p className="mt-1 text-[11px] text-muted-foreground">Used once, redacted from evidence, and never stored.</p></div>
            <div className="rounded-xl border bg-muted/20 p-3 text-xs leading-5 text-muted-foreground">
              Expanded MCP testing works best when you can provide disposable prerequisites:
              a primary token, optional secondary identity token, optional wrong-audience or wrong-issuer tokens, one explicitly approved disposable tool/resource/prompt, an optional disposable task ID for Tasks/MRTR mutation checks, an optional canary URL for outbound-call correlation, and optional local stdio config for offline analysis.
            </div>
            <details className="group rounded-xl border bg-muted/20">
              <summary className="cursor-pointer list-none px-3 py-3 text-sm font-medium">Advanced execution profile <span className="float-right text-xs text-muted-foreground group-open:hidden">Expand</span></summary>
              <div className="space-y-4 border-t p-3">
                <p className="text-[11px] leading-5 text-muted-foreground">Optional inputs unlock cross-principal, OAuth, Tasks, MRTR, canary, cross-server, and local stdio configuration tests. Credentials are used in memory and redacted from evidence.</p>
                <div><Label htmlFor="mcp-secondary-token">Secondary principal token</Label><Input id="mcp-secondary-token" className="mt-1.5" type="password" autoComplete="off" value={form.secondary_bearer_token} onChange={(e) => setForm({ ...form, secondary_bearer_token: e.target.value })} /></div>
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                  <div><Label htmlFor="mcp-audience-token">Wrong-audience test token</Label><Input id="mcp-audience-token" className="mt-1.5" type="password" autoComplete="off" value={form.audience_mismatch_token} onChange={(e) => setForm({ ...form, audience_mismatch_token: e.target.value })} /></div>
                  <div><Label htmlFor="mcp-issuer-token">Wrong-issuer test token</Label><Input id="mcp-issuer-token" className="mt-1.5" type="password" autoComplete="off" value={form.issuer_mismatch_token} onChange={(e) => setForm({ ...form, issuer_mismatch_token: e.target.value })} /></div>
                </div>
                <div><Label htmlFor="mcp-tool">Approved disposable tool</Label><Input id="mcp-tool" className="mt-1.5 font-mono text-xs" placeholder="security_test_fixture" value={form.approved_tool_name} onChange={(e) => setForm({ ...form, approved_tool_name: e.target.value })} /></div>
                <div><Label htmlFor="mcp-tool-args">Approved tool arguments</Label><Textarea id="mcp-tool-args" className="mt-1.5 min-h-20 font-mono text-xs" value={form.approved_tool_arguments} onChange={(e) => setForm({ ...form, approved_tool_arguments: e.target.value })} /></div>
                <div><Label htmlFor="mcp-resource">Approved resource URI</Label><Input id="mcp-resource" className="mt-1.5 font-mono text-xs" value={form.approved_resource_uri} onChange={(e) => setForm({ ...form, approved_resource_uri: e.target.value })} /></div>
                <div><Label htmlFor="mcp-prompt">Approved prompt name</Label><Input id="mcp-prompt" className="mt-1.5 font-mono text-xs" value={form.approved_prompt_name} onChange={(e) => setForm({ ...form, approved_prompt_name: e.target.value })} /></div>
                <div><Label htmlFor="mcp-task">Disposable task ID</Label><Input id="mcp-task" className="mt-1.5 font-mono text-xs" value={form.test_task_id} onChange={(e) => setForm({ ...form, test_task_id: e.target.value })} /></div>
                <div><Label htmlFor="mcp-canary">OOB canary base URL</Label><Input id="mcp-canary" className="mt-1.5 font-mono text-xs" type="url" placeholder="https://canary.example.net/unique-id" value={form.canary_url} onChange={(e) => setForm({ ...form, canary_url: e.target.value })} /></div>
                <div><Label htmlFor="mcp-cross-server">Second MCP endpoint</Label><Input id="mcp-cross-server" className="mt-1.5 font-mono text-xs" type="url" value={form.cross_server_endpoint} onChange={(e) => setForm({ ...form, cross_server_endpoint: e.target.value })} /></div>
                <div><Label htmlFor="mcp-cross-token">Second endpoint token</Label><Input id="mcp-cross-token" className="mt-1.5" type="password" autoComplete="off" value={form.cross_server_bearer_token} onChange={(e) => setForm({ ...form, cross_server_bearer_token: e.target.value })} /></div>
                <div><Label htmlFor="mcp-local-config">Local MCP configuration</Label><Textarea id="mcp-local-config" className="mt-1.5 min-h-24 font-mono text-xs" placeholder='{"mcpServers":{"local":{"command":"/usr/local/bin/server"}}}' value={form.local_config_text} onChange={(e) => setForm({ ...form, local_config_text: e.target.value })} /></div>
                <div><Label htmlFor="mcp-concurrency">Bounded concurrency: {form.max_concurrency}</Label><Input id="mcp-concurrency" className="mt-1.5" type="range" min={1} max={8} value={form.max_concurrency} onChange={(e) => setForm({ ...form, max_concurrency: Number(e.target.value) })} /></div>
                <div className="flex items-center justify-between rounded-xl border p-3"><div><p className="text-sm font-medium">Deep disposable-target tests</p><p className="text-[11px] text-muted-foreground">May invoke only the approved tool/resource/prompt</p></div><Switch checked={form.enable_deep_tests} onCheckedChange={(value) => setForm({ ...form, enable_deep_tests: value })} /></div>
                <div className="flex items-center justify-between rounded-xl border p-3"><div><p className="text-sm font-medium">Task mutation race</p><p className="text-[11px] text-muted-foreground">May update/cancel the disposable task ID</p></div><Switch checked={form.allow_mutation_tests} onCheckedChange={(value) => setForm({ ...form, allow_mutation_tests: value })} /></div>
                {(form.enable_deep_tests || form.allow_mutation_tests) && <label className="flex cursor-pointer gap-3 rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-xs leading-5"><input type="checkbox" className="mt-1 h-4 w-4 accent-red-600" checked={form.deep_authorization_confirmed} onChange={(e) => setForm({ ...form, deep_authorization_confirmed: e.target.checked })} /><span>I confirm this is an isolated, disposable target and authorize the selected tool/resource/task operations.</span></label>}
              </div>
            </details>
            <div className="flex items-center justify-between rounded-xl border p-3"><div><p className="text-sm font-medium">Protocol safety tests</p><p className="text-[11px] text-muted-foreground">Origin and malformed JSON checks</p></div><Switch checked={form.protocol_tests} onCheckedChange={(value) => setForm({ ...form, protocol_tests: value })} /></div>
            <div className="flex items-center justify-between rounded-xl border p-3"><div><p className="text-sm font-medium">Private endpoint</p><p className="text-[11px] text-muted-foreground">Required for localhost; Docker routes it to the host</p></div><Switch checked={form.allow_private} onCheckedChange={(value) => setForm({ ...form, allow_private: value })} /></div>
            <details className="rounded-xl border bg-muted/20"><summary className="cursor-pointer px-3 py-3 text-sm font-medium">73-test coverage map</summary><div className="grid grid-cols-2 gap-x-3 gap-y-2 border-t p-3 text-[11px] text-muted-foreground"><span>Protocol: 6</span><span>Authorization: 6</span><span>State: 5</span><span>MRTR: 5</span><span>Tasks: 4</span><span>Cache: 4</span><span>AI trust: 7</span><span>Injection sinks: 5</span><span>SSRF: 4</span><span>OAuth: 4</span><span>Data: 3</span><span>Chains: 3</span><span>Apps/UI: 3</span><span>Local/stdio: 4</span><span>DoS: 3</span><span>Telemetry: 2</span><span>Supply chain: 3</span><span>Drift: 2</span></div><p className="border-t px-3 py-2 text-[10px] leading-4 text-muted-foreground">Every test receives an explicit executed, failed, review, blocked, or not-applicable outcome. Advanced prerequisites are never reported as passed when they were not supplied.</p></details>
            <label className="flex cursor-pointer gap-3 rounded-xl bg-amber-500/8 p-3 text-xs leading-5"><input type="checkbox" className="mt-1 h-4 w-4 accent-cyan-600" checked={form.authorization_confirmed} onChange={(e) => setForm({ ...form, authorization_confirmed: e.target.checked })} /><span>I confirm I am authorized to test this endpoint. Advertised tools are invoked only when deep tests and the separate isolated-target confirmation are enabled.</span></label>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1"><Button className="w-full" disabled={running}>{running ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}{running ? 'Monitoring assessment...' : 'Start MCP assessment'}</Button>{running && <Button type="button" variant="destructive" className="w-full" onClick={() => void cancelActiveRun()}><Ban className="mr-2 h-4 w-4" />Cancel assessment</Button>}</div>
          </form></CardContent>
        </Card>

        <Card><CardHeader><CardTitle className="text-base">Run history</CardTitle></CardHeader><CardContent className="space-y-3">
          <div className="grid gap-2">
            <Input placeholder="Search by name, endpoint, or run ID" value={historyQuery} onChange={(event) => setHistoryQuery(event.target.value)} />
            <Select value={historyStatus} onValueChange={setHistoryStatus}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All statuses</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="cancel_requested">Cancel requested</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {!loading && visibleRuns.length === 0 && <p className="text-sm text-muted-foreground">No MCP assessments match these filters.</p>}
          {visibleRuns.map((run) => <button key={run.id} onClick={() => setSelected(run)} className={cn('w-full rounded-xl border p-3 text-left transition-colors', selected?.id === run.id ? 'border-cyan-500/40 bg-cyan-500/5' : 'hover:bg-muted/60')}>
            <div className="flex items-center gap-2"><span className="min-w-0 flex-1 truncate text-sm font-medium">{run.name}</span><Badge variant={run.status === 'failed' ? 'destructive' : run.status === 'completed' ? severityVariant(run.overall_severity) : 'outline'}>{run.status === 'completed' ? run.overall_severity : run.status.replace('_', ' ').toUpperCase()}</Badge></div>
            <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground">{run.endpoint}</p>
            <div className="mt-1 flex items-center justify-between gap-3 text-[11px] text-muted-foreground">
              <span>{formatRelativeTime(run.created_at)}</span>
              <span className="font-mono">{run.id.slice(0, 8)}</span>
            </div>
          </button>)}
        </CardContent></Card>
      </div>

      <div className="min-w-0 space-y-6">
        {!selected ? <Card><CardContent className="py-24 text-center"><ShieldCheck className="mx-auto h-10 w-10 text-muted-foreground" /><p className="mt-4 text-sm text-muted-foreground">Start or select an MCP assessment to inspect it.</p></CardContent></Card> : <>
          <Card><CardContent className="flex flex-wrap items-center gap-3 p-5"><div className="min-w-0 flex-1"><div className="flex items-center gap-2"><h2 className="truncate text-xl font-semibold">{selected.name}</h2><Badge variant={selected.status === 'failed' ? 'destructive' : severityVariant(selected.overall_severity)}>{selected.status}</Badge></div><p className="mt-1 truncate font-mono text-xs text-muted-foreground">{selected.endpoint}</p></div><Button variant="outline" size="sm" onClick={() => loadRunIntoForm(selected)}><Copy className="mr-2 h-4 w-4" />Load as template</Button><Button variant="outline" size="sm" onClick={() => downloadText(`${selected.name.replace(/[^a-z0-9-_]+/gi, '-').toLowerCase()}-${selected.id}.json`, JSON.stringify(selected, null, 2), 'application/json;charset=utf-8')}><Download className="mr-2 h-4 w-4" />Export JSON</Button><Button variant="outline" size="sm" onClick={() => setDeleteRun(selected)}><Trash2 className="mr-2 h-4 w-4" />Delete</Button></CardContent></Card>
          {['queued', 'running', 'cancel_requested'].includes(selected.status) && <Card><CardContent className="p-4"><div className="flex items-center justify-between gap-3 text-xs"><span className="font-medium capitalize">{selected.summary.current_step || selected.status.replace('_', ' ')}</span><span className="font-mono text-muted-foreground">{selected.summary.progress || 0}%</span></div><div className="mt-2 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-cyan-500 transition-all duration-500" style={{ width: `${Math.max(2, selected.summary.progress || 0)}%` }} /></div><p className="mt-2 text-[11px] text-muted-foreground">{selected.summary.completed_steps || 0} protocol exchanges completed{selected.summary.estimated_steps ? ` of approximately ${selected.summary.estimated_steps}` : ''}.</p></CardContent></Card>}
          {selected.error_message && <div className="flex gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-500"><AlertTriangle className="h-5 w-5 shrink-0" />{selected.error_message}</div>}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{metrics.map(([label, value, Icon]) => <Card key={label}><CardContent className="flex items-center gap-3 p-4"><Icon className="h-5 w-5 text-cyan-500" /><div><p className="text-2xl font-semibold">{value}</p><p className="text-xs text-muted-foreground">{label}</p></div></CardContent></Card>)}</div>
          <Tabs defaultValue="exchanges">
            <TabsList><TabsTrigger value="exchanges">Exchange Inspector</TabsTrigger><TabsTrigger value="coverage">Test Coverage ({canonicalCoverage.length || protocolChecks.length})</TabsTrigger><TabsTrigger value="findings">Findings ({selected.findings.length})</TabsTrigger><TabsTrigger value="inventory">Inventory</TabsTrigger><TabsTrigger value="reporting">Reporting</TabsTrigger></TabsList>
            <TabsContent value="exchanges"><ExchangeInspector key={selected.id} exchanges={selected.exchanges} findings={selected.findings} /></TabsContent>
            <TabsContent value="coverage" className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{(['executed', 'failed', 'review', 'blocked', 'not_applicable'] as const).map((status) => <Card key={status}><CardContent className="p-4"><p className="text-2xl font-semibold">{selected.summary.test_coverage?.[status] || 0}</p><p className="mt-1 text-xs capitalize text-muted-foreground">{status.replace('_', ' ')}</p></CardContent></Card>)}</div>
              {canonicalCoverage.length > 0 && <Card><CardHeader><CardTitle className="text-sm">Canonical MCP test specification</CardTitle></CardHeader><CardContent className="p-4"><div className="mb-4 grid gap-2 sm:grid-cols-[1fr_180px]"><Input aria-label="Search MCP tests" placeholder="Search ID, title, or reason" value={coverageQuery} onChange={(event) => setCoverageQuery(event.target.value)} /><select aria-label="Filter MCP tests by status" className="h-10 rounded-md border bg-background px-3 text-sm" value={coverageStatus} onChange={(event) => setCoverageStatus(event.target.value)}><option value="all">All statuses</option><option value="executed">Executed</option><option value="failed">Failed</option><option value="review">Review</option><option value="blocked">Blocked</option><option value="not_applicable">Not applicable</option></select></div><div className="grid gap-2 md:grid-cols-2">{visibleCoverage.map((test) => <div key={test.test_id} className="rounded-lg border p-2.5"><div className="flex items-center justify-between gap-2"><span className="font-mono text-xs font-medium">{test.test_id}</span><Badge variant={test.status === 'failed' ? 'destructive' : test.status === 'executed' ? 'success' : 'outline'}>{test.status.replace('_', ' ')}</Badge></div><p className="mt-1 text-xs font-medium">{test.title}</p><p className="mt-1 text-[11px] text-muted-foreground">{test.mode.replaceAll('_', ' ')}{test.reason ? ` · ${test.reason}` : ''}</p>{test.evidence != null && <details className="mt-2"><summary className="cursor-pointer text-[11px] text-cyan-600">Evidence</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-2 font-mono text-[10px]">{pretty(test.evidence)}</pre></details>}</div>)}{visibleCoverage.length === 0 && <p className="col-span-full py-10 text-center text-sm text-muted-foreground">No tests match these filters.</p>}</div></CardContent></Card>}
              <p className="text-xs text-muted-foreground">Protocol exchange results</p>
              <Card><CardContent className="divide-y p-0">{protocolChecks.map((check) => {
                const Icon = check.status === 'passed' ? CheckCircle2 : check.status === 'failed' ? AlertCircle : HelpCircle
                return <button key={check.id} onClick={() => {
                  const exchange = selected.exchanges.find((item) => item.id === check.id)
                  if (exchange) toast({ title: check.name, description: `${check.detail}; inspect the Exchange Inspector for full request and response.` })
                }} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/50">
                  <Icon className={cn('h-4 w-4 shrink-0', check.status === 'passed' ? 'text-emerald-500' : check.status === 'failed' ? 'text-red-500' : 'text-amber-500')} />
                  <div className="min-w-0 flex-1"><p className="font-mono text-xs font-medium">{check.name}</p><p className="mt-1 truncate text-xs text-muted-foreground">{check.detail}</p></div>
                  <Badge variant={check.status === 'failed' ? 'destructive' : check.status === 'passed' ? 'success' : 'outline'}>{check.status}</Badge>
                  <span className="w-16 text-right font-mono text-[11px] text-muted-foreground">{check.duration_ms} ms</span>
                </button>
              })}</CardContent></Card>
            </TabsContent>
            <TabsContent value="findings" className="grid gap-3 md:grid-cols-2">{selected.findings.length === 0 ? <p className="col-span-full py-12 text-center text-sm text-muted-foreground">No issues were identified by the current checks.</p> : selected.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</TabsContent>
            <TabsContent value="inventory" className="space-y-4">
              <Card>
                <CardContent className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-4">
                  <div><p className="text-xs text-muted-foreground">Negotiated protocol</p><p className="mt-1 font-mono text-sm">{negotiation.selected_protocol || inventory.protocol_version || 'Not advertised'}</p></div>
                  <div><p className="text-xs text-muted-foreground">Server</p><p className="mt-1 font-mono text-sm">{String(inventory.server?.name || 'Unknown')}</p></div>
                  <div><p className="text-xs text-muted-foreground">Discover fallback</p><p className="mt-1 text-sm">{negotiation.fallback_reason || 'Not needed'}</p></div>
                  <div><p className="text-xs text-muted-foreground">Definition fingerprint</p><p className="mt-1 truncate font-mono text-xs">{inventory.tool_fingerprint || 'Unavailable'}</p></div>
                </CardContent>
              </Card>
              <CodeBlock label="Discover support and cache hints" value={{ supported_versions: negotiation.discover_supported_versions || [], cache_hints: inventory.cache_hints || {} }} />
              <CodeBlock label="Execution profile (credentials excluded)" value={inventory.execution_profile || {}} />
              {inventory.oauth_metadata && Object.keys(inventory.oauth_metadata).length > 0 && <CodeBlock label="OAuth protected-resource metadata" value={inventory.oauth_metadata} />}
              {inventory.local_config_analysis && <CodeBlock label="Offline local configuration analysis" value={inventory.local_config_analysis} />}
              {inventory.instructions && <CodeBlock label="Server instructions" value={inventory.instructions} />}
              {manualTests.length > 0 && <Card><CardHeader><CardTitle className="text-base">Recommended follow-up tests</CardTitle></CardHeader><CardContent className="space-y-2">{manualTests.map((item: string) => <div key={item} className="rounded-xl border px-3 py-2 text-sm text-muted-foreground">{item}</div>)}</CardContent></Card>}
              <CodeBlock label="Advertised tools" value={inventory.tools || []} />
              <CodeBlock label="Resources" value={inventory.resources || []} />
              <CodeBlock label="Resource templates" value={inventory.resource_templates || []} />
              <CodeBlock label="Prompts" value={inventory.prompts || []} />
            </TabsContent>
            <TabsContent value="reporting" className="space-y-4">
              <Card>
                <CardHeader><CardTitle className="text-base">Assessment summary</CardTitle></CardHeader>
                <CardContent className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-4">
                  <div><p className="text-xs text-muted-foreground">Overall severity</p><p className="mt-1 text-sm font-semibold">{selected.overall_severity}</p></div>
                  <div><p className="text-xs text-muted-foreground">Risk score</p><p className="mt-1 text-sm font-semibold">{selected.risk_score}</p></div>
                  <div><p className="text-xs text-muted-foreground">Executed tests</p><p className="mt-1 text-sm font-semibold">{selected.summary.test_coverage?.executed || 0}</p></div>
                  <div><p className="text-xs text-muted-foreground">Manual follow-ups</p><p className="mt-1 text-sm font-semibold">{manualTests.length}</p></div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-base">Expanded scan requirements</CardTitle></CardHeader>
                <CardContent className="space-y-2 text-sm text-muted-foreground">
                  <p>Base coverage only needs the endpoint and authorization confirmation. Authenticated and expanded coverage improves when you provide optional disposable test material.</p>
                  <p>Recommended optional inputs: primary token, secondary token, wrong-audience token, wrong-issuer token, approved disposable tool or resource, approved prompt name, disposable task ID for Tasks testing, canary URL, second MCP endpoint, and local stdio configuration text.</p>
                  <p>Current run profile: protocol tests {transportProfile.protocol_tests === false ? 'disabled' : 'enabled'}, private routing {transportProfile.allow_private === true ? 'enabled' : 'disabled'}, deep tests {executionProfile.deep_tests === true ? 'enabled' : 'disabled'}, mutation tests {executionProfile.mutation_tests === true ? 'enabled' : 'disabled'}.</p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-base">Analyst-ready notes</CardTitle></CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <p>
                    {selected.name} tested {selected.endpoint} and recorded {selected.summary.exchanges || selected.exchanges.length} protocol exchanges. The run observed {selected.summary.tools || 0} tools,
                    {` ${selected.summary.resources || 0} resources, and ${selected.summary.prompts || 0} prompts.`}
                  </p>
                  <p>
                    Coverage outcomes: {selected.summary.test_coverage?.executed || 0} executed, {selected.summary.test_coverage?.failed || 0} failed, {selected.summary.test_coverage?.review || 0} review,
                    {` ${selected.summary.test_coverage?.blocked || 0} blocked, and ${selected.summary.test_coverage?.not_applicable || 0} not applicable.`}
                  </p>
                  {manualTests.length > 0 ? <p>Follow-up manual tests: {manualTests.join(' | ')}</p> : <p>No blocked checks required manual follow-up in this run.</p>}
                  <div className="flex flex-wrap gap-2 pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => downloadText(
                        `${selected.name.replace(/[^a-z0-9-_]+/gi, '-').toLowerCase()}-${selected.id}.md`,
                        [
                          `# ${selected.name}`,
                          '',
                          `- Endpoint: ${selected.endpoint}`,
                          `- Status: ${selected.status}`,
                          `- Severity: ${selected.overall_severity}`,
                          `- Risk score: ${selected.risk_score}`,
                          `- Exchanges: ${selected.summary.exchanges || selected.exchanges.length}`,
                          `- Tools: ${selected.summary.tools || 0}`,
                          `- Resources: ${selected.summary.resources || 0}`,
                          '',
                          '## Coverage',
                          `- Executed: ${selected.summary.test_coverage?.executed || 0}`,
                          `- Failed: ${selected.summary.test_coverage?.failed || 0}`,
                          `- Review: ${selected.summary.test_coverage?.review || 0}`,
                          `- Blocked: ${selected.summary.test_coverage?.blocked || 0}`,
                          `- Not applicable: ${selected.summary.test_coverage?.not_applicable || 0}`,
                          '',
                          '## Findings',
                          ...selected.findings.map((finding) => `- [${finding.severity}] ${finding.title}: ${finding.evidence}`),
                          '',
                          '## Manual follow-up',
                          ...(manualTests.length ? manualTests.map((item) => `- ${item}`) : ['- None']),
                        ].join('\n')
                      )}
                    >
                      <Download className="mr-2 h-4 w-4" />
                      Export Markdown report
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>}
      </div>
    </div>

    <Dialog open={Boolean(deleteRun)} onOpenChange={(open) => !open && setDeleteRun(null)}><DialogContent><DialogHeader><DialogTitle>Delete MCP assessment?</DialogTitle><DialogDescription>This permanently removes the run, findings, inventory, and captured exchanges. The remote MCP server is not changed.</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => setDeleteRun(null)}>Keep assessment</Button><Button variant="destructive" onClick={() => void confirmDelete()}>Delete assessment</Button></DialogFooter></DialogContent></Dialog>
  </div>
}
