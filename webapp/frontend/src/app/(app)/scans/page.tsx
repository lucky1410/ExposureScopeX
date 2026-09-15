'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { Activity, AlertTriangle, CheckCircle2, Clock3, Download, Eye, RefreshCw, RotateCcw, Square } from 'lucide-react'
import { PageHeader } from '@/components/shared/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { cancelAssessment, cloneScanRecoveryDraft, downloadReportArtifact, getScanExecution, getScanExecutions, retryScanExecution, retryScanIngestion } from '@/lib/api'
import type { ScanExecution } from '@/lib/types'
import { formatRelativeTime } from '@/lib/utils'

const ACTIVE_STATUSES = new Set(['pending', 'queued', 'running'])

type ExecutionStepStatus = 'completed' | 'running' | 'pending' | 'skipped' | 'warning' | 'failed' | 'cancelled' | 'timed_out' | 'not_run'
type ExecutionStep = {
  id: string
  label: string
  purpose: string
  tools: string[]
  progress: number
  planned: (phases: Record<string, boolean>, flags: Record<string, boolean>) => boolean
  warning?: RegExp
  commandTools?: string[]
}

type ToolRun = {
  id: string
  tool: string
  status: 'running' | 'completed' | 'failed' | 'timed_out'
  exit_code?: number | null
  started_at?: string | null
  completed_at?: string | null
  command?: string | null
  output_file?: string | null
  output_excerpt?: string | null
}

type PersistedExecutionStep = {
  id: string
  label: string
  planned: boolean
  status: ExecutionStepStatus
  progress: number
  attempts: number
  started_at?: string | null
  completed_at?: string | null
  message?: string | null
}

type SpecializedAdapter = {
  tool: string
  enabled?: boolean
  exit_code?: number
  artifacts?: string[]
}

type SpecializedSummary = {
  target_type?: string
  target?: string
  provider?: string
  image?: string
  registry?: string
  status?: string
  notes?: string[]
  adapters?: SpecializedAdapter[]
  artifacts?: string[]
}

type ScanTelemetry = {
  elapsed_seconds?: number
  eta_seconds?: number | null
  last_output_at?: string | null
  output_silence_seconds?: number
  output_stalled?: boolean
  stall_warning_seconds?: number
  artifact_bytes?: number
  quota_bytes?: number
  work_units?: { total: number; completed: number; successful?: number; exceptions?: number; target_count: number; planned_stages?: number }
}

type CoverageSummary = {
  planned?: number
  successful?: number
  exceptions?: number
  successful_percent?: number
  complete?: boolean
  status_counts?: Record<string, number>
}

type AutomaticReport = {
  id?: string
  status?: 'generating' | 'ready' | 'failed'
  format?: string
  filename?: string
  error?: string
}

type ExecutionPolicy = {
  queue?: string
  timeout_seconds?: number
  memory_mb?: number
  disk_mb?: number
  network_policy?: string
}

function durationLabel(seconds?: number | null) {
  if (seconds === null || seconds === undefined) return 'Calculating'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.ceil(seconds / 60)}m`
  return `${(seconds / 3600).toFixed(1)}h`
}

const EXECUTION_STEPS: ExecutionStep[] = [
  { id: 'passive_recon', label: 'Passive reconnaissance', purpose: 'Public-source hosts, DNS, archives, ownership, and exposure context.', tools: ['crt.sh', 'dig', 'WHOIS', 'Wayback'], progress: 8, planned: (p, f) => Boolean(p.enum || f.passive_only) },
  { id: 'enumeration', label: 'Asset enumeration', purpose: 'Discover subdomains, takeover candidates, and responsive web hosts.', tools: ['Subfinder', 'Assetfinder', 'Amass', 'Subjack', 'httpx'], commandTools: ['subfinder', 'assetfinder', 'amass', 'subjack', 'httpx'], progress: 15, planned: (p) => Boolean(p.enum), warning: /subfinder failed|assetfinder failed|amass failed|subjack reported errors|httpx probing failed/i },
  { id: 'dns_recon', label: 'DNS security', purpose: 'Records, DNSSEC, zone-transfer checks, and authoritative infrastructure.', tools: ['dig', 'dnsx'], progress: 25, planned: (p) => Boolean(p.enum || p.scan), warning: /dns recon.*failed|dnsx.*failed/i },
  { id: 'osint', label: 'OSINT enrichment', purpose: 'External intelligence, reputation, leaked-code, and ownership signals.', tools: ['Shodan', 'VirusTotal', 'GitHub', 'WHOIS'], progress: 32, planned: (_p, f) => !f.no_osint, warning: /shodan.*failed|virustotal.*failed|osint.*failed/i },
  { id: 'port_scan', label: 'Network and service scan', purpose: 'Open ports, service versions, scripts, and operating-system signals.', tools: ['Masscan', 'Naabu', 'Nmap'], commandTools: ['masscan', 'naabu', 'nmap'], progress: 40, planned: (p) => Boolean(p.scan), warning: /port scan.*failed|nmap.*failed|naabu.*failed|masscan.*failed/i },
  { id: 'ssl_tls', label: 'TLS, headers, and email', purpose: 'Certificates, protocol posture, HTTP headers, SPF, DKIM, and DMARC.', tools: ['OpenSSL', 'testssl.sh', 'curl', 'dig'], progress: 50, planned: (p) => Boolean(p.scan), warning: /ssl.*failed|testssl.*failed|header.*failed/i },
  { id: 'cloud', label: 'Cloud exposure', purpose: 'Public storage, cloud templates, and exposed orchestration services.', tools: ['Nuclei cloud', 'S3/GCS/Azure checks', 'Kubernetes checks'], progress: 57, planned: (p) => Boolean(p.cloud), warning: /cloud.*failed|bucket.*failed/i },
  { id: 'crawler', label: 'Web crawling', purpose: 'Routes, JavaScript, APIs, forms, admin pages, and interesting files.', tools: ['Katana', 'GAU', 'Waybackurls'], commandTools: ['katana', 'gau', 'waybackurls'], progress: 63, planned: (p, f) => Boolean(p.scan || f.crawl), warning: /crawler.*failed|katana.*failed|gau.*failed/i },
  { id: 'web_testing', label: 'Web security tests', purpose: 'Technology-aware, non-destructive web checks, content discovery, and parameter mapping.', tools: ['Nikto', 'ffuf', 'Arjun', 'Feroxbuster'], commandTools: ['nikto', 'ffuf', 'arjun', 'feroxbuster'], progress: 70, planned: (p) => Boolean(p.scan), warning: /web.*test.*failed|nikto.*failed|ffuf.*failed|arjun.*failed|feroxbuster.*failed/i },
  { id: 'api_security', label: 'API security', purpose: 'OpenAPI, GraphQL, JWT, metadata, and API endpoint exposure.', tools: ['OpenAPI probes', 'GraphQL probes', 'JWT checks'], progress: 76, planned: (p) => Boolean(p.scan), warning: /api security.*failed|no valid targets for api/i },
  { id: 'screenshots', label: 'Visual reconnaissance', purpose: 'Capture responsive applications for rapid interface review.', tools: ['Gowitness', 'EyeWitness'], commandTools: ['gowitness', 'eyewitness'], progress: 80, planned: (p, f) => Boolean(p.scan || f.screenshots), warning: /screenshot.*failed|gowitness.*failed|eyewitness.*failed/i },
  { id: 'nuclei', label: 'Vulnerability templates', purpose: 'Official and community checks for CVEs, exposures, and misconfiguration.', tools: ['Nuclei official', 'Community templates', 'Headless templates'], commandTools: ['nuclei'], progress: 85, planned: (p) => Boolean(p.scan), warning: /nuclei.*failed|tool 'nuclei' failed/i },
  { id: 'cve_correlation', label: 'CVE correlation', purpose: 'Correlate observed products and versions with known vulnerabilities.', tools: ['Local CVE matcher', 'NVD data'], progress: 90, planned: (p, f) => Boolean(p.scan || f.cve), warning: /cve.*failed/i },
  { id: 'reporting', label: 'Reporting', purpose: 'Produce human-readable and machine-readable assessment artifacts.', tools: ['Word (DOCX)', 'Markdown', 'SARIF', 'PDF when available'], progress: 95, planned: (p) => Boolean(p.report), warning: /report.*failed|pandoc.*failed/i },
  { id: 'ingesting_results', label: 'Platform ingestion', purpose: 'Normalize and attach assets, ports, and findings to this exact scan.', tools: ['Asset parser', 'Port parser', 'Finding parsers'], progress: 98, planned: () => true, warning: /ingestion failed/i },
]

function buildExecutionChecklist(scan: ScanExecution): Array<ExecutionStep & { status: ExecutionStepStatus; detail?: string }> {
  const metadata = (scan.scan_metadata || {}) as {
    profile?: { phases?: Record<string, boolean>; flags?: Record<string, boolean> }
    phases_requested?: Record<string, boolean>
    flags_requested?: Record<string, boolean>
    ingestion_result?: { assets_added?: number; ports_added?: number; findings_added?: number }
    tool_runs?: ToolRun[]
    execution_manifest?: PersistedExecutionStep[]
  }
  const phases = metadata.profile?.phases || metadata.phases_requested || {}
  const flags = metadata.profile?.flags || metadata.flags_requested || {}
  const log = scan.raw_log || ''
  const toolRuns = metadata.tool_runs || []

  if (metadata.execution_manifest?.length) {
    return metadata.execution_manifest.map((persisted) => {
      const definition = EXECUTION_STEPS.find((step) => step.id === persisted.id)
      return {
        id: persisted.id,
        label: persisted.label,
        purpose: definition?.purpose || persisted.message || 'Tracked execution stage.',
        tools: definition?.tools || [],
        progress: persisted.progress,
        planned: () => persisted.planned,
        status: persisted.status,
        detail: persisted.message || (persisted.attempts > 1 ? `${persisted.attempts} attempts` : undefined),
      }
    })
  }

  return EXECUTION_STEPS.map((step) => {
    const planned = step.planned(phases, flags)
    const matchingRuns = toolRuns.filter((run) => step.commandTools?.includes(run.tool))
    let status: ExecutionStepStatus = 'pending'
    if (!planned) status = 'skipped'
    else if (matchingRuns.some((run) => run.status === 'running')) status = 'running'
    else if (matchingRuns.some((run) => run.status === 'failed' || run.status === 'timed_out')) status = 'warning'
    else if (matchingRuns.length > 0 && matchingRuns.every((run) => run.status === 'completed')) status = 'completed'
    else if (scan.current_phase === step.id) status = scan.status === 'failed' ? 'failed' : 'running'
    else if (scan.status === 'failed' && scan.progress >= step.progress) status = 'failed'
    else if (scan.status === 'cancelled') status = 'cancelled'
    else if (scan.status === 'completed' || scan.status === 'partial') status = step.warning?.test(log) ? 'warning' : 'not_run'

    let detail: string | undefined
    if (step.id === 'ingesting_results' && metadata.ingestion_result) {
      const result = metadata.ingestion_result
      detail = `${result.assets_added || 0} assets, ${result.ports_added || 0} ports, ${result.findings_added || 0} findings added`
    } else if (status === 'warning') {
      const failedRuns = matchingRuns.filter((run) => run.status === 'failed' || run.status === 'timed_out')
      detail = failedRuns.length > 0
        ? `${failedRuns.length} utility run(s) failed or timed out; successful batches were retained.`
        : 'Completed with one or more tool warnings; review worker output.'
    }
    return { ...step, status, detail }
  })
}

const STEP_STATUS_STYLES: Record<ExecutionStepStatus, string> = {
  completed: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  running: 'border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400',
  pending: 'border-border bg-muted/40 text-muted-foreground',
  skipped: 'border-border bg-muted/20 text-muted-foreground',
  warning: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400',
  failed: 'border-destructive/30 bg-destructive/10 text-destructive',
  cancelled: 'border-destructive/30 bg-destructive/10 text-destructive',
  timed_out: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400',
  not_run: 'border-border bg-muted/20 text-muted-foreground',
}

function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (status === 'completed') return 'default'
  if (status === 'failed') return 'destructive'
  if (status === 'running' || status === 'queued' || status === 'partial') return 'secondary'
  return 'outline'
}

export default function ScansPage() {
  const { toast } = useToast()
  const [scans, setScans] = useState<ScanExecution[]>([])
  const [status, setStatus] = useState('all')
  const [mode, setMode] = useState('all')
  const [targetType, setTargetType] = useState('all')
  const [query, setQuery] = useState('')
  const [assessmentId, setAssessmentId] = useState<string | undefined>()
  const [selected, setSelected] = useState<ScanExecution | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get('assessment_id')
    setAssessmentId(id || undefined)
  }, [])

  const loadScans = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    try {
      const result = await getScanExecutions({
        page_size: 100,
        status: status === 'all' ? undefined : status,
        assessment_id: assessmentId,
      })
      setScans(result.items)
      setSelected((current) => {
        if (!current) return null
        const summary = result.items.find((item) => item.id === current.id)
        return summary ? { ...current, ...summary, raw_log: current.raw_log } : current
      })
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load scan executions')
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [assessmentId, status])

  useEffect(() => {
    void loadScans()
  }, [loadScans])

  useEffect(() => {
    if (!scans.some((scan) => ACTIVE_STATUSES.has(scan.status))) return
    const timer = window.setInterval(() => void loadScans(true), 3000)
    return () => window.clearInterval(timer)
  }, [loadScans, scans])

  const selectedReportMetadata = ((selected?.scan_metadata || {}) as {
    automatic_report?: AutomaticReport
    automatic_reports?: Record<string, AutomaticReport>
  })
  const selectedReportStatus = Object.values(selectedReportMetadata.automatic_reports || {}).some((report) => report.status === 'generating')
    ? 'generating'
    : selectedReportMetadata.automatic_report?.status
  const refreshSelectedId = selected && (ACTIVE_STATUSES.has(selected.status) || selectedReportStatus === 'generating') ? selected.id : null

  useEffect(() => {
    if (!refreshSelectedId) return
    const timer = window.setInterval(async () => {
      try {
        setSelected(await getScanExecution(refreshSelectedId))
      } catch {
        // The summary poll remains available if a detail refresh is missed.
      }
    }, 3000)
    return () => window.clearInterval(timer)
  }, [refreshSelectedId])

  const stopScan = async (scan: ScanExecution) => {
    try {
      await cancelAssessment(scan.assessment_id)
      toast({ title: 'Cancel requested', description: `${scan.assessment_name} is being stopped.` })
      await loadScans(true)
    } catch (err) {
      toast({
        title: 'Could not stop scan',
        description: err instanceof Error ? err.message : 'The scan could not be cancelled.',
        variant: 'destructive',
      })
    }
  }

  const showDetails = async (scan: ScanExecution) => {
    setSelected(scan)
    try {
      setSelected(await getScanExecution(scan.id))
    } catch {
      toast({ title: 'Worker output unavailable', description: 'Showing the latest scan summary instead.' })
    }
  }

  const retryScan = async (scan: ScanExecution) => {
    try {
      const retried = await retryScanExecution(scan.id)
      toast({ title: 'Retry queued', description: `Attempt ${retried.attempt || 2} is ready for the worker.` })
      setSelected(retried)
      await loadScans(true)
    } catch (err) {
      toast({ title: 'Could not retry scan', description: err instanceof Error ? err.message : 'Retry failed.', variant: 'destructive' })
    }
  }

  const recoverIngestion = async (scan: ScanExecution) => {
    try {
      await retryScanIngestion(scan.id)
      toast({ title: 'Results recovered', description: 'Retained artifacts were ingested without rerunning the target scan.' })
      await loadScans(true)
    } catch (err) {
      toast({ title: 'Could not recover results', description: err instanceof Error ? err.message : 'Ingestion retry failed.', variant: 'destructive' })
    }
  }

  const cloneRecovery = async (scan: ScanExecution) => {
    try {
      const draft = await cloneScanRecoveryDraft(scan.id)
      toast({ title: 'Recovery draft created', description: 'Scope and execution settings were copied without starting a scan.' })
      window.location.assign(`/assessments/${draft.id}`)
    } catch (err) {
      toast({ title: 'Could not create recovery draft', description: err instanceof Error ? err.message : 'Clone failed.', variant: 'destructive' })
    }
  }

  const activeCount = scans.filter((scan) => ACTIVE_STATUSES.has(scan.status)).length
  const completedCount = scans.filter((scan) => scan.status === 'completed').length
  const partialCount = scans.filter((scan) => scan.status === 'partial').length
  const failedCount = scans.filter((scan) => scan.status === 'failed').length
  const visibleScans = scans.filter((scan) => {
    const normalizedQuery = query.trim().toLowerCase()
    const matchesQuery = !normalizedQuery || `${scan.assessment_name} ${scan.target} ${scan.id}`.toLowerCase().includes(normalizedQuery)
    const matchesMode = mode === 'all' || scan.scan_mode === mode
    const matchesType = targetType === 'all' || scan.target_type === targetType
    return matchesQuery && matchesMode && matchesType
  })
  const selectedToolRuns = (selected?.tool_runs as ToolRun[] | undefined) || ((selected?.scan_metadata || {}) as { tool_runs?: ToolRun[] }).tool_runs || []
  const selectedEvents = selected?.events || []
  const selectedSpecializedSummary = ((selected?.scan_metadata || {}) as { specialized_summary?: SpecializedSummary }).specialized_summary
  const selectedArtifacts = selected?.artifacts || []
  const legacyArtifacts = ((selected?.scan_metadata || {}) as { artifacts?: string[] }).artifacts || []
  const selectedTelemetry = ((selected?.scan_metadata || {}) as { telemetry?: ScanTelemetry }).telemetry || {}
  const selectedCoverage = ((selected?.scan_metadata || {}) as { coverage?: CoverageSummary }).coverage || {}
  const selectedPolicy = ((selected?.scan_metadata || {}) as { execution_policy?: ExecutionPolicy }).execution_policy || {}
  const selectedAutomaticReports = ((selected?.scan_metadata || {}) as {
    automatic_report?: AutomaticReport
    automatic_reports?: Record<string, AutomaticReport>
  })
  const selectedAutomaticReport = selectedAutomaticReports.automatic_reports?.docx || selectedAutomaticReports.automatic_report
  const selectedAutomaticPdf = selectedAutomaticReports.automatic_reports?.pdf
  const selectedAutomaticEvidence = selectedAutomaticReports.automatic_reports?.evidence

  return (
    <div className="space-y-6">
      <PageHeader title="Scans" description="Live execution state, phase progress, worker output, failures, and assessment results.">
        <div className="flex items-center gap-2">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search assessment, target, or scan ID"
            className="h-10 w-64 rounded-md border bg-background px-3 text-sm"
          />
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="w-40"><SelectValue placeholder="Status" /></SelectTrigger>
            <SelectContent>
              {['all', 'queued', 'running', 'completed', 'partial', 'failed', 'cancelled'].map((value) => (
                <SelectItem key={value} value={value} className="capitalize">{value}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={mode} onValueChange={setMode}>
            <SelectTrigger className="w-36"><SelectValue placeholder="Mode" /></SelectTrigger>
            <SelectContent>
              {['all', 'light', 'medium', 'aggressive'].map((value) => (
                <SelectItem key={value} value={value} className="capitalize">{value}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={targetType} onValueChange={setTargetType}>
            <SelectTrigger className="w-44"><SelectValue placeholder="Target type" /></SelectTrigger>
            <SelectContent>
              {['all', 'domain', 'ip', 'cidr', 'url', 'api', 'file', 'asn', 'repository', 'image', 'kubernetes', 'android', 'ios', 'cloud_account', 'organization', 'mcp'].map((value) => (
                <SelectItem key={value} value={value} className="capitalize">{value.replaceAll('_', ' ')}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => void loadScans()}><RefreshCw className="mr-2 h-4 w-4" /> Refresh</Button>
        </div>
      </PageHeader>

      {assessmentId && (
        <div className="flex items-center justify-between rounded-xl border bg-muted/30 px-4 py-3 text-sm">
          <span>Showing execution history for one assessment.</span>
          <Button variant="ghost" size="sm" asChild><Link href="/scans">Clear assessment filter</Link></Button>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Card><CardContent className="flex items-center gap-3 p-5"><Activity className="h-5 w-5 text-blue-500" /><div><p className="text-2xl font-semibold">{activeCount}</p><p className="text-xs text-muted-foreground">Active / queued</p></div></CardContent></Card>
        <Card><CardContent className="flex items-center gap-3 p-5"><CheckCircle2 className="h-5 w-5 text-emerald-500" /><div><p className="text-2xl font-semibold">{completedCount}</p><p className="text-xs text-muted-foreground">Completed</p></div></CardContent></Card>
        <Card><CardContent className="flex items-center gap-3 p-5"><AlertTriangle className="h-5 w-5 text-amber-500" /><div><p className="text-2xl font-semibold">{partialCount}</p><p className="text-xs text-muted-foreground">Completed with gaps</p></div></CardContent></Card>
        <Card><CardContent className="flex items-center gap-3 p-5"><AlertTriangle className="h-5 w-5 text-red-500" /><div><p className="text-2xl font-semibold">{failedCount}</p><p className="text-xs text-muted-foreground">Failed</p></div></CardContent></Card>
      </div>

      {error ? (
        <Card className="border-destructive/40"><CardContent className="p-6 text-sm text-destructive">{error}</CardContent></Card>
      ) : loading ? (
        <Card><CardContent className="p-10 text-center text-sm text-muted-foreground">Loading scan executions...</CardContent></Card>
      ) : visibleScans.length === 0 ? (
        <Card><CardContent className="p-10 text-center"><Clock3 className="mx-auto mb-3 h-8 w-8 text-muted-foreground" /><p className="font-medium">No scans match this view</p><p className="mt-1 text-sm text-muted-foreground">Start an assessment to create a tracked scan execution.</p></CardContent></Card>
      ) : (
        <div className="space-y-3">
          {visibleScans.map((scan) => (
            <Card key={scan.id} className="overflow-hidden">
              <CardHeader className="pb-3">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div><CardTitle className="text-base">{scan.assessment_name}</CardTitle><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{scan.target}</p><p className="mt-1 text-[11px] text-muted-foreground">Attempt {scan.attempt || 1} · {scan.target_type.replaceAll('_', ' ')} · {scan.id.slice(0, 8)}</p></div>
                  <div className="flex flex-wrap items-center gap-2"><Badge variant="outline" className="capitalize">{scan.scan_mode}</Badge><Badge variant="outline" className="capitalize">{scan.target_type.replaceAll('_', ' ')}</Badge><Badge variant={statusVariant(scan.status)} className="capitalize">{scan.status}</Badge></div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="mb-2 flex items-center justify-between text-xs"><span className="capitalize text-muted-foreground">{(scan.current_phase || 'queued').replaceAll('_', ' ')}</span><span className="font-mono font-semibold">{Math.max(0, Math.min(100, scan.progress))}%</span></div>
                  <Progress value={Math.max(0, Math.min(100, scan.progress))} />
                </div>
                <div className="flex flex-col gap-3 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
                  <span>Started {scan.started_at ? formatRelativeTime(scan.started_at) : 'not yet'}</span>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" onClick={() => void showDetails(scan)}><Eye className="mr-2 h-3.5 w-3.5" />Details</Button>
                    <Button size="sm" variant="outline" asChild><Link href={`/assets?assessment_id=${scan.assessment_id}`}>Assets</Link></Button>
                    <Button size="sm" variant="outline" asChild><Link href={`/findings?assessment_id=${scan.assessment_id}&scan_id=${scan.id}`}>Findings</Link></Button>
                    <Button size="sm" variant="outline" asChild><Link href={`/assessments/${scan.assessment_id}`}>Assessment</Link></Button>
                    {ACTIVE_STATUSES.has(scan.status) && <Button size="sm" variant="destructive" onClick={() => void stopScan(scan)}><Square className="mr-2 h-3.5 w-3.5" />Stop</Button>}
                    {scan.status === 'failed' && /ingestion failed/i.test(scan.error_message || '') && <Button size="sm" variant="outline" onClick={() => void recoverIngestion(scan)}><RotateCcw className="mr-2 h-3.5 w-3.5" />Retry ingestion</Button>}
                    {(scan.status === 'partial' || scan.status === 'failed' || scan.status === 'cancelled') && <><Button size="sm" variant="outline" onClick={() => void cloneRecovery(scan)}>Clone & review</Button><Button size="sm" variant="outline" onClick={() => void retryScan(scan)}><RotateCcw className="mr-2 h-3.5 w-3.5" />Retry now</Button></>}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={Boolean(selected)} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-h-[85vh] max-w-4xl overflow-y-auto">
          {selected && (
            <>
              <DialogHeader><DialogTitle>{selected.assessment_name}</DialogTitle><DialogDescription>Scan {selected.id} · {selected.status} · {selected.progress}%</DialogDescription></DialogHeader>
              <div className="grid gap-3 text-sm sm:grid-cols-2">
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Current phase</p><p className="mt-1 capitalize">{(selected.current_phase || 'queued').replaceAll('_', ' ')}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Worker task</p><p className="mt-1 break-all font-mono text-xs">{selected.celery_task_id || 'Local fallback task'}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Started</p><p className="mt-1">{selected.started_at ? new Date(selected.started_at).toLocaleString() : 'Not started'}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Completed</p><p className="mt-1">{selected.completed_at ? new Date(selected.completed_at).toLocaleString() : 'Still running'}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Elapsed / ETA</p><p className="mt-1">{durationLabel(selectedTelemetry.elapsed_seconds)} / {durationLabel(selectedTelemetry.eta_seconds)}</p></div>
                <div className={`rounded-lg border p-3 ${selectedTelemetry.output_stalled ? 'border-amber-500/50 bg-amber-500/10' : ''}`}><p className="text-xs text-muted-foreground">Worker output</p><p className="mt-1">{selectedTelemetry.last_output_at ? `${durationLabel(selectedTelemetry.output_silence_seconds)} silent` : 'Waiting for first output'}</p>{selectedTelemetry.output_stalled && <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">No new output beyond the warning threshold. The active tool remains bounded by its timeout.</p>}</div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Execution queue</p><p className="mt-1 font-mono text-xs">{selectedPolicy.queue || 'legacy'}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Artifact usage</p><p className="mt-1">{((selectedTelemetry.artifact_bytes || 0) / 1024 / 1024).toFixed(1)} MiB / {selectedPolicy.disk_mb || 0} MiB</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Sandbox policy</p><p className="mt-1">{selectedPolicy.memory_mb || 0} MiB · {selectedPolicy.network_policy || 'authorized-egress'}</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Verified coverage</p><p className="mt-1">{selectedCoverage.successful ?? selectedTelemetry.work_units?.successful ?? 0} / {selectedCoverage.planned ?? selectedTelemetry.work_units?.total ?? 0} planned stages successful</p><p className="mt-1 text-xs text-muted-foreground">{selectedCoverage.exceptions ?? selectedTelemetry.work_units?.exceptions ?? 0} exception(s); processed work alone is not counted as success.</p></div>
                <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Automatic report and evidence package</p><p className="mt-1 capitalize">{selectedAutomaticReport?.status || selectedAutomaticPdf?.status || selectedAutomaticEvidence?.status || (ACTIVE_STATUSES.has(selected.status) ? 'Waiting for scan close' : 'Not generated')}</p><div className="mt-1 flex flex-wrap items-center gap-3">{selectedAutomaticReport?.status === 'ready' && selectedAutomaticReport.id && <button className="inline-flex items-center text-xs font-medium text-primary hover:underline" onClick={() => void downloadReportArtifact(selectedAutomaticReport.id!, selectedAutomaticReport.filename || `scan-report-${selected.id}.docx`)}><Download className="mr-1 h-3 w-3" />DOCX</button>}{selectedAutomaticPdf?.status === 'ready' && selectedAutomaticPdf.id && <button className="inline-flex items-center text-xs font-medium text-primary hover:underline" onClick={() => void downloadReportArtifact(selectedAutomaticPdf.id!, selectedAutomaticPdf.filename || `scan-report-${selected.id}.pdf`)}><Download className="mr-1 h-3 w-3" />PDF</button>}{selectedAutomaticEvidence?.status === 'ready' && selectedAutomaticEvidence.id && <button className="inline-flex items-center text-xs font-medium text-primary hover:underline" onClick={() => void downloadReportArtifact(selectedAutomaticEvidence.id!, selectedAutomaticEvidence.filename || `scan-evidence-${selected.id}.zip`)}><Download className="mr-1 h-3 w-3" />Evidence ZIP</button>}{(selectedAutomaticReport?.id || selectedAutomaticPdf?.id || selectedAutomaticEvidence?.id) && <Link className="text-xs font-medium text-primary hover:underline" href="/reports">Open in Reports</Link>}</div></div>
              </div>
              {selected.error_message && <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{selected.error_message}</div>}
              {selectedSpecializedSummary && (
                <div className="space-y-3">
                  <div>
                    <p className="mb-2 text-sm font-medium">Specialized summary</p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Target type</p><p className="mt-1 capitalize">{selectedSpecializedSummary.target_type?.replaceAll('_', ' ') || selected.target_type}</p></div>
                      <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Execution status</p><p className="mt-1 capitalize">{selectedSpecializedSummary.status?.replaceAll('_', ' ') || selected.status}</p></div>
                      {selectedSpecializedSummary.provider ? <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Cloud provider</p><p className="mt-1 uppercase">{selectedSpecializedSummary.provider}</p></div> : null}
                      {selectedSpecializedSummary.image ? <div className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">Image</p><p className="mt-1 break-all font-mono text-xs">{selectedSpecializedSummary.image}</p></div> : null}
                    </div>
                  </div>
                  {selectedSpecializedSummary.notes?.length ? (
                    <div className="rounded-lg border bg-muted/20 p-3 text-xs text-muted-foreground">
                      {selectedSpecializedSummary.notes.join(' ')}
                    </div>
                  ) : null}
                  {selectedSpecializedSummary.adapters?.length ? (
                    <div>
                      <p className="mb-2 text-sm font-medium">Adapter runs</p>
                      <div className="space-y-2">
                        {selectedSpecializedSummary.adapters.map((adapter) => (
                          <div key={`${adapter.tool}-${adapter.exit_code ?? 'na'}`} className="rounded-lg border p-3">
                            <div className="flex items-center justify-between gap-3">
                              <p className="font-mono text-xs">{adapter.tool}</p>
                              <Badge variant={adapter.exit_code === 0 ? 'default' : adapter.enabled === false ? 'outline' : 'secondary'}>
                                {adapter.enabled === false ? 'disabled' : adapter.exit_code === 0 ? 'completed' : `exit ${adapter.exit_code ?? 'n/a'}`}
                              </Badge>
                            </div>
                            {adapter.artifacts?.length ? <p className="mt-2 text-xs text-muted-foreground">{adapter.artifacts.join(' · ')}</p> : null}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
              {selectedToolRuns.length > 0 && (
                <div>
                  <p className="mb-2 text-sm font-medium">Utility activity</p>
                  <div className="overflow-hidden rounded-xl border">
                    {selectedToolRuns.map((run) => (
                      <details key={run.id} className="group border-b px-3 py-2 text-xs last:border-b-0">
                        <summary className="flex cursor-pointer list-none flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                          <span className="font-mono font-medium">{run.tool}</span>
                          <span className="flex items-center gap-3 text-muted-foreground">
                            <span>{run.started_at ? new Date(run.started_at).toLocaleString() : 'Not started'}</span>
                            <span className={`rounded-full border px-2 py-0.5 uppercase ${STEP_STATUS_STYLES[run.status]}`}>{run.status.replace('_', ' ')}</span>
                          </span>
                        </summary>
                        <div className="mt-3 space-y-2">
                          <div><p className="mb-1 font-medium text-muted-foreground">Command</p><pre className="overflow-x-auto whitespace-pre-wrap rounded-lg bg-slate-950 p-3 font-mono text-slate-200">{run.command || 'Command telemetry was not captured for this older run.'}</pre></div>
                          <div><p className="mb-1 font-medium text-muted-foreground">Output</p><pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-950 p-3 font-mono text-slate-200">{run.output_excerpt || 'No output excerpt was captured. The tool may write directly to an artifact file.'}</pre></div>
                        </div>
                      </details>
                    ))}
                  </div>
                </div>
              )}
              {selectedEvents.length > 0 && (
                <div>
                  <p className="mb-2 text-sm font-medium">Execution timeline</p>
                  <div className="max-h-72 space-y-2 overflow-auto rounded-xl border p-3">
                    {selectedEvents.map(event => <div key={event.id} className="flex gap-3 text-xs"><span className="w-36 shrink-0 text-muted-foreground">{new Date(event.created_at).toLocaleString()}</span><span className="font-medium capitalize">{(event.phase || event.event_type).replaceAll('_', ' ')}</span><span className="ml-auto text-muted-foreground">{event.progress ?? 0}%</span></div>)}
                  </div>
                </div>
              )}
              <div>
                <div className="mb-3 flex items-center justify-between gap-3">
                  <div><p className="text-sm font-medium">Execution checklist</p><p className="text-xs text-muted-foreground">Planned coverage, tools used, completed work, warnings, and pending stages.</p></div>
                  <Badge variant="outline">{buildExecutionChecklist(selected).filter((step) => step.status === 'completed' || step.status === 'warning').length} / {buildExecutionChecklist(selected).filter((step) => step.status !== 'skipped').length} performed</Badge>
                </div>
                <div className="space-y-2">
                  {buildExecutionChecklist(selected).map((step) => (
                    <div key={step.id} className="rounded-xl border p-3">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                        <div><p className="text-sm font-medium">{step.label}</p><p className="mt-0.5 text-xs text-muted-foreground">{step.purpose}</p></div>
                        <span className={`w-fit rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${STEP_STATUS_STYLES[step.status]}`}>{step.status}</span>
                      </div>
                      <p className="mt-2 text-xs text-muted-foreground"><span className="font-medium text-foreground">Tools:</span> {step.tools.join(' · ')}</p>
                      {step.detail && <p className="mt-1 text-xs text-muted-foreground">{step.detail}</p>}
                    </div>
                  ))}
                </div>
              </div>
              <div><p className="mb-2 text-sm font-medium">Recent worker output</p><pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-200">{selected.raw_log || 'Worker output will appear when execution begins.'}</pre></div>
              {(selectedArtifacts.length > 0 || legacyArtifacts.length > 0) && (
                <div>
                  <p className="mb-2 text-sm font-medium">Verified artifacts</p>
                  <div className="space-y-2 rounded-xl border bg-muted/20 p-3 text-xs">
                    {selectedArtifacts.map((artifact) => <div key={artifact.id} className="flex flex-col gap-1 rounded-lg border bg-background p-2 sm:flex-row sm:items-center sm:justify-between"><span className="break-all font-mono">{artifact.path}</span><span className="shrink-0 text-muted-foreground">{artifact.artifact_type.replaceAll('_', ' ')} · {(artifact.size_bytes / 1024).toFixed(1)} KiB · sha256 {artifact.sha256.slice(0, 12)}</span></div>)}
                    {legacyArtifacts.map((artifact) => <div key={artifact} className="break-all font-mono text-muted-foreground">{artifact}</div>)}
                  </div>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
