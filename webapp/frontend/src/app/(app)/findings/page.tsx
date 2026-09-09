'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { type ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { PageHeader } from '@/components/shared/page-header'
import { DataTable, ArrowUpDown } from '@/components/shared/data-table'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { getAssets, getAssessments, getFindings, getScanExecutions } from '@/lib/api'
import { formatRelativeTime, normalizeUuidParam, truncate } from '@/lib/utils'

interface FindingRow {
  id: string
  assessment_id: string
  severity: string
  title: string
  asset_id: string
  asset_value: string
  source: string
  status: string
  found_at: string
  url?: string | null
}

interface AssessmentOption {
  id: string
  name: string
}

interface ScanOption {
  id: string
  label: string
}

interface AssetOption {
  id: string
  value: string
}

const columns: ColumnDef<FindingRow>[] = [
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: ({ row }) => <SeverityBadge severity={row.getValue('severity')} />,
  },
  {
    accessorKey: 'title',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
        Title <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
      </Button>
    ),
    cell: ({ row }) => (
      <Link href={`/findings/${row.original.id}`} className="text-sm font-medium hover:text-primary hover:underline">{truncate(row.getValue('title'), 60)}</Link>
    ),
  },
  {
    accessorKey: 'asset_value',
    header: 'Asset',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-primary">{row.getValue('asset_value') || '--'}</span>
    ),
  },
  {
    accessorKey: 'source',
    header: 'Source',
    cell: ({ row }) => (
      <Badge variant="secondary" className="text-[10px]">{row.getValue('source') || 'unknown'}</Badge>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const status = row.getValue('status') as string
      const variants: Record<string, 'default' | 'secondary' | 'outline'> = {
        open: 'default',
        confirmed: 'default',
        false_positive: 'secondary',
        remediated: 'outline',
        accepted: 'outline',
      }
      return <Badge variant={variants[status] || 'outline'} className="text-[10px] capitalize">{status.replace('_', ' ')}</Badge>
    },
  },
  {
    accessorKey: 'found_at',
    header: 'Found',
    cell: ({ row }) => (
      <span className="text-xs text-muted-foreground">{formatRelativeTime(row.getValue('found_at'))}</span>
    ),
  },
]

const ALL = '__all__'

export default function FindingsPage() {
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [assessments, setAssessments] = useState<AssessmentOption[]>([])
  const [scans, setScans] = useState<ScanOption[]>([])
  const [assets, setAssets] = useState<AssetOption[]>([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState(ALL)
  const [status, setStatus] = useState(ALL)
  const [source, setSource] = useState(ALL)
  const [assessmentId, setAssessmentId] = useState(ALL)
  const [scanId, setScanId] = useState<string | undefined>(undefined)
  const [assetId, setAssetId] = useState<string | undefined>(undefined)
  const [assetQuery, setAssetQuery] = useState('')
  const [keyword, setKeyword] = useState('')
  const [urlFilter, setUrlFilter] = useState<'all' | 'with_url' | 'without_url'>('all')
  const [minRisk, setMinRisk] = useState('')
  const [minConfidence, setMinConfidence] = useState('')
  const [reachability, setReachability] = useState(ALL)
  const [exploitability, setExploitability] = useState(ALL)
  const [error, setError] = useState<string | null>(null)
  const [filtersReady, setFiltersReady] = useState(false)
  const [scanOptionsReady, setScanOptionsReady] = useState(false)
  const [assetOptionsReady, setAssetOptionsReady] = useState(false)
  const requestSequence = useRef(0)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    const scopedAssessmentId = params.get('assessment_id')
    const scopedScanId = params.get('scan_id')
    const scopedAssetId = params.get('asset_id')
    const scopedAssetQuery = params.get('asset_query')
    const scopedSeverity = params.get('severity')
    const scopedStatus = params.get('status')
    const scopedSource = params.get('source')
    const scopedSearch = params.get('search')
    const scopedHasUrl = params.get('has_url')

    const normalizedAssessmentId = normalizeUuidParam(scopedAssessmentId)
    const normalizedScanId = normalizeUuidParam(scopedScanId)
    const normalizedAssetId = normalizeUuidParam(scopedAssetId)

    if (normalizedAssessmentId) setAssessmentId(normalizedAssessmentId)
    if (normalizedScanId) setScanId(normalizedScanId)
    if (normalizedAssetId) setAssetId(normalizedAssetId)
    if (scopedAssetQuery) setAssetQuery(scopedAssetQuery)
    if (scopedSeverity) setSeverity(scopedSeverity)
    if (scopedStatus) setStatus(scopedStatus)
    if (scopedSource) setSource(scopedSource)
    if (scopedSearch) setKeyword(scopedSearch)
    if (scopedHasUrl === 'true') setUrlFilter('with_url')
    if (scopedHasUrl === 'false') setUrlFilter('without_url')
    setFiltersReady(true)
  }, [])

  const loadFindings = useCallback(async () => {
    const requestId = requestSequence.current + 1
    requestSequence.current = requestId
    setLoading(true)
    try {
      const res = await getFindings({
        page_size: 100,
        severity: severity === ALL ? undefined : severity,
        status: status === ALL ? undefined : status,
        source: source === ALL ? undefined : source,
        assessment_id: assessmentId === ALL ? undefined : normalizeUuidParam(assessmentId),
        scan_id: normalizeUuidParam(scanId),
        asset_id: normalizeUuidParam(assetId),
        asset_query: assetQuery.trim() || undefined,
        search: keyword.trim() || undefined,
        has_url: urlFilter === 'all' ? undefined : urlFilter === 'with_url',
        min_risk_score: minRisk ? Number(minRisk) : undefined,
        min_confidence: minConfidence ? Number(minConfidence) : undefined,
        reachability: reachability === ALL ? undefined : reachability,
        exploitability: exploitability === ALL ? undefined : exploitability,
      })
      const mapped = res.items.map((f) => ({
        id: f.id,
        assessment_id: f.assessment_id,
        severity: f.severity,
        title: f.title,
        asset_id: f.asset_id,
        asset_value: f.asset_value || '',
        source: f.source || '',
        status: f.status || 'open',
        found_at: f.first_seen || f.found_at || '',
        url: f.url,
      }))
      if (requestSequence.current !== requestId) return
      setFindings(mapped)
      setError(null)
    } catch (err) {
      if (requestSequence.current !== requestId) return
      setError(err instanceof Error ? err.message : 'Could not load findings')
    } finally {
      if (requestSequence.current === requestId) setLoading(false)
    }
  }, [assessmentId, assetId, assetQuery, exploitability, keyword, minConfidence, minRisk, reachability, scanId, severity, source, status, urlFilter])

  useEffect(() => {
    getAssessments({ page_size: 100 })
      .then((res) => setAssessments(res.items.map((item) => ({ id: item.id, name: item.name }))))
      .catch(console.error)
  }, [])

  useEffect(() => {
    const scopedAssessmentId = normalizeUuidParam(assessmentId)
    if (!scopedAssessmentId) {
      setScans([])
      setAssets([])
      setScanOptionsReady(true)
      setAssetOptionsReady(true)
      return
    }

    setScanOptionsReady(false)
    setAssetOptionsReady(false)

    getScanExecutions({ page_size: 100, assessment_id: scopedAssessmentId })
      .then((res) =>
        setScans(
          res.items.map((item) => ({
            id: item.id,
            label: `${item.status.toUpperCase()} · ${formatRelativeTime(item.started_at || item.completed_at || new Date().toISOString())}`,
          }))
        )
      )
      .catch(console.error)
      .finally(() => setScanOptionsReady(true))

    getAssets({ page_size: 100, assessment_id: scopedAssessmentId })
      .then((res) =>
        setAssets(
          res.items.map((item) => ({
            id: item.id,
            value: item.value,
          }))
        )
      )
      .catch(console.error)
      .finally(() => setAssetOptionsReady(true))
  }, [assessmentId])

  useEffect(() => {
    if (scanOptionsReady && scanId && !scans.some((item) => item.id === scanId)) {
      setScanId(undefined)
    }
  }, [scanId, scanOptionsReady, scans])

  useEffect(() => {
    if (assetOptionsReady && assetId && !assets.some((item) => item.id === assetId)) {
      setAssetId(undefined)
    }
  }, [assetId, assetOptionsReady, assets])

  useEffect(() => {
    if (!filtersReady) return
    void loadFindings()
  }, [filtersReady, loadFindings])

  const sourceOptions = useMemo(() => {
    return Array.from(new Set(findings.map((item) => item.source).filter(Boolean))).sort()
  }, [findings])

  const clearFilters = () => {
    setSeverity(ALL)
    setStatus(ALL)
    setSource(ALL)
    setAssessmentId(ALL)
    setScanId(undefined)
    setAssetId(undefined)
    setAssetQuery('')
    setKeyword('')
    setUrlFilter('all')
    setMinRisk('')
    setMinConfidence('')
    setReachability(ALL)
    setExploitability(ALL)
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Findings" description="All security findings across assessments" />

      <div className="rounded-xl border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Filters</p>
            <p className="text-xs text-muted-foreground">Narrow findings by asset, severity, workflow status, assessment, latest scan scope, source, and URL context.</p>
          </div>
          <Button variant="outline" size="sm" onClick={clearFilters}>Clear</Button>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="space-y-2">
            <Label htmlFor="finding-keyword">Keyword</Label>
            <Input id="finding-keyword" placeholder="Title or description" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="finding-asset">Asset</Label>
            <Input id="finding-asset" placeholder="Hostname, IP, URL..." value={assetQuery} onChange={(e) => setAssetQuery(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger><SelectValue placeholder="All severities" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All severities</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
                <SelectItem value="INFO">Info</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Status</Label>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger><SelectValue placeholder="All statuses" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All statuses</SelectItem>
                <SelectItem value="new">New</SelectItem>
                <SelectItem value="confirmed">Confirmed</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
                <SelectItem value="remediated">Remediated</SelectItem>
                <SelectItem value="suppressed">Suppressed</SelectItem>
                <SelectItem value="approved_exception">Approved Exception</SelectItem>
                <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                <SelectItem value="compensating_control">Compensating Control</SelectItem>
                <SelectItem value="not_exploitable">Not Exploitable</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Assessment</Label>
            <Select value={assessmentId} onValueChange={setAssessmentId}>
              <SelectTrigger><SelectValue placeholder="All assessments" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All assessments</SelectItem>
                {assessments.map((item) => (
                  <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Scan Scope</Label>
            <Select value={scanId || ALL} onValueChange={(value) => setScanId(value === ALL ? undefined : value)}>
              <SelectTrigger><SelectValue placeholder="All scans" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All scans</SelectItem>
                {scans.map((item) => (
                  <SelectItem key={item.id} value={item.id}>{item.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Asset Scope</Label>
            <Select value={assetId || ALL} onValueChange={(value) => setAssetId(value === ALL ? undefined : value)}>
              <SelectTrigger><SelectValue placeholder="All assets" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All assets</SelectItem>
                {assets.map((item) => (
                  <SelectItem key={item.id} value={item.id}>{item.value}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Source</Label>
            <Select value={source} onValueChange={setSource}>
              <SelectTrigger><SelectValue placeholder="All sources" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All sources</SelectItem>
                {sourceOptions.map((item) => (
                  <SelectItem key={item} value={item}>{item}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>URL Context</Label>
            <Select value={urlFilter} onValueChange={(value) => setUrlFilter(value as 'all' | 'with_url' | 'without_url')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All findings</SelectItem>
                <SelectItem value="with_url">Only with URL</SelectItem>
                <SelectItem value="without_url">Only without URL</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="finding-risk">Minimum Risk</Label>
            <Input id="finding-risk" type="number" min="0" max="100" placeholder="0-100" value={minRisk} onChange={(e) => setMinRisk(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="finding-confidence">Minimum Confidence</Label>
            <Input id="finding-confidence" type="number" min="0" max="100" placeholder="0-100" value={minConfidence} onChange={(e) => setMinConfidence(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Reachability</Label>
            <Select value={reachability} onValueChange={setReachability}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value={ALL}>All</SelectItem><SelectItem value="reachable">Reachable</SelectItem><SelectItem value="unreachable">Unreachable</SelectItem><SelectItem value="unknown">Unknown</SelectItem></SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Exploitability</Label>
            <Select value={exploitability} onValueChange={setExploitability}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value={ALL}>All</SelectItem><SelectItem value="confirmed">Confirmed</SelectItem><SelectItem value="likely">Likely</SelectItem><SelectItem value="not_exploitable">Not Exploitable</SelectItem><SelectItem value="unknown">Unknown</SelectItem></SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {error ? (
        <div className="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">{error}</div>
      ) : loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={findings}
          searchKey="title"
          searchPlaceholder="Search loaded findings..."
        />
      )}
    </div>
  )
}
