'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/shared/page-header'
import { DataTable, ArrowUpDown } from '@/components/shared/data-table'
import { StatusIndicator } from '@/components/shared/status-indicator'
import { getAssets, getAssessments } from '@/lib/api'
import { formatRelativeTime, normalizeUuidParam } from '@/lib/utils'

interface AssetRow {
  id: string
  value: string
  type: string
  status: string
  first_seen: string
}

interface AssessmentOption {
  id: string
  name: string
}

const ALL = '__all__'

const columns: ColumnDef<AssetRow>[] = [
  {
    accessorKey: 'value',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
        Asset <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
      </Button>
    ),
    cell: ({ row }) => (
      <span className="font-mono text-sm font-medium text-primary">{row.getValue('value')}</span>
    ),
  },
  {
    accessorKey: 'type',
    header: 'Type',
    cell: ({ row }) => (
      <Badge variant="outline" className="text-xs capitalize">{row.getValue('type')}</Badge>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const status = row.getValue('status') as string
      return (
        <StatusIndicator
          status={status === 'live' ? 'success' : status === 'dead' ? 'error' : 'idle'}
          label={status}
        />
      )
    },
  },
  {
    accessorKey: 'first_seen',
    header: 'First Seen',
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground">
        {formatRelativeTime(row.getValue('first_seen'))}
      </span>
    ),
  },
]

export default function AssetsPage() {
  const [assets, setAssets] = useState<AssetRow[]>([])
  const [assessments, setAssessments] = useState<AssessmentOption[]>([])
  const [loading, setLoading] = useState(true)
  const [assetType, setAssetType] = useState(ALL)
  const [assetStatus, setAssetStatus] = useState(ALL)
  const [assessmentId, setAssessmentId] = useState(ALL)
  const [search, setSearch] = useState('')
  const [rootDomain, setRootDomain] = useState('')
  const [owner, setOwner] = useState('')
  const [ownershipStatus, setOwnershipStatus] = useState(ALL)
  const [error, setError] = useState<string | null>(null)
  const [filtersReady, setFiltersReady] = useState(false)
  const requestSequence = useRef(0)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    const scopedAssessmentId = params.get('assessment_id')
    const scopedSearch = params.get('search')
    const scopedType = params.get('type')
    const scopedStatus = params.get('status')

    const normalizedAssessmentId = normalizeUuidParam(scopedAssessmentId)

    if (normalizedAssessmentId) setAssessmentId(normalizedAssessmentId)
    if (scopedSearch) setSearch(scopedSearch)
    if (scopedType) setAssetType(scopedType)
    if (scopedStatus) setAssetStatus(scopedStatus)
    setFiltersReady(true)
  }, [])

  const loadAssets = useCallback(async () => {
    const requestId = requestSequence.current + 1
    requestSequence.current = requestId
    setLoading(true)
    try {
      const res = await getAssets({
        page_size: 100,
        type: assetType === ALL ? undefined : assetType,
        status: assetStatus === ALL ? undefined : assetStatus,
        assessment_id: assessmentId === ALL ? undefined : normalizeUuidParam(assessmentId),
        search: search.trim() || undefined,
        root_domain: rootDomain.trim() || undefined,
        owner: owner.trim() || undefined,
        ownership_status: ownershipStatus === ALL ? undefined : ownershipStatus,
      })
      const mapped = res.items.map((a: any) => ({
        id: a.id,
        value: a.value,
        type: a.asset_type || a.type || 'unknown',
        status: a.is_live === true ? 'live' : a.is_live === false ? 'dead' : (a.status || 'unknown'),
        first_seen: a.first_seen,
      }))
      if (requestSequence.current !== requestId) return
      setAssets(mapped)
      setError(null)
    } catch (err) {
      if (requestSequence.current !== requestId) return
      setError(err instanceof Error ? err.message : 'Could not load assets')
    } finally {
      if (requestSequence.current === requestId) setLoading(false)
    }
  }, [assetStatus, assetType, assessmentId, owner, ownershipStatus, rootDomain, search])

  useEffect(() => {
    getAssessments({ page_size: 100 })
      .then((res) => setAssessments(res.items.map((item) => ({ id: item.id, name: item.name }))))
      .catch(console.error)
  }, [])

  useEffect(() => {
    if (!filtersReady) return
    void loadAssets()
  }, [filtersReady, loadAssets])

  return (
    <div className="space-y-6">
      <PageHeader title="Assets" description="Discovered assets across all assessments" />

      <div className="rounded-xl border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Filters</p>
            <p className="text-xs text-muted-foreground">Slice the inventory by type, status, assessment, or direct asset search.</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setAssetType(ALL)
              setAssetStatus(ALL)
              setAssessmentId(ALL)
              setSearch('')
              setRootDomain('')
              setOwner('')
              setOwnershipStatus(ALL)
            }}
          >
            Clear
          </Button>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="space-y-2">
            <Label htmlFor="asset-search">Asset Search</Label>
            <Input id="asset-search" placeholder="Domain, IP, URL..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Type</Label>
            <Select value={assetType} onValueChange={setAssetType}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All types</SelectItem>
                <SelectItem value="domain">Domain</SelectItem>
                <SelectItem value="subdomain">Subdomain</SelectItem>
                <SelectItem value="ip">IP</SelectItem>
                <SelectItem value="url">URL</SelectItem>
                <SelectItem value="cidr">CIDR</SelectItem>
                <SelectItem value="cloud_resource">Cloud Resource</SelectItem>
                <SelectItem value="repository">Repository</SelectItem>
                <SelectItem value="cloud_account">Cloud Account</SelectItem>
                <SelectItem value="organization">Organization</SelectItem>
                <SelectItem value="asn">ASN</SelectItem>
                <SelectItem value="mcp">MCP Endpoint</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Status</Label>
            <Select value={assetStatus} onValueChange={setAssetStatus}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All statuses</SelectItem>
                <SelectItem value="live">Live</SelectItem>
                <SelectItem value="dead">Dead</SelectItem>
                <SelectItem value="unknown">Unknown</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Assessment</Label>
            <Select value={assessmentId} onValueChange={setAssessmentId}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All assessments</SelectItem>
                {assessments.map((item) => (
                  <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="root-domain">Root Domain</Label>
            <Input id="root-domain" placeholder="example.com" value={rootDomain} onChange={(e) => setRootDomain(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="asset-owner">Owner</Label>
            <Input id="asset-owner" placeholder="Team or business unit" value={owner} onChange={(e) => setOwner(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Ownership</Label>
            <Select value={ownershipStatus} onValueChange={setOwnershipStatus}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value={ALL}>All</SelectItem><SelectItem value="confirmed">Confirmed</SelectItem><SelectItem value="inferred">Inferred</SelectItem><SelectItem value="disputed">Disputed</SelectItem><SelectItem value="unattributed">Unattributed</SelectItem></SelectContent>
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
          data={assets}
          searchKey="value"
          searchPlaceholder="Search loaded assets..."
        />
      )}
    </div>
  )
}
