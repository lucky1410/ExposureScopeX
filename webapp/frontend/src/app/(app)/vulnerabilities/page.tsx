'use client'

import { useCallback, useEffect, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { AlertTriangle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/shared/page-header'
import { DataTable, ArrowUpDown } from '@/components/shared/data-table'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { getVulnerabilities } from '@/lib/api'
import type { Vulnerability } from '@/lib/types'

const ALL = '__all__'

const columns: ColumnDef<Vulnerability>[] = [
  {
    accessorKey: 'cve_id',
    header: 'CVE ID',
    cell: ({ row }) => (
      <span className="font-mono text-sm text-primary">{row.getValue('cve_id')}</span>
    ),
  },
  {
    accessorKey: 'title',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
        Title <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
      </Button>
    ),
    cell: ({ row }) => (
      <span className="text-sm font-medium">{row.getValue('title')}</span>
    ),
  },
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: ({ row }) => <SeverityBadge severity={row.getValue('severity')} />,
  },
  {
    accessorKey: 'cvss_score',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
        CVSS <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
      </Button>
    ),
    cell: ({ row }) => {
      const value = row.getValue('cvss_score') as number | null
      return <span className="font-mono text-sm font-semibold">{typeof value === 'number' ? value.toFixed(1) : '--'}</span>
    },
  },
  {
    accessorKey: 'is_kev',
    header: 'KEV',
    cell: ({ row }) => (
      row.getValue('is_kev') ? (
        <Badge variant="destructive" className="text-[10px] gap-1">
          <AlertTriangle className="h-3 w-3" /> KEV
        </Badge>
      ) : (
        <span className="text-xs text-muted-foreground">--</span>
      )
    ),
  },
  {
    accessorKey: 'affected_assets_count',
    header: 'Assets',
    cell: ({ row }) => <span className="text-sm">{row.getValue('affected_assets_count')}</span>,
  },
  {
    accessorKey: 'exploit_available',
    header: 'Exploit',
    cell: ({ row }) => (
      row.getValue('exploit_available') ? (
        <Badge variant="destructive" className="text-[10px]">Available</Badge>
      ) : (
        <span className="text-xs text-muted-foreground">--</span>
      )
    ),
  },
]

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState(ALL)
  const [kev, setKev] = useState<'all' | 'kev' | 'non_kev'>('all')
  const [exploit, setExploit] = useState<'all' | 'available' | 'unavailable'>('all')
  const [search, setSearch] = useState('')

  const loadVulnerabilities = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getVulnerabilities({
        page_size: 100,
        severity: severity === ALL ? undefined : severity,
        is_kev: kev === 'all' ? undefined : kev === 'kev',
        exploit_available: exploit === 'all' ? undefined : exploit === 'available',
        search: search.trim() || undefined,
      })
      setVulnerabilities(res.items)
    } finally {
      setLoading(false)
    }
  }, [exploit, kev, search, severity])

  useEffect(() => {
    void loadVulnerabilities()
  }, [loadVulnerabilities])

  return (
    <div className="space-y-6">
      <PageHeader title="Vulnerabilities" description="CVE tracking and vulnerability intelligence" />

      <div className="rounded-xl border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Filters</p>
            <p className="text-xs text-muted-foreground">Narrow vulnerability intelligence by severity, KEV presence, exploitability, or CVE/title search.</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setSeverity(ALL)
              setKev('all')
              setExploit('all')
              setSearch('')
            }}
          >
            Clear
          </Button>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="space-y-2">
            <Label htmlFor="vuln-search">Search</Label>
            <Input id="vuln-search" placeholder="CVE ID or title" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label>Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger><SelectValue /></SelectTrigger>
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
            <Label>KEV</Label>
            <Select value={kev} onValueChange={(value) => setKev(value as 'all' | 'kev' | 'non_kev')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All vulnerabilities</SelectItem>
                <SelectItem value="kev">Only KEV</SelectItem>
                <SelectItem value="non_kev">Only non-KEV</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Exploitability</Label>
            <Select value={exploit} onValueChange={(value) => setExploit(value as 'all' | 'available' | 'unavailable')}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All exploit states</SelectItem>
                <SelectItem value="available">Exploit available</SelectItem>
                <SelectItem value="unavailable">No known exploit</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={vulnerabilities}
          searchKey="cve_id"
          searchPlaceholder="Search loaded vulnerability rows..."
        />
      )}
    </div>
  )
}
