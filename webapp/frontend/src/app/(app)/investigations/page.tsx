'use client'

import { useCallback, useEffect, useState } from 'react'
import axios from 'axios'
import { useRouter } from 'next/navigation'
import { type ColumnDef } from '@tanstack/react-table'
import { Eye, MoreHorizontal, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { DataTable, ArrowUpDown } from '@/components/shared/data-table'
import { SeverityBadge } from '@/components/shared/severity-badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useToast } from '@/components/ui/use-toast'
import { formatRelativeTime } from '@/lib/utils'
import { deleteInvestigation, getInvestigations } from '@/lib/api'
import type { Investigation } from '@/lib/types'

export default function CasesPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const loadInvestigations = useCallback(async () => {
    try {
      setError(null)
      const data = await getInvestigations({ page_size: 100 })
      setInvestigations(data)
    } catch (err) {
      const message = axios.isAxiosError(err)
        ? err.response?.data?.detail || err.message
        : 'Failed to load investigations'
      setError(message)
      toast({
        title: 'Could not load cases',
        description: message,
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => {
    void loadInvestigations()
  }, [loadInvestigations])

  const handleDelete = async (investigation: Investigation) => {
    const confirmed = window.confirm(`Delete case "${investigation.title}"?`)
    if (!confirmed) return

    try {
      await deleteInvestigation(investigation.id)
      setInvestigations((current) => current.filter((item) => item.id !== investigation.id))
      toast({
        title: 'Case deleted',
        description: `${investigation.title} was removed successfully.`,
      })
    } catch (err) {
      toast({
        title: 'Could not delete case',
        description: axios.isAxiosError(err)
          ? err.response?.data?.detail || err.message
          : 'Delete failed',
        variant: 'destructive',
      })
    }
  }

  const columns: ColumnDef<Investigation>[] = [
    {
      accessorKey: 'title',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
          Title <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ row }) => <span className="font-medium text-sm">{row.getValue('title')}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const status = row.getValue('status') as string
        const variant = status === 'in_progress' ? 'default' : status === 'open' ? 'outline' : 'secondary'
        return <Badge variant={variant} className="text-[10px] capitalize">{status.replace('_', ' ')}</Badge>
      },
    },
    {
      accessorKey: 'priority',
      header: 'Priority',
      cell: ({ row }) => <SeverityBadge severity={row.getValue('priority')} />,
    },
    {
      accessorKey: 'findings_count',
      header: 'Findings',
      cell: ({ row }) => <span className="text-sm">{row.getValue('findings_count')}</span>,
    },
    {
      accessorKey: 'assignee',
      header: 'Assignee',
      cell: ({ row }) => {
        const assignee = row.getValue('assignee') as string | null
        return <span className="text-sm text-muted-foreground">{assignee || 'Unassigned'}</span>
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">{formatRelativeTime(row.getValue('created_at'))}</span>
      ),
    },
    {
      id: 'tags',
      header: 'Tags',
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1">
          {(row.original.tags || []).slice(0, 3).map((tag) => (
            <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>
          ))}
        </div>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => router.push(`/investigations/${row.original.id}`)}>
              <Eye className="mr-2 h-4 w-4" /> View Details
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive"
              onClick={() => handleDelete(row.original)}
            >
              <Trash2 className="mr-2 h-4 w-4" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title="Cases" description="Track and manage security case files across engagements">
        <Button>
          <Plus className="mr-2 h-4 w-4" /> New Case
        </Button>
      </PageHeader>
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-6">
          <p className="font-medium text-destructive">Failed to load cases</p>
          <p className="mt-1 text-sm text-muted-foreground">{error}</p>
          <Button
            className="mt-4"
            variant="outline"
            onClick={() => {
              setLoading(true)
              void loadInvestigations()
            }}
          >
            Retry
          </Button>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={investigations}
          searchKey="title"
          searchPlaceholder="Search cases..."
        />
      )}
    </div>
  )
}
