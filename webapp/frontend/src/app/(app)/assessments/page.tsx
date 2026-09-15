'use client'

import { useCallback, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import axios from 'axios'
import { type ColumnDef } from '@tanstack/react-table'
import { Plus, MoreHorizontal, Play, Trash2, Eye, Upload, Square, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { DataTable, ArrowUpDown } from '@/components/shared/data-table'
import { StatusIndicator } from '@/components/shared/status-indicator'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useToast } from '@/components/ui/use-toast'
import { formatRelativeTime, getRiskScoreColor } from '@/lib/utils'
import { cancelAssessment, deleteAssessment, downloadReport, getAssessments, getReports, importAssessments, startScan } from '@/lib/api'
import type { Assessment, Report } from '@/lib/types'

function getErrorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    return error.response?.data?.detail || error.message || fallback
  }
  if (error instanceof Error) {
    return error.message
  }
  return fallback
}

function summarizeImportResult(added: number, skipped: number, errors: string[], successHint?: string) {
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
    title: 'Import ready',
    description: `Prepared ${added} targets, skipped ${skipped}${errors.length ? `, errors ${errors.length}` : ''}.${successHint ? ` ${successHint}` : ''}${errors.length ? ` First issues: ${firstErrors}${errors.length > 3 ? ` | +${errors.length - 3} more` : ''}` : ''}`,
    variant: errors.length ? 'destructive' as const : 'default' as const,
  }
}

const IMPORT_DRAFT_STORAGE_KEY = 'assessment-import-draft'

export default function AssessmentsPage() {
  const router = useRouter()
  const { toast } = useToast()
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [downloadingReport, setDownloadingReport] = useState<string | null>(null)

  const loadAssessments = useCallback(async () => {
    try {
      setError(null)
      const [res, reportItems] = await Promise.all([
        getAssessments({ page_size: 100 }),
        getReports().catch(() => [] as Report[]),
      ])
      setAssessments(res.items)
      setReports(reportItems)
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to load assessments')
      setError(message)
      toast({
        title: 'Could not load assessments',
        description: message,
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => {
    void loadAssessments()
  }, [loadAssessments])

  useEffect(() => {
    if (!assessments.some((assessment) => assessment.status === 'running')) return
    const timer = window.setInterval(() => void loadAssessments(), 5000)
    return () => window.clearInterval(timer)
  }, [assessments, loadAssessments])

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setImporting(true)
    try {
      const result = await importAssessments(file, {
        default_scan_mode: 'medium',
        default_auto_start: false,
      })
      if (typeof window !== 'undefined') {
        sessionStorage.setItem(
          IMPORT_DRAFT_STORAGE_KEY,
          JSON.stringify({
            importedTargets: result.imported_targets,
            suggestedName: result.suggested_name || file.name.replace(/\.[^.]+$/, ''),
            suggestedDescription: result.suggested_description || '',
          })
        )
      }
      toast(summarizeImportResult(
        result.added,
        result.skipped,
        result.errors,
        'Opening assessment setup with the normalized targets.'
      ))
      if (result.imported_targets.length > 0) {
        router.push('/assessments/new?import=1')
      }
    } catch (err) {
      toast({
        title: 'Import failed',
        description: getErrorMessage(err, 'Could not import assessment CSV'),
        variant: 'destructive',
      })
    } finally {
      event.target.value = ''
      setImporting(false)
    }
  }

  const handleDelete = async (assessment: Assessment) => {
    const confirmed = window.confirm(
      `Delete assessment "${assessment.name}" and all related findings, assets, and scans?`
    )
    if (!confirmed) return

    try {
      await deleteAssessment(assessment.id)
      setAssessments((current) => current.filter((item) => item.id !== assessment.id))
      toast({
        title: 'Assessment deleted',
        description: `${assessment.name} was removed successfully.`,
      })
    } catch (err) {
      toast({
        title: 'Delete failed',
        description: getErrorMessage(err, 'Could not delete assessment'),
        variant: 'destructive',
      })
    }
  }

  const handleRunScan = async (assessment: Assessment) => {
    try {
      const updated = await startScan(assessment.id)
      setAssessments((current) =>
        current.map((item) => (item.id === updated.id ? updated : item))
      )
      toast({
        title: 'Scan queued',
        description: `${assessment.name} was queued for scanning.`,
      })
    } catch (err) {
      toast({
        title: 'Could not start scan',
        description: getErrorMessage(err, 'Failed to queue assessment scan'),
        variant: 'destructive',
      })
    }
  }

  const handleCancelScan = async (assessment: Assessment) => {
    try {
      const updated = await cancelAssessment(assessment.id)
      setAssessments((current) =>
        current.map((item) => (item.id === updated.id ? updated : item))
      )
      toast({
        title: 'Cancel requested',
        description: `${assessment.name} is being stopped.`,
      })
    } catch (err) {
      toast({
        title: 'Could not cancel scan',
        description: getErrorMessage(err, 'Failed to cancel assessment scan'),
        variant: 'destructive',
      })
    }
  }

  const handleViewAssessment = (assessment: Assessment) => {
    router.push(`/assessments/${assessment.id}`)
  }

  const handleDownloadReport = async (report: Report) => {
    setDownloadingReport(report.id)
    try {
      await downloadReport(report)
    } catch (err) {
      toast({
        title: 'Download failed',
        description: getErrorMessage(err, 'Could not download the assessment report'),
        variant: 'destructive',
      })
    } finally {
      setDownloadingReport(null)
    }
  }

  const columns: ColumnDef<Assessment>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
          Name <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.getValue('name')}</p>
          <p className="text-xs text-muted-foreground">{row.original.target}</p>
        </div>
      ),
    },
    {
      accessorKey: 'target_type',
      header: 'Type',
      cell: ({ row }) => (
        <Badge variant="outline" className="text-xs capitalize">{row.getValue('target_type')}</Badge>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => {
        const status = row.getValue('status') as string
        const statusMap: Record<string, 'running' | 'idle' | 'error' | 'success' | 'pending'> = {
          created: 'pending',
          running: 'running',
          completed: 'success',
          partial: 'pending',
          failed: 'error',
          pending: 'pending',
          cancelled: 'idle',
        }
        return <StatusIndicator status={statusMap[status] || 'idle'} label={status} />
      },
    },
    {
      accessorKey: 'scan_mode',
      header: 'Mode',
      cell: ({ row }) => (
        <span className="text-sm capitalize">{row.getValue('scan_mode')}</span>
      ),
    },
    {
      accessorKey: 'risk_score',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')} className="px-0 hover:bg-transparent">
          Risk <ArrowUpDown className="ml-2 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ row }) => {
        const score = Number(row.getValue('risk_score'))
        return (
          <span className="font-mono text-sm font-semibold" style={{ color: getRiskScoreColor(score) }}>
            {score > 0 ? score.toFixed(1) : '--'}
          </span>
        )
      },
    },
    {
      accessorKey: 'created_at',
      header: 'Created',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatRelativeTime(row.getValue('created_at'))}
        </span>
      ),
    },
    {
      id: 'scan_action',
      header: 'Scan',
      cell: ({ row }) => {
        const assessment = row.original
        const formatOrder: Report['format'][] = ['docx', 'pdf', 'evidence']
        const formatLabels: Partial<Record<Report['format'], string>> = {
          docx: 'Word document (DOCX)',
          pdf: 'PDF document',
          evidence: 'Evidence bundle (ZIP)',
        }
        const assessmentReports = reports.filter((report) => report.assessment_id === assessment.id)
        const latestByFormat = new Map<Report['format'], Report>()
        for (const format of formatOrder) {
          const candidates = assessmentReports.filter((report) => report.format === format)
          const report = candidates.find((item) => item.scope?.automatic === true)
          if (report) latestByFormat.set(format, report)
        }
        const hasReports = latestByFormat.size > 0
        const hasGeneratingReport = [...latestByFormat.values()].some((report) => report.status === 'generating')
        const isDownloadingAssessment = assessmentReports.some((report) => report.id === downloadingReport)
        const reportButton = hasReports ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" className="h-8">
                <Download className="mr-2 h-3.5 w-3.5" />
                {isDownloadingAssessment ? 'Downloading' : hasGeneratingReport ? 'Preparing' : 'Reports'}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-56">
              <DropdownMenuLabel>Download latest report</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {formatOrder.map((format) => {
                const report = latestByFormat.get(format)
                const ready = report?.status === 'ready' && Boolean(report.download_url)
                const status = report?.status === 'generating' ? 'Preparing' : report?.status === 'failed' ? 'Failed' : 'Unavailable'
                return (
                  <DropdownMenuItem
                    key={format}
                    disabled={!ready || downloadingReport === report?.id}
                    onClick={() => ready && report && void handleDownloadReport(report)}
                  >
                    <Download className="mr-2 h-4 w-4" />
                    <span>{formatLabels[format]}</span>
                    {!ready && <span className="ml-auto text-xs text-muted-foreground">{status}</span>}
                  </DropdownMenuItem>
                )
              })}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null

        if (assessment.status === 'running') {
          return (
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                onClick={() => handleCancelScan(assessment)}
              >
                <Square className="mr-2 h-3.5 w-3.5" /> Stop
              </Button>
              {reportButton}
            </div>
          )
        }

        return (
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              className="h-8"
              onClick={() => handleRunScan(assessment)}
            >
              <Play className="mr-2 h-3.5 w-3.5" /> Start
            </Button>
            {reportButton}
          </div>
        )
      },
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
            <DropdownMenuItem onClick={() => handleViewAssessment(row.original)}>
              <Eye className="mr-2 h-4 w-4" /> View Details
            </DropdownMenuItem>
            {row.original.status === 'running' ? (
              <DropdownMenuItem onClick={() => handleCancelScan(row.original)}>
                <Square className="mr-2 h-4 w-4" /> Cancel Scan
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem onClick={() => handleRunScan(row.original)}>
                <Play className="mr-2 h-4 w-4" /> Run Scan
              </DropdownMenuItem>
            )}
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
      <PageHeader
        title="Assessments"
        description="Manage security assessments and scan configurations"
      >
        <div className="flex gap-2">
          <Button asChild variant="outline" disabled={importing}>
            <label className="cursor-pointer">
              <Upload className="mr-2 h-4 w-4" /> {importing ? 'Importing...' : 'Import CSV'}
              <input
                type="file"
                accept=".csv,text/csv"
                className="hidden"
                onChange={handleImport}
                disabled={importing}
              />
            </label>
          </Button>
          <Button onClick={() => router.push('/assessments/new')}>
            <Plus className="mr-2 h-4 w-4" /> New Assessment
          </Button>
        </div>
      </PageHeader>
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-6">
          <p className="font-medium text-destructive">Failed to load assessments</p>
          <p className="mt-1 text-sm text-muted-foreground">{error}</p>
          <Button className="mt-4" variant="outline" onClick={() => {
            setLoading(true)
            void loadAssessments()
          }}>
            Retry
          </Button>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={assessments}
          searchKey="name"
          searchPlaceholder="Search assessments..."
        />
      )}
    </div>
  )
}
