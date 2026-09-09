'use client'

import { useEffect, useState } from 'react'
import { FileText, Download, Plus, FileJson, Loader2, Trash2, GitCompare } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { PageHeader } from '@/components/shared/page-header'
import { formatDate, formatNumber } from '@/lib/utils'
import { cancelReport, compareScans, deleteReport, downloadReport, getAssessments, getAssets, getReports, getScans, generateReport } from '@/lib/api'
import type { Assessment, Asset, Report, Scan, ScanComparison } from '@/lib/types'
import { useToast } from '@/components/ui/use-toast'

export default function ReportsPage() {
  const [generating, setGenerating] = useState(false)
  const [selectedAssessment, setSelectedAssessment] = useState('')
  const [selectedFormat, setSelectedFormat] = useState('')
  const [selectedScan, setSelectedScan] = useState('all')
  const [baselineScan, setBaselineScan] = useState('none')
  const [scans, setScans] = useState<Scan[]>([])
  const [comparison, setComparison] = useState<ScanComparison | null>(null)
  const [assets, setAssets] = useState<Asset[]>([])
  const [selectedAsset, setSelectedAsset] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [findingStatus, setFindingStatus] = useState('all')
  const [owners, setOwners] = useState('')
  const [modules, setModules] = useState('')
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const { toast } = useToast()

  useEffect(() => {
    Promise.all([
      getAssessments({ page_size: 100 }),
      getReports().catch(() => []),
    ])
      .then(([assessRes, reportsData]) => {
        setAssessments(assessRes.items)
        setReports(Array.isArray(reportsData) ? reportsData : [])
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!reports.some((report) => report.status === 'generating')) return
    const timer = window.setInterval(() => {
      getReports().then((rows) => setReports(Array.isArray(rows) ? rows : [])).catch(() => undefined)
    }, 3000)
    return () => window.clearInterval(timer)
  }, [reports])

  useEffect(() => {
    setSelectedScan('all')
    setBaselineScan('none')
    setComparison(null)
    setSelectedAsset('all')
    if (!selectedAssessment) {
      setScans([])
      setAssets([])
      return
    }
    void Promise.all([getScans(selectedAssessment), getAssets({ assessment_id: selectedAssessment, page_size: 100 })])
      .then(([scanRows, assetRows]) => { setScans(scanRows); setAssets(assetRows.items) })
      .catch(() => { setScans([]); setAssets([]) })
  }, [selectedAssessment])

  const handleGenerate = async () => {
    if (!selectedAssessment || !selectedFormat) return
    setGenerating(true)
    try {
      const report = await generateReport({
        assessment_id: selectedAssessment,
        format: selectedFormat,
        scan_id: selectedScan === 'all' ? undefined : selectedScan,
        baseline_scan_id: baselineScan === 'none' ? undefined : baselineScan,
        asset_ids: selectedAsset === 'all' ? undefined : [selectedAsset],
        severities: severity === 'all' ? undefined : [severity],
        statuses: findingStatus === 'all' ? undefined : [findingStatus],
        owners: owners.split(',').map(item => item.trim()).filter(Boolean),
        modules: modules.split(',').map(item => item.trim()).filter(Boolean),
      })
      setReports((prev) => [report, ...prev])
    } catch (err) {
      toast({ title: 'Report generation failed', description: 'The report could not be generated. Check the selected assessment and try again.', variant: 'destructive' })
    } finally {
      setGenerating(false)
    }
  }

  const handleCompare = async () => {
    if (selectedScan === 'all' || baselineScan === 'none') return
    try {
      setComparison(await compareScans(selectedScan, baselineScan))
    } catch {
      toast({ title: 'Comparison failed', description: 'Select two completed scans from the same assessment.', variant: 'destructive' })
    }
  }

  const formatIcons: Record<string, React.ElementType> = {
    html: FileText,
    pdf: FileText,
    sarif: FileJson,
    markdown: FileText,
    csv: FileText,
    json: FileJson,
    evidence: FileJson,
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Reports" description="Generate and download assessment reports" />

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" /> Generate New Report
          </CardTitle>
          <CardDescription>Create a report from an existing assessment</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div className="space-y-2">
              <Label>Assessment</Label>
              <Select value={selectedAssessment} onValueChange={setSelectedAssessment} disabled={loading}>
                <SelectTrigger>
                  <SelectValue placeholder={loading ? 'Loading...' : 'Select assessment'} />
                </SelectTrigger>
                <SelectContent>
                  {assessments.map((a) => (
                    <SelectItem key={a.id} value={a.id}>{a.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2"><Label>Asset</Label><Select value={selectedAsset} onValueChange={setSelectedAsset} disabled={!selectedAssessment}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All assets</SelectItem>{assets.map(asset => <SelectItem key={asset.id} value={asset.id}>{asset.value}</SelectItem>)}</SelectContent></Select></div>
            <div className="space-y-2"><Label>Severity</Label><Select value={severity} onValueChange={setSeverity}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem>{['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(item => <SelectItem key={item} value={item}>{item}</SelectItem>)}</SelectContent></Select></div>
            <div className="space-y-2"><Label>Finding status</Label><Select value={findingStatus} onValueChange={setFindingStatus}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All statuses</SelectItem>{['new','confirmed','in_progress','remediated','false_positive','accepted_risk','suppressed'].map(item => <SelectItem key={item} value={item}>{item.replaceAll('_', ' ')}</SelectItem>)}</SelectContent></Select></div>
            <div className="space-y-2"><Label>Owners</Label><Input value={owners} onChange={event => setOwners(event.target.value)} placeholder="team-a, appsec" /></div>
            <div className="space-y-2"><Label>Modules / sources</Label><Input value={modules} onChange={event => setModules(event.target.value)} placeholder="nuclei, trivy" /></div>
            <div className="space-y-2">
              <Label>Current scan</Label>
              <Select value={selectedScan} onValueChange={setSelectedScan} disabled={!selectedAssessment}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All assessment findings</SelectItem>
                  {scans.map(scan => <SelectItem key={scan.id} value={scan.id}>{scan.status} - {scan.id.slice(0, 8)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Baseline</Label>
              <Select value={baselineScan} onValueChange={setBaselineScan} disabled={selectedScan === 'all'}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No comparison</SelectItem>
                  {scans.filter(scan => scan.id !== selectedScan).map(scan => <SelectItem key={scan.id} value={scan.id}>{scan.status} - {scan.id.slice(0, 8)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Format</Label>
              <Select value={selectedFormat} onValueChange={setSelectedFormat}>
                <SelectTrigger>
                  <SelectValue placeholder="Select format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="html">HTML Report</SelectItem>
                  <SelectItem value="pdf">PDF Report</SelectItem>
                  <SelectItem value="sarif">SARIF (for CI/CD)</SelectItem>
                  <SelectItem value="markdown">Markdown Report</SelectItem>
                  <SelectItem value="csv">CSV Findings</SelectItem>
                  <SelectItem value="json">JSON Evidence</SelectItem>
                  <SelectItem value="evidence">Evidence Bundle (ZIP)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end">
              <Button onClick={handleGenerate} disabled={!selectedAssessment || !selectedFormat || generating}>
                {generating ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Generating...</>
                ) : (
                  <><FileText className="mr-2 h-4 w-4" /> Generate Report</>
                )}
              </Button>
              {selectedScan !== 'all' && baselineScan !== 'none' && (
                <Button className="ml-2" variant="outline" onClick={handleCompare}>
                  <GitCompare className="mr-2 h-4 w-4" /> Compare
                </Button>
              )}
            </div>
          </div>
          {comparison && (
            <div className="mt-5 grid grid-cols-2 gap-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-4">
              <div><p className="text-xs text-muted-foreground">New</p><p className="text-xl font-semibold text-destructive">{comparison.summary.new}</p></div>
              <div><p className="text-xs text-muted-foreground">Resolved</p><p className="text-xl font-semibold text-emerald-600">{comparison.summary.resolved}</p></div>
              <div><p className="text-xs text-muted-foreground">Changed</p><p className="text-xl font-semibold text-amber-600">{comparison.summary.changed}</p></div>
              <div><p className="text-xs text-muted-foreground">Unchanged</p><p className="text-xl font-semibold">{comparison.summary.unchanged}</p></div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Generated Reports</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : reports.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No reports generated yet</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Report</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((report) => {
                  const Icon = formatIcons[report.format] || FileText
                  return (
                    <TableRow key={report.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm font-medium">{report.title}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] uppercase">{report.format}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={report.status === 'ready' ? 'success' : report.status === 'generating' ? 'default' : 'destructive'} className="text-[10px]">
                          {report.status}
                        </Badge>
                        {report.status === 'failed' && report.error ? <p className="mt-1 max-w-md text-xs text-destructive">{report.error}</p> : null}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatNumber(report.file_size)}B
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(report.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        {report.status === 'generating' ? <Button variant="ghost" size="sm" onClick={() => void cancelReport(report.id).then((updated) => setReports((current) => current.map((item) => item.id === updated.id ? updated : item)))}>Cancel</Button> : null}
                        <Button variant="ghost" size="sm" disabled={report.status !== 'ready'} asChild={report.status === 'ready'}>
                          {report.status === 'ready' && report.download_url ? (
                            <button onClick={() => void downloadReport(report).catch(() => toast({ title: 'Download failed', variant: 'destructive' }))}>
                              <Download className="mr-2 inline h-3.5 w-3.5" /> Download
                            </button>
                          ) : (
                            <span><Download className="mr-2 h-3.5 w-3.5" /> Download</span>
                          )}
                        </Button>
                        <Button className="ml-1" variant="ghost" size="icon" aria-label={`Delete ${report.title}`} onClick={() => {
                          if (!window.confirm(`Delete ${report.title}?`)) return
                          void deleteReport(report.id).then(() => setReports(current => current.filter(item => item.id !== report.id))).catch(() => toast({ title: 'Delete failed', variant: 'destructive' }))
                        }}><Trash2 className="h-3.5 w-3.5" /></Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
