'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { ArrowRight, Boxes, Bug, ChevronDown, Clock3, Crosshair, Play, RefreshCw, Server, Square, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/shared/page-header'
import { StatusIndicator } from '@/components/shared/status-indicator'
import { cancelAssessment, createScanSchedule, deleteScanSchedule, getAssessment, getScanProfiles, getScanScheduleHistory, getScanSchedules, getScans, startScan, updateScanSchedule } from '@/lib/api'
import type { Assessment, Scan, ScanProfile, ScanSchedule, ScanScheduleRun, ToolPlanItem } from '@/lib/types'
import { formatRelativeTime, getRiskScoreColor } from '@/lib/utils'

function statusTone(status: string): 'running' | 'idle' | 'error' | 'success' | 'pending' {
  const statusMap: Record<string, 'running' | 'idle' | 'error' | 'success' | 'pending'> = {
    created: 'pending',
    running: 'running',
    completed: 'success',
    failed: 'error',
    pending: 'pending',
    cancelled: 'idle',
    queued: 'pending',
  }
  return statusMap[status] || 'idle'
}

export default function AssessmentDetailPage() {
  const params = useParams<{ id: string }>()
  const router = useRouter()
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [profiles, setProfiles] = useState<ScanProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [schedules, setSchedules] = useState<ScanSchedule[]>([])
  const [scheduleName, setScheduleName] = useState('Recurring assessment')
  const [scheduleInterval, setScheduleInterval] = useState(1440)
  const [scheduleTimezone, setScheduleTimezone] = useState(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [windowStart, setWindowStart] = useState('')
  const [windowEnd, setWindowEnd] = useState('')
  const [missedRunPolicy, setMissedRunPolicy] = useState<'run_once' | 'skip'>('run_once')
  const [scheduleBusy, setScheduleBusy] = useState<string | null>(null)
  const [scheduleError, setScheduleError] = useState<string | null>(null)
  const [expandedSchedule, setExpandedSchedule] = useState<string | null>(null)
  const [scheduleHistory, setScheduleHistory] = useState<Record<string, ScanScheduleRun[]>>({})

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    else setRefreshing(true)
    try {
      const [assessmentData, scanData] = await Promise.all([
        getAssessment(params.id),
        getScans(params.id).catch(() => []),
      ])
      setAssessment(assessmentData)
      setScans(scanData)
      const profileData = await getScanProfiles(assessmentData.target_type).catch(() => [])
      setProfiles(profileData)
      setSchedules(await getScanSchedules(params.id).catch(() => []))
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load assessment details')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [params.id])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    if (!assessment || assessment.status !== 'running') return
    const timer = window.setInterval(() => void load(true), 4000)
    return () => window.clearInterval(timer)
  }, [assessment, load])

  const latestScan = scans[0] || null
  const selectedProfile = assessment ? profiles.find((profile) => profile.mode === assessment.scan_mode) || null : null
  const toolPlan = useMemo(() => {
    const current = latestScan?.scan_metadata as { tool_plan?: ToolPlanItem[] } | undefined
    return current?.tool_plan || selectedProfile?.tool_plan || []
  }, [latestScan, selectedProfile])

  const handleRun = async () => {
    if (!assessment) return
    const updated = await startScan(assessment.id)
    setAssessment(updated)
    await load(true)
  }

  const handleCancel = async () => {
    if (!assessment) return
    const updated = await cancelAssessment(assessment.id)
    setAssessment(updated)
    await load(true)
  }

  const addSchedule = async () => {
    if (!assessment) return
    if (Boolean(windowStart) !== Boolean(windowEnd)) {
      setScheduleError('Choose both maintenance-window times, or leave both empty.')
      return
    }
    setScheduleBusy('create')
    try {
      const created = await createScanSchedule({
        assessment_id: assessment.id,
        name: scheduleName.trim(),
        timezone: scheduleTimezone.trim(),
        interval_minutes: scheduleInterval,
        window_start: windowStart || null,
        window_end: windowEnd || null,
        missed_run_policy: missedRunPolicy,
        overlap_policy: 'skip',
        is_active: true,
      })
      setSchedules((current) => [...current, created].sort((a, b) => a.next_run_at.localeCompare(b.next_run_at)))
      setScheduleError(null)
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Could not create the schedule')
    } finally {
      setScheduleBusy(null)
    }
  }

  const toggleScheduleHistory = async (scheduleId: string) => {
    if (expandedSchedule === scheduleId) {
      setExpandedSchedule(null)
      return
    }
    setExpandedSchedule(scheduleId)
    if (scheduleHistory[scheduleId]) return
    setScheduleBusy(`history-${scheduleId}`)
    try {
      const history = await getScanScheduleHistory(scheduleId)
      setScheduleHistory((current) => ({ ...current, [scheduleId]: history }))
      setScheduleError(null)
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Could not load schedule history')
    } finally {
      setScheduleBusy(null)
    }
  }

  const toggleSchedule = async (schedule: ScanSchedule) => {
    setScheduleBusy(schedule.id)
    try {
      const updated = await updateScanSchedule(schedule.id, { is_active: !schedule.is_active })
      setSchedules((current) => current.map((item) => item.id === updated.id ? updated : item))
      setScheduleError(null)
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Could not update the schedule')
    } finally {
      setScheduleBusy(null)
    }
  }

  const removeSchedule = async (schedule: ScanSchedule) => {
    setScheduleBusy(schedule.id)
    try {
      await deleteScanSchedule(schedule.id)
      setSchedules((current) => current.filter((item) => item.id !== schedule.id))
      setExpandedSchedule((current) => current === schedule.id ? null : current)
      setScheduleError(null)
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Could not delete the schedule')
    } finally {
      setScheduleBusy(null)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Assessment Workspace" description="Loading scope, execution state, and coverage." />
        <div className="flex items-center justify-center py-24">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      </div>
    )
  }

  if (error || !assessment) {
    return (
      <div className="space-y-6">
        <PageHeader title="Assessment Workspace" description="Assessment detail and execution workspace." />
        <Card className="border-destructive/30">
          <CardContent className="p-6">
            <p className="font-medium text-destructive">Could not load assessment</p>
            <p className="mt-2 text-sm text-muted-foreground">{error || 'This assessment may no longer exist.'}</p>
            <div className="mt-4 flex gap-2">
              <Button variant="outline" onClick={() => void load()}>
                <RefreshCw className="mr-2 h-4 w-4" /> Retry
              </Button>
              <Button variant="outline" onClick={() => router.push('/assessments')}>Back</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={assessment.name}
        description="Assessment scope, latest execution, normalized tool plan, and drill-down shortcuts."
      >
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => void load(true)} disabled={refreshing}>
            <RefreshCw className="mr-2 h-4 w-4" /> {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>
          {assessment.status === 'running' ? (
            <Button variant="destructive" onClick={() => void handleCancel()}>
              <Square className="mr-2 h-4 w-4" /> Stop
            </Button>
          ) : (
            <Button onClick={() => void handleRun()}>
              <Play className="mr-2 h-4 w-4" /> Start Scan
            </Button>
          )}
        </div>
      </PageHeader>

      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <Card className="border-border/60 bg-card/85">
          <CardContent className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="metric-kicker">Scope</p>
                <p className="mt-3 break-all font-mono text-sm text-muted-foreground">{assessment.target}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Badge variant="outline" className="capitalize">{assessment.target_type.replaceAll('_', ' ')}</Badge>
                  <Badge variant="outline" className="capitalize">{assessment.scan_mode}</Badge>
                </div>
              </div>
              <StatusIndicator status={statusTone(assessment.status)} label={assessment.status} />
            </div>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <p className="metric-kicker">Risk</p>
                <p className="mt-2 text-3xl font-semibold" style={{ color: getRiskScoreColor(Number(assessment.risk_score || 0)) }}>
                  {assessment.risk_score ? Number(assessment.risk_score).toFixed(1) : '--'}
                </p>
              </div>
              <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <p className="metric-kicker">Created</p>
                <p className="mt-2 text-sm font-medium">{formatRelativeTime(assessment.created_at)}</p>
              </div>
              <div className="rounded-2xl border border-border/60 bg-background/70 p-4">
                <p className="metric-kicker">Runs</p>
                <p className="mt-2 text-3xl font-semibold">{scans.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Latest execution</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {latestScan ? (
              <>
                <div className="flex items-center justify-between gap-3 text-sm">
                  <span className="capitalize text-muted-foreground">{(latestScan.current_phase || 'queued').replaceAll('_', ' ')}</span>
                  <span className="font-mono font-semibold">{latestScan.progress}%</span>
                </div>
                <Progress value={latestScan.progress} />
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-xl border border-border/60 bg-background/70 p-3">
                    <p className="text-xs text-muted-foreground">Started</p>
                    <p className="mt-1 text-sm">{latestScan.started_at ? new Date(latestScan.started_at).toLocaleString() : 'Not started'}</p>
                  </div>
                  <div className="rounded-xl border border-border/60 bg-background/70 p-3">
                    <p className="text-xs text-muted-foreground">Completed</p>
                    <p className="mt-1 text-sm">{latestScan.completed_at ? new Date(latestScan.completed_at).toLocaleString() : 'Still running'}</p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" asChild>
                    <Link href={`/scans?assessment_id=${assessment.id}`}>Open scan timeline</Link>
                  </Button>
                  <Button variant="outline" asChild>
                    <Link href={`/findings?assessment_id=${assessment.id}&scan_id=${latestScan.id}`}>Latest findings</Link>
                  </Button>
                </div>
              </>
            ) : (
              <div className="rounded-xl border border-dashed p-5 text-sm text-muted-foreground">
                No scan run has been recorded yet. Start the assessment to create the first tracked execution.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Normalized tool plan</CardTitle>
          </CardHeader>
          <CardContent>
            {toolPlan.length > 0 ? (
              <div className="grid gap-3 sm:grid-cols-2">
                {toolPlan.map((tool) => (
                  <div key={`${tool.tool_id}-${tool.role}`} className="rounded-2xl border border-border/60 bg-background/70 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold">{tool.name}</p>
                        <p className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">{tool.role.replaceAll('_', ' ')}</p>
                      </div>
                      <Badge variant={tool.required ? 'default' : 'secondary'}>
                        {tool.required ? 'required' : 'optional'}
                      </Badge>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge variant="outline">{tool.install_mode.replaceAll('_', ' ')}</Badge>
                      <Badge variant="outline">{tool.status.replaceAll('_', ' ')}</Badge>
                    </div>
                    <p className="mt-3 text-xs text-muted-foreground">{tool.outputs.join(' · ')}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-xl border border-dashed p-5 text-sm text-muted-foreground">
                Tool plan metadata will appear after the first normalized execution is prepared.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="border-border/60 bg-card/85">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Operator shortcuts</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Link href={`/assets?assessment_id=${assessment.id}`} className="flex items-center justify-between rounded-2xl border border-border/60 bg-background/70 p-4 transition-colors hover:border-primary/40">
              <div className="flex items-center gap-3">
                <Server className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-sm font-semibold">Assets</p>
                  <p className="text-xs text-muted-foreground">Inspect normalized scope and discovered infrastructure.</p>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
            </Link>
            <Link href={`/findings?assessment_id=${assessment.id}`} className="flex items-center justify-between rounded-2xl border border-border/60 bg-background/70 p-4 transition-colors hover:border-primary/40">
              <div className="flex items-center gap-3">
                <Bug className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-sm font-semibold">Findings</p>
                  <p className="text-xs text-muted-foreground">Review findings scoped to this assessment only.</p>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
            </Link>
            <Link href={`/attack-surface?assessment_id=${assessment.id}`} className="flex items-center justify-between rounded-2xl border border-border/60 bg-background/70 p-4 transition-colors hover:border-primary/40">
              <div className="flex items-center gap-3">
                <Boxes className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-sm font-semibold">Exposure graph</p>
                  <p className="text-xs text-muted-foreground">Trace relationships, drift, and attack-path context.</p>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
            </Link>
            <Link href={`/scans?assessment_id=${assessment.id}`} className="flex items-center justify-between rounded-2xl border border-border/60 bg-background/70 p-4 transition-colors hover:border-primary/40">
              <div className="flex items-center gap-3">
                <Crosshair className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-sm font-semibold">Execution details</p>
                  <p className="text-xs text-muted-foreground">See stage progress, commands, output, artifacts, and retries.</p>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
            </Link>
          </CardContent>
        </Card>
      </div>
      <Card className="border-border/60 bg-card/85">
        <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Clock3 className="h-4 w-4 text-primary" /> Recurring scans</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="space-y-2"><Label>Name</Label><Input value={scheduleName} onChange={(event) => setScheduleName(event.target.value)} /></div>
            <div className="space-y-2"><Label>Interval (minutes)</Label><Input type="number" min={15} value={scheduleInterval} onChange={(event) => setScheduleInterval(Number(event.target.value))} /></div>
            <div className="space-y-2"><Label>IANA timezone</Label><Input value={scheduleTimezone} onChange={(event) => setScheduleTimezone(event.target.value)} /></div>
            <div className="space-y-2"><Label>Missed run</Label><Select value={missedRunPolicy} onValueChange={(value) => setMissedRunPolicy(value as 'run_once' | 'skip')}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="run_once">Run once when available</SelectItem><SelectItem value="skip">Skip missed run</SelectItem></SelectContent></Select></div>
            <div className="space-y-2"><Label>Window start (optional)</Label><Input type="time" value={windowStart} onChange={(event) => setWindowStart(event.target.value)} /></div>
            <div className="space-y-2"><Label>Window end (optional)</Label><Input type="time" value={windowEnd} onChange={(event) => setWindowEnd(event.target.value)} /></div>
            <div className="flex items-end xl:col-span-2"><Button onClick={() => void addSchedule()} disabled={!scheduleName.trim() || !scheduleTimezone.trim() || scheduleInterval < 15 || scheduleBusy === 'create'}>{scheduleBusy === 'create' ? 'Adding...' : 'Add schedule'}</Button></div>
          </div>
          <p className="text-xs text-muted-foreground">Windows use the selected timezone. Overlapping runs are always skipped to protect targets and worker capacity.</p>
          {scheduleError && <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{scheduleError}</div>}
          <div className="grid gap-3 lg:grid-cols-2">
            {schedules.map((schedule) => <div key={schedule.id} className="rounded-xl border p-4"><div className="flex items-start justify-between gap-4"><div><p className="text-sm font-semibold">{schedule.name}</p><p className="mt-1 text-xs text-muted-foreground">Every {schedule.interval_minutes} minutes · next {new Date(schedule.next_run_at).toLocaleString()} · {schedule.timezone}</p><p className="mt-1 text-xs text-muted-foreground">{schedule.window_start && schedule.window_end ? `Window ${schedule.window_start}-${schedule.window_end}` : 'No maintenance window'} · missed runs {schedule.missed_run_policy === 'run_once' ? 'run once' : 'skip'}</p><Badge className="mt-2" variant={schedule.is_active ? 'success' : 'secondary'}>{schedule.last_status || (schedule.is_active ? 'scheduled' : 'paused')}</Badge></div><div className="flex gap-2"><Button size="sm" variant="outline" disabled={scheduleBusy === schedule.id} onClick={() => void toggleSchedule(schedule)}>{schedule.is_active ? 'Pause' : 'Resume'}</Button><Button size="icon" variant="ghost" aria-label={`Delete ${schedule.name}`} disabled={scheduleBusy === schedule.id} onClick={() => void removeSchedule(schedule)}><Trash2 className="h-4 w-4" /></Button></div></div><Button className="mt-3" size="sm" variant="ghost" onClick={() => void toggleScheduleHistory(schedule.id)}><ChevronDown className={`mr-2 h-4 w-4 transition-transform ${expandedSchedule === schedule.id ? 'rotate-180' : ''}`} />Run history</Button>{expandedSchedule === schedule.id && <div className="mt-2 space-y-2 border-t pt-3">{scheduleBusy === `history-${schedule.id}` ? <p className="text-xs text-muted-foreground">Loading history...</p> : (scheduleHistory[schedule.id]?.length || 0) > 0 ? scheduleHistory[schedule.id].map((run) => <div key={run.id} className="flex items-start justify-between gap-3 rounded-lg bg-background/70 p-3 text-xs"><div><p className="font-medium capitalize">{run.status.replaceAll('_', ' ')}</p><p className="mt-1 text-muted-foreground">{run.message || 'Scheduler completed this decision without additional detail.'}</p></div><div className="shrink-0 text-right text-muted-foreground"><p>{new Date(run.planned_at).toLocaleString()}</p>{run.scan_id && <Link className="mt-1 inline-block text-primary hover:underline" href={`/scans?scan_id=${run.scan_id}`}>Open scan</Link>}</div></div>) : <p className="text-xs text-muted-foreground">No scheduler decisions have been recorded yet.</p>}</div>}</div>)}
            {schedules.length === 0 && <div className="rounded-xl border border-dashed p-5 text-sm text-muted-foreground lg:col-span-2">No recurring scans configured. Add one above; the first run is scheduled after the selected interval.</div>}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
