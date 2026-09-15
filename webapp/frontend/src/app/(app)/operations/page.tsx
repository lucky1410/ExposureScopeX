'use client'

import { useEffect, useState } from 'react'
import axios from 'axios'
import { Archive, CheckCircle2, CircleStop, Flag, Pause, Play, Plus, ShieldCheck, Target, Users } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/use-toast'
import { createOperationWorkspace, getOperationWorkspaces, transitionOperationWorkspace, updateOperationWorkspace } from '@/lib/api'
import type { OperationTransitionAction, OperationWorkspace, OperationWorkspaceCreateRequest } from '@/lib/types'

const statusStyles: Record<OperationWorkspace['status'], 'default' | 'secondary' | 'outline' | 'destructive'> = {
  planning: 'secondary',
  approved: 'outline',
  active: 'default',
  paused: 'outline',
  completed: 'secondary',
  stopped: 'destructive',
  archived: 'outline',
}

const actionConfig: Partial<Record<OperationWorkspace['status'], Array<{ action: OperationTransitionAction; label: string }>>> = {
  planning: [{ action: 'approve', label: 'Approve' }],
  approved: [{ action: 'activate', label: 'Activate' }, { action: 'emergency_stop', label: 'Stop' }],
  active: [{ action: 'pause', label: 'Pause' }, { action: 'complete', label: 'Complete' }, { action: 'emergency_stop', label: 'Emergency Stop' }],
  paused: [{ action: 'resume', label: 'Resume' }, { action: 'complete', label: 'Complete' }, { action: 'emergency_stop', label: 'Emergency Stop' }],
  completed: [{ action: 'archive', label: 'Archive' }],
  stopped: [{ action: 'archive', label: 'Archive' }],
}

function actionIcon(action: OperationTransitionAction) {
  if (action === 'activate' || action === 'resume') return Play
  if (action === 'pause') return Pause
  if (action === 'complete' || action === 'approve') return CheckCircle2
  if (action === 'archive') return Archive
  return CircleStop
}

const defaultForm = {
  name: '',
  codename: '',
  description: '',
  objective: '',
  status: 'planning' as OperationWorkspace['status'],
  classification: 'internal' as OperationWorkspace['classification'],
  operation_type: 'red_team' as OperationWorkspace['operation_type'],
  planned_start_at: '',
  planned_end_at: '',
  scope_summary: '',
  roe_summary: '',
  tags: '',
}

export default function OperationsPage() {
  const { toast } = useToast()
  const [operations, setOperations] = useState<OperationWorkspace[]>([])
  const [form, setForm] = useState(defaultForm)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [transitioning, setTransitioning] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      setOperations(await getOperationWorkspaces())
      setError('')
    } catch (reason) {
      const detail = (reason as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || 'Operation workspaces are temporarily unavailable.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const counters = {
    total: operations.length,
    active: operations.filter((item) => item.status === 'active').length,
    planning: operations.filter((item) => item.status === 'planning' || item.status === 'approved').length,
    purple: operations.filter((item) => item.operation_type === 'purple_team').length,
  }

  const handleCreate = async () => {
    const payload: OperationWorkspaceCreateRequest = {
      name: form.name,
      codename: form.codename || undefined,
      description: form.description || undefined,
      objective: form.objective,
      status: form.status,
      classification: form.classification,
      operation_type: form.operation_type,
      planned_start_at: form.planned_start_at ? new Date(form.planned_start_at).toISOString() : null,
      planned_end_at: form.planned_end_at ? new Date(form.planned_end_at).toISOString() : null,
      scope_summary: form.scope_summary || undefined,
      roe_summary: form.roe_summary || undefined,
      tags: form.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
    }

    setSaving(true)
    try {
      const saved = editingId
        ? await updateOperationWorkspace(editingId, payload)
        : await createOperationWorkspace(payload)
      setOperations((current) => editingId
        ? current.map((item) => item.id === saved.id ? saved : item)
        : [saved, ...current])
      setDialogOpen(false)
      setEditingId(null)
      setForm(defaultForm)
      toast({
        title: editingId ? 'Operation updated' : 'Operation created',
        description: `${saved.name} is ready for scope, approvals, and execution planning.`,
      })
    } catch (reason) {
      const detail = axios.isAxiosError(reason) ? reason.response?.data?.detail || reason.message : 'Could not create operation'
      toast({
        title: 'Create failed',
        description: detail,
        variant: 'destructive',
      })
    } finally {
      setSaving(false)
    }
  }

  const editOperation = (operation: OperationWorkspace) => {
    const localDate = (value: string | null) => {
      if (!value) return ''
      const date = new Date(value)
      return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
    }
    setEditingId(operation.id)
    setForm({
      name: operation.name,
      codename: operation.codename || '',
      description: operation.description || '',
      objective: operation.objective,
      status: 'planning',
      classification: operation.classification,
      operation_type: operation.operation_type,
      planned_start_at: localDate(operation.planned_start_at),
      planned_end_at: localDate(operation.planned_end_at),
      scope_summary: operation.scope_summary || '',
      roe_summary: operation.roe_summary || '',
      tags: operation.tags.join(', '),
    })
    setDialogOpen(true)
  }

  const handleTransition = async (operation: OperationWorkspace, action: OperationTransitionAction) => {
    let reason: string | undefined
    if (action === 'emergency_stop') {
      reason = window.prompt('Emergency stop reason. This will cancel every active scan linked to this operation.')?.trim()
      if (!reason) return
    }
    setTransitioning(operation.id)
    try {
      const updated = await transitionOperationWorkspace(operation.id, action, reason)
      setOperations((current) => current.map((item) => item.id === updated.id ? updated : item))
      toast({ title: `Operation ${updated.status}`, description: `${updated.name} is now ${updated.status}.` })
    } catch (reason) {
      const detail = axios.isAxiosError(reason) ? reason.response?.data?.detail || reason.message : 'Could not update operation'
      toast({ title: 'Transition blocked', description: detail, variant: 'destructive' })
    } finally {
      setTransitioning(null)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operations"
        description="Plan red-team and purple-team engagements before they become scans, tasks, findings, or reports."
      >
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => { setEditingId(null); setForm(defaultForm) }}><Plus className="mr-2 h-4 w-4" />New Operation</Button>
          </DialogTrigger>
          <DialogContent className="max-w-3xl">
            <DialogHeader>
              <DialogTitle>{editingId ? 'Edit Operation Workspace' : 'Create Operation Workspace'}</DialogTitle>
              <DialogDescription>
                Capture the objective, scope, and rules of engagement now. We can attach assessments, tasks, timelines, and ATT&CK coverage next.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="operation-name">Name</Label>
                <Input id="operation-name" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} placeholder="Q4 Identity Adversary Exercise" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="operation-codename">Codename</Label>
                <Input id="operation-codename" value={form.codename} onChange={(event) => setForm((current) => ({ ...current, codename: event.target.value }))} placeholder="granite-owl" />
              </div>
              <div className="space-y-2">
                <Label>Operation Type</Label>
                <Select value={form.operation_type} onValueChange={(value: OperationWorkspace['operation_type']) => setForm((current) => ({ ...current, operation_type: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="red_team">Red Team</SelectItem>
                    <SelectItem value="adversary_emulation">Adversary Emulation</SelectItem>
                    <SelectItem value="purple_team">Purple Team</SelectItem>
                    <SelectItem value="tabletop">Tabletop</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Classification</Label>
                <Select value={form.classification} onValueChange={(value: OperationWorkspace['classification']) => setForm((current) => ({ ...current, classification: value }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="internal">Internal</SelectItem>
                    <SelectItem value="confidential">Confidential</SelectItem>
                    <SelectItem value="restricted">Restricted</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="operation-tags">Tags</Label>
                <Input id="operation-tags" value={form.tags} onChange={(event) => setForm((current) => ({ ...current, tags: event.target.value }))} placeholder="identity, cloud, finance" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="operation-start">Planned Start</Label>
                <Input id="operation-start" type="datetime-local" value={form.planned_start_at} onChange={(event) => setForm((current) => ({ ...current, planned_start_at: event.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="operation-end">Planned End</Label>
                <Input id="operation-end" type="datetime-local" value={form.planned_end_at} onChange={(event) => setForm((current) => ({ ...current, planned_end_at: event.target.value }))} />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="operation-objective">Objective</Label>
              <Textarea id="operation-objective" value={form.objective} onChange={(event) => setForm((current) => ({ ...current, objective: event.target.value }))} placeholder="Validate identity compromise paths, cloud pivoting, and SOC detection quality without disrupting production." />
            </div>
            <div className="space-y-2">
              <Label htmlFor="operation-description">Description</Label>
              <Textarea id="operation-description" value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} placeholder="Business context, operational narrative, and any notable constraints." />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="operation-scope">Scope Summary</Label>
                <Textarea id="operation-scope" value={form.scope_summary} onChange={(event) => setForm((current) => ({ ...current, scope_summary: event.target.value }))} placeholder="In-scope tenants, domains, identities, labs, cloud accounts, and prohibited areas." />
              </div>
              <div className="space-y-2">
                <Label htmlFor="operation-roe">ROE Summary</Label>
                <Textarea id="operation-roe" value={form.roe_summary} onChange={(event) => setForm((current) => ({ ...current, roe_summary: event.target.value }))} placeholder="Allowed techniques, communication windows, safeguards, and escalation paths." />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={saving}>Cancel</Button>
              <Button onClick={() => void handleCreate()} disabled={saving}>{saving ? 'Saving...' : editingId ? 'Save Changes' : 'Create Operation'}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </PageHeader>
      {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">{error}</div>}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Card><CardContent className="p-5"><Flag className="h-5 w-5 text-primary" /><p className="mt-3 text-2xl font-semibold">{counters.total}</p><p className="text-xs text-muted-foreground">Total operations</p></CardContent></Card>
        <Card><CardContent className="p-5"><Target className="h-5 w-5 text-sky-500" /><p className="mt-3 text-2xl font-semibold">{counters.active}</p><p className="text-xs text-muted-foreground">Active operations</p></CardContent></Card>
        <Card><CardContent className="p-5"><ShieldCheck className="h-5 w-5 text-amber-500" /><p className="mt-3 text-2xl font-semibold">{counters.planning}</p><p className="text-xs text-muted-foreground">Planning & approved</p></CardContent></Card>
        <Card><CardContent className="p-5"><Users className="h-5 w-5 text-emerald-500" /><p className="mt-3 text-2xl font-semibold">{counters.purple}</p><p className="text-xs text-muted-foreground">Purple-team tracks</p></CardContent></Card>
        <Card><CardContent className="p-5"><Target className="h-5 w-5 text-cyan-500" /><p className="mt-3 text-sm font-semibold">Scope -&gt; Execute -&gt; Validate</p><p className="text-xs text-muted-foreground">Platform lifecycle</p></CardContent></Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Operation Workspaces</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && <p className="text-sm text-muted-foreground">Loading operation workspaces...</p>}
          {!loading && operations.length === 0 && (
            <div className="rounded-xl border border-dashed p-6 text-sm text-muted-foreground">
              No operations yet. Create the first workspace to anchor objectives, scope, approvals, and future task execution.
            </div>
          )}
          {operations.map((operation) => (
            <div key={operation.id} className="rounded-2xl border p-5">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-lg font-semibold">{operation.name}</h3>
                    {operation.codename && <Badge variant="outline" className="font-mono">{operation.codename}</Badge>}
                    <Badge variant={statusStyles[operation.status]} className="capitalize">{operation.status}</Badge>
                    <Badge variant="secondary" className="capitalize">{operation.operation_type.replaceAll('_', ' ')}</Badge>
                    <Badge variant="outline" className="capitalize">{operation.classification}</Badge>
                  </div>
                  <p className="max-w-4xl text-sm text-muted-foreground">{operation.objective}</p>
                </div>
                <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:text-right">
                  <span>Created {new Date(operation.created_at).toLocaleDateString()}</span>
                  <span>Updated {new Date(operation.updated_at).toLocaleDateString()}</span>
                  <span>{operation.planned_start_at ? `Start ${new Date(operation.planned_start_at).toLocaleString()}` : 'Start TBD'}</span>
                  <span>{operation.planned_end_at ? `End ${new Date(operation.planned_end_at).toLocaleString()}` : 'End TBD'}</span>
                </div>
              </div>
              {operation.description && <p className="mt-4 text-sm">{operation.description}</p>}
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border bg-muted/20 p-4">
                  <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Scope Summary</p>
                  <p className="mt-2 text-sm text-muted-foreground">{operation.scope_summary || 'Scope details will be added next.'}</p>
                </div>
                <div className="rounded-xl border bg-muted/20 p-4">
                  <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Rules of Engagement</p>
                  <p className="mt-2 text-sm text-muted-foreground">{operation.roe_summary || 'ROE details will be added next.'}</p>
                </div>
              </div>
              {operation.tags.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {operation.tags.map((tag) => <Badge key={tag} variant="outline">{tag}</Badge>)}
                </div>
              )}
              {(actionConfig[operation.status]?.length || 0) > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2 border-t pt-4">
                  {operation.status === 'planning' && <Button size="sm" variant="ghost" disabled={transitioning === operation.id} onClick={() => editOperation(operation)}>Edit Plan</Button>}
                  {actionConfig[operation.status]?.map(({ action, label }) => {
                    const Icon = actionIcon(action)
                    const destructive = action === 'emergency_stop'
                    return <Button key={action} size="sm" variant={destructive ? 'destructive' : 'outline'} disabled={transitioning === operation.id} onClick={() => void handleTransition(operation, action)}><Icon className="mr-2 h-4 w-4" />{label}</Button>
                  })}
                  {operation.status === 'planning' && (!operation.scope_summary || !operation.roe_summary || !operation.planned_start_at || !operation.planned_end_at) && (
                    <p className="text-xs text-amber-600">Approval requires scope, rules of engagement, and a start/end window.</p>
                  )}
                </div>
              )}
              {operation.stop_reason && <p className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">Stopped: {operation.stop_reason}</p>}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
