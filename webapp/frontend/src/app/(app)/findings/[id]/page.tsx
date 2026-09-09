'use client'

import { useCallback, useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { ArrowLeft, MessageSquare, RotateCcw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { createFindingActivity, getFinding, getFindingActivities, getUsers, updateFindingWorkflow } from '@/lib/api'
import type { Finding, FindingActivity, User } from '@/lib/types'
import { useToast } from '@/components/ui/use-toast'

export default function FindingWorkspacePage() {
  const id = String(useParams().id)
  const router = useRouter()
  const { toast } = useToast()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [activities, setActivities] = useState<FindingActivity[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [comment, setComment] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    const [current, timeline, members] = await Promise.all([getFinding(id), getFindingActivities(id), getUsers()])
    setFinding(current); setActivities(timeline); setUsers(members)
  }, [id])
  useEffect(() => { void load().catch((error) => toast({ title: 'Finding unavailable', description: error.message, variant: 'destructive' })) }, [load, toast])

  const saveWorkflow = async (patch: Parameters<typeof updateFindingWorkflow>[1]) => {
    setSaving(true)
    try { setFinding(await updateFindingWorkflow(id, patch)); await load(); toast({ title: 'Workflow updated' }) }
    catch (error) { toast({ title: 'Update failed', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' }) }
    finally { setSaving(false) }
  }
  const addActivity = async (type: 'comment' | 'retest_requested') => {
    if (type === 'comment' && !comment.trim()) return
    setSaving(true)
    try { await createFindingActivity(id, { activity_type: type, body: comment.trim() || undefined }); setComment(''); await load() }
    finally { setSaving(false) }
  }

  if (!finding) return <Card><CardContent className="p-10 text-center text-sm text-muted-foreground">Loading finding workspace...</CardContent></Card>
  return <div className="space-y-6">
    <Button variant="ghost" onClick={() => router.back()}><ArrowLeft className="mr-2 h-4 w-4" />Back to findings</Button>
    <div className="flex flex-col gap-4 rounded-2xl border bg-card p-6 lg:flex-row lg:items-start lg:justify-between"><div><div className="mb-3 flex gap-2"><SeverityBadge severity={finding.severity} /><Badge variant="outline" className="capitalize">{finding.status.replaceAll('_', ' ')}</Badge><Badge variant={finding.sla_status === 'overdue' ? 'destructive' : 'secondary'}>{finding.sla_status || 'untracked'}</Badge></div><h1 className="text-2xl font-semibold">{finding.title}</h1><p className="mt-2 break-all font-mono text-xs text-muted-foreground">{finding.asset_value || finding.url || 'No asset context'}</p></div><Button variant="outline" disabled={saving} onClick={() => void addActivity('retest_requested')}><RotateCcw className="mr-2 h-4 w-4" />Request retest</Button></div>
    <div className="grid gap-6 xl:grid-cols-[1.4fr_.8fr]">
      <div className="space-y-6"><Card><CardHeader><CardTitle>Evidence</CardTitle></CardHeader><CardContent className="space-y-4"><p className="whitespace-pre-wrap text-sm">{finding.description || 'No description supplied.'}</p><pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-slate-950 p-4 text-xs text-slate-200">{finding.evidence || 'No direct evidence captured.'}</pre></CardContent></Card><Card><CardHeader><CardTitle>Activity</CardTitle></CardHeader><CardContent className="space-y-4"><div className="flex gap-2"><Textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add analyst context, remediation notes, or verification evidence..." /><Button disabled={saving || !comment.trim()} onClick={() => void addActivity('comment')}><MessageSquare className="h-4 w-4" /></Button></div>{activities.map((item) => <div key={item.id} className="rounded-xl border p-3"><div className="flex justify-between text-xs"><span className="font-medium capitalize">{item.activity_type.replaceAll('_', ' ')}</span><span className="text-muted-foreground">{new Date(item.created_at).toLocaleString()}</span></div>{item.body && <p className="mt-2 whitespace-pre-wrap text-sm">{item.body}</p>}</div>)}{activities.length === 0 && <p className="text-sm text-muted-foreground">No lifecycle activity yet.</p>}</CardContent></Card></div>
      <Card><CardHeader><CardTitle>Ownership & verification</CardTitle></CardHeader><CardContent className="space-y-5"><div className="space-y-2"><Label>Assignee</Label><Select value={finding.assigned_to || 'unassigned'} onValueChange={(value) => void saveWorkflow({ assigned_to: value === 'unassigned' ? null : value })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="unassigned">Unassigned</SelectItem>{users.map((user) => <SelectItem key={user.id} value={user.id}>{user.username}</SelectItem>)}</SelectContent></Select></div><div className="space-y-2"><Label>Due date</Label><Input type="datetime-local" value={finding.due_at ? finding.due_at.slice(0, 16) : ''} onChange={(e) => void saveWorkflow({ due_at: e.target.value ? new Date(e.target.value).toISOString() : null })} /></div><div className="space-y-2"><Label>Verification</Label><Select value={finding.verification_status || 'not_requested'} onValueChange={(value) => void saveWorkflow({ verification_status: value as Finding['verification_status'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['not_requested','requested','in_progress','passed','failed','inconclusive'].map((value) => <SelectItem key={value} value={value}>{value.replaceAll('_', ' ')}</SelectItem>)}</SelectContent></Select></div><div className="rounded-xl border bg-muted/30 p-3 text-xs text-muted-foreground">First seen {finding.first_seen ? new Date(finding.first_seen).toLocaleString() : 'unknown'}<br />Source {finding.source || 'unknown'}<br />Confidence {finding.confidence_score ?? 'unscored'}</div></CardContent></Card>
    </div>
  </div>
}
