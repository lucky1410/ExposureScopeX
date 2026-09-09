'use client'

import { FormEvent, useCallback, useEffect, useState } from 'react'
import { ShieldCheck, Trash2 } from 'lucide-react'
import {
  createScanAuthorization,
  deleteScanAuthorization,
  getScanAuthorizations,
} from '@/lib/api'
import type { ScanAuthorization } from '@/lib/types'
import { PageHeader } from '@/components/shared/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'

function errorMessage(error: any): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (detail?.message) {
    const targets = Array.isArray(detail.uncovered_targets) ? ` ${detail.uncovered_targets.join(', ')}` : ''
    return `${detail.message}${targets}`
  }
  return error?.message || 'The request could not be completed.'
}

function authorizationStatus(item: ScanAuthorization) {
  const now = Date.now()
  if (item.valid_from && new Date(item.valid_from).getTime() > now) return 'scheduled'
  if (item.valid_until && new Date(item.valid_until).getTime() < now) return 'expired'
  return 'active'
}

const initialForm = {
  target: '',
  authorization_type: 'full' as ScanAuthorization['authorization_type'],
  valid_from: '',
  valid_until: '',
  scope_file: '',
  notes: '',
}

export default function ScanAuthorizationsPage() {
  const [items, setItems] = useState<ScanAuthorization[]>([])
  const [form, setForm] = useState(initialForm)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const { toast } = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setItems(await getScanAuthorizations())
    } catch (error) {
      toast({ title: 'Could not load authorizations', description: errorMessage(error), variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { void load() }, [load])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setSaving(true)
    try {
      await createScanAuthorization({
        ...form,
        valid_from: form.valid_from ? new Date(form.valid_from).toISOString() : undefined,
        valid_until: form.valid_until ? new Date(form.valid_until).toISOString() : undefined,
      })
      setForm(initialForm)
      await load()
      toast({ title: 'Scan scope authorized', description: 'Matching scans can now be started during the validity window.' })
    } catch (error) {
      toast({ title: 'Could not authorize scope', description: errorMessage(error), variant: 'destructive' })
    } finally {
      setSaving(false)
    }
  }

  async function remove(item: ScanAuthorization) {
    if (!window.confirm(`Remove scan authorization for ${item.target}?`)) return
    try {
      await deleteScanAuthorization(item.id)
      setItems(current => current.filter(candidate => candidate.id !== item.id))
      toast({ title: 'Authorization removed' })
    } catch (error) {
      toast({ title: 'Could not remove authorization', description: errorMessage(error), variant: 'destructive' })
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Scan Authorizations" description="Define who and what ExposureScopeX is permitted to scan." />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" /> Authorize a scope</CardTitle>
            <CardDescription>Use a domain, wildcard domain, IP, CIDR, or URL. Every batch target must be covered before dispatch.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={submit}>
              <div className="space-y-2">
                <Label htmlFor="target">Primary scope</Label>
                <Input id="target" required placeholder="example.com, *.example.com, or 203.0.113.0/24" value={form.target} onChange={event => setForm({ ...form, target: event.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>Authorization level</Label>
                <Select value={form.authorization_type} onValueChange={(value: ScanAuthorization['authorization_type']) => setForm({ ...form, authorization_type: value })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="full">Full active scanning</SelectItem>
                    <SelectItem value="passive_only">Passive enumeration only</SelectItem>
                    <SelectItem value="read_only">Read-only sources only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2"><Label htmlFor="valid-from">Valid from</Label><Input id="valid-from" type="datetime-local" value={form.valid_from} onChange={event => setForm({ ...form, valid_from: event.target.value })} /></div>
                <div className="space-y-2"><Label htmlFor="valid-until">Valid until</Label><Input id="valid-until" type="datetime-local" value={form.valid_until} onChange={event => setForm({ ...form, valid_until: event.target.value })} /></div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="scope-file">Additional scope entries</Label>
                <Textarea id="scope-file" rows={5} placeholder={'One target per line, or a JSON targets list'} value={form.scope_file} onChange={event => setForm({ ...form, scope_file: event.target.value })} />
              </div>
              <div className="space-y-2"><Label htmlFor="notes">Evidence / notes</Label><Textarea id="notes" rows={3} placeholder="Ticket, contract, owner, or approval reference" value={form.notes} onChange={event => setForm({ ...form, notes: event.target.value })} /></div>
              <Button className="w-full" disabled={saving}>{saving ? 'Authorizing...' : 'Authorize scope'}</Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Authorized scopes</CardTitle><CardDescription>Expired and future records remain visible as evidence but cannot dispatch scans.</CardDescription></CardHeader>
          <CardContent className="space-y-3">
            {loading && <p className="text-sm text-muted-foreground">Loading authorizations...</p>}
            {!loading && items.length === 0 && <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">No scan scopes have been authorized yet.</p>}
            {items.map(item => {
              const state = authorizationStatus(item)
              return <div key={item.id} className="rounded-xl border bg-card/60 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0"><p className="truncate font-medium">{item.target}</p><p className="mt-1 text-xs text-muted-foreground">{item.authorization_type.replaceAll('_', ' ')}</p></div>
                  <div className="flex items-center gap-2"><Badge variant={state === 'active' ? 'default' : 'secondary'}>{state}</Badge><Button size="icon" variant="ghost" aria-label={`Remove ${item.target}`} onClick={() => void remove(item)}><Trash2 className="h-4 w-4" /></Button></div>
                </div>
                {(item.valid_from || item.valid_until) && <p className="mt-3 text-xs text-muted-foreground">{item.valid_from ? new Date(item.valid_from).toLocaleString() : 'Immediately'} to {item.valid_until ? new Date(item.valid_until).toLocaleString() : 'No expiry'}</p>}
                {item.notes && <p className="mt-2 text-sm text-muted-foreground">{item.notes}</p>}
              </div>
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
