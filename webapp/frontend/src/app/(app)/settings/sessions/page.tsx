'use client'

import { useCallback, useEffect, useState } from 'react'
import { Laptop, LogOut, RefreshCw, ShieldCheck } from 'lucide-react'
import { getAuthSessions, revokeAuthSession, revokeOtherAuthSessions } from '@/lib/api'
import type { AuthSession } from '@/lib/types'
import { PageHeader } from '@/components/shared/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'

export default function SessionsPage() {
  const { toast } = useToast()
  const [sessions, setSessions] = useState<AuthSession[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setSessions(await getAuthSessions())
    } catch (error) {
      toast({ title: 'Could not load sessions', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => { void load() }, [load])

  const revoke = async (session: AuthSession) => {
    try {
      await revokeAuthSession(session.id)
      await load()
      toast({ title: session.is_current ? 'Current session revoked' : 'Session revoked', description: session.is_current ? 'You will be asked to sign in again when this page refreshes.' : undefined })
    } catch (error) {
      toast({ title: 'Could not revoke session', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    }
  }

  const revokeOthers = async () => {
    try {
      const count = await revokeOtherAuthSessions()
      await load()
      toast({ title: 'Other sessions revoked', description: `${count} session${count === 1 ? '' : 's'} revoked.` })
    } catch (error) {
      toast({ title: 'Could not revoke sessions', description: error instanceof Error ? error.message : 'Request failed', variant: 'destructive' })
    }
  }

  return <div className="space-y-6">
    <PageHeader title="My Sessions" description="Review devices using your account and revoke access immediately">
      <div className="flex gap-2"><Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button><Button variant="destructive" onClick={() => void revokeOthers()}><LogOut className="mr-2 h-4 w-4" />Revoke others</Button></div>
    </PageHeader>
    <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="h-4 w-4 text-primary" />Active and recent sessions</CardTitle><CardDescription>IP addresses and browser identifiers are retained as security evidence. Token values are never displayed.</CardDescription></CardHeader><CardContent className="space-y-3">
      {sessions.map(session => <div key={session.id} className="flex flex-col justify-between gap-3 rounded-xl border p-4 md:flex-row md:items-center"><div className="flex min-w-0 gap-3"><Laptop className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><p className="truncate text-sm font-medium">{session.device_name}</p>{session.is_current && <Badge variant="success">Current</Badge>}<Badge variant={session.is_active ? 'secondary' : 'outline'}>{session.is_active ? 'Active' : 'Inactive'}</Badge></div><p className="mt-1 text-xs text-muted-foreground">{session.ip_address || 'Unknown source'} · Created {new Date(session.created_at).toLocaleString()} · Expires {new Date(session.expires_at).toLocaleString()}</p></div></div><Button size="sm" variant="outline" disabled={!session.is_active} onClick={() => void revoke(session)}>Revoke</Button></div>)}
      {!loading && sessions.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No sessions found.</p>}
      {loading && <p className="py-8 text-center text-sm text-muted-foreground">Loading sessions...</p>}
    </CardContent></Card>
  </div>
}
