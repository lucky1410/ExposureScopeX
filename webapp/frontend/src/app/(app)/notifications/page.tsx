'use client'

import { useEffect, useState } from 'react'
import { Bell, Check, CheckCheck, AlertTriangle, Info, CheckCircle, XCircle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'
import { SeverityBadge } from '@/components/shared/severity-badge'
import { formatRelativeTime } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { getNotifications, markNotificationRead, markAllNotificationsRead } from '@/lib/api'
import type { Notification } from '@/lib/types'

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [showRead, setShowRead] = useState(true)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getNotifications({ page: 1 })
      .then((res) => setNotifications(res.items))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const unreadCount = notifications.filter((n) => !n.is_read).length

  const markAsRead = async (id: string) => {
    try {
      await markNotificationRead(id)
      setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, is_read: true } : n)))
    } catch {
      setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, is_read: true } : n)))
    }
  }

  const markAllRead = async () => {
    try {
      await markAllNotificationsRead()
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })))
    } catch {
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })))
    }
  }

  const filteredNotifications = showRead ? notifications : notifications.filter((n) => !n.is_read)

  const typeIcons: Record<string, React.ElementType> = {
    error: XCircle,
    warning: AlertTriangle,
    success: CheckCircle,
    info: Info,
  }

  const typeColors: Record<string, string> = {
    error: 'text-red-400',
    warning: 'text-yellow-400',
    success: 'text-green-400',
    info: 'text-blue-400',
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Notifications" description={`${unreadCount} unread notification${unreadCount !== 1 ? 's' : ''}`}>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowRead(!showRead)}>
            {showRead ? 'Show Unread Only' : 'Show All'}
          </Button>
          <Button variant="outline" size="sm" onClick={markAllRead} disabled={unreadCount === 0}>
            <CheckCheck className="mr-2 h-3.5 w-3.5" /> Mark All Read
          </Button>
        </div>
      </PageHeader>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : (
        <div className="space-y-2">
          {filteredNotifications.map((notification) => {
            const Icon = typeIcons[notification.type] || Info
            return (
              <Card
                key={notification.id}
                className={cn(
                  'transition-colors cursor-pointer hover:border-primary/20',
                  !notification.is_read && 'border-l-2 border-l-primary bg-primary/[0.02]'
                )}
                onClick={() => markAsRead(notification.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className={cn('mt-0.5', typeColors[notification.type])}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className={cn('text-sm font-medium', !notification.is_read && 'text-foreground')}>{notification.title}</p>
                        <SeverityBadge severity={notification.severity} />
                        {!notification.is_read && (
                          <div className="h-2 w-2 rounded-full bg-primary" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">{notification.message}</p>
                      <div className="flex items-center gap-3 mt-2">
                        <span className="text-[11px] text-muted-foreground">{formatRelativeTime(notification.created_at)}</span>
                        <Badge variant="secondary" className="text-[10px]">{notification.source}</Badge>
                      </div>
                    </div>
                    {!notification.is_read && (
                      <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); markAsRead(notification.id) }}>
                        <Check className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
          {filteredNotifications.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12">
              <Bell className="h-8 w-8 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">No notifications to show</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
