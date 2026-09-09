'use client'

import { useEffect, useState } from 'react'
import { Users, Plus, MoreHorizontal, Shield, Eye, Edit, Trash2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { PageHeader } from '@/components/shared/page-header'
import { StatusIndicator } from '@/components/shared/status-indicator'
import { formatDate, formatRelativeTime, getInitials } from '@/lib/utils'
import { getUsers } from '@/lib/api'
import type { User } from '@/lib/types'

const roleIcons: Record<string, React.ElementType> = {
  admin: Shield,
  analyst: Eye,
  viewer: Eye,
}

const roleColors: Record<string, 'default' | 'secondary' | 'outline'> = {
  admin: 'default',
  analyst: 'secondary',
  viewer: 'outline',
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getUsers()
      .then(setUsers)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6">
      <PageHeader title="User Management" description="Manage users, roles, and permissions">
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Invite User
        </Button>
      </PageHeader>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" /> Organization Members
          </CardTitle>
          <CardDescription>
            {loading ? 'Loading...' : `${users.length} user${users.length !== 1 ? 's' : ''} in your organization`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => {
                  const RoleIcon = roleIcons[user.role] || Eye
                  return (
                    <TableRow key={user.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <Avatar className="h-8 w-8">
                            <AvatarFallback className="bg-primary/10 text-primary text-xs">
                              {getInitials(user.full_name)}
                            </AvatarFallback>
                          </Avatar>
                          <div>
                            <p className="text-sm font-medium">{user.full_name}</p>
                            <p className="text-xs text-muted-foreground">{user.email}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={roleColors[user.role]} className="text-[10px] capitalize gap-1">
                          <RoleIcon className="h-3 w-3" /> {user.role}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <StatusIndicator
                          status={user.is_active ? 'success' : 'error'}
                          label={user.is_active ? 'Active' : 'Inactive'}
                        />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDate(user.created_at)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {user.last_login ? formatRelativeTime(user.last_login) : 'Never'}
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>
                              <Edit className="mr-2 h-4 w-4" /> Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem className="text-destructive">
                              <Trash2 className="mr-2 h-4 w-4" /> Remove
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
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
