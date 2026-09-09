'use client'

import { useRouter } from 'next/navigation'
import { Key, Users, Shield, Bell, Database, Palette, Plug, ScanSearch, ScrollText, MonitorSmartphone } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'

const settingsSections = [
  {
    title: 'Sessions',
    description: 'Review browser devices and revoke active sessions',
    href: '/settings/sessions',
    icon: MonitorSmartphone,
  },
  {
    title: 'Audit Log',
    description: 'Search and export organization security and administrative events.',
    icon: ScrollText,
    href: '/settings/audit-logs',
  },
  {
    title: 'Scan Authorizations',
    description: 'Approve target scopes and validity windows before active scans can run.',
    icon: ScanSearch,
    href: '/settings/scan-authorizations',
  },
  {
    title: 'API Keys',
    description: 'Manage API keys for third-party integrations (Shodan, VirusTotal, Censys, etc.)',
    icon: Key,
    href: '/settings/api-keys',
  },
  {
    title: 'User Management',
    description: 'Manage users, roles, and permissions for your organization.',
    icon: Users,
    href: '/settings/users',
  },
  {
    title: 'Security',
    description: 'Configure authentication, session management, and security policies.',
    icon: Shield,
    href: null,
  },
  {
    title: 'Integrations',
    description: 'Connect Slack, Teams, PagerDuty, Splunk, Jira, GitHub SARIF, and threat intel sources.',
    icon: Plug,
    href: '/settings/integrations',
  },
  {
    title: 'Notifications',
    description: 'Configure Slack, Teams, Splunk, and syslog integrations for alerts.',
    icon: Bell,
    href: null,
  },
  {
    title: 'Runtime & Capacity',
    description: 'Review adapter health, storage, isolation, and organization scan limits.',
    icon: Database,
    href: '/settings/runtime',
  },
  {
    title: 'Appearance',
    description: 'Customize the interface theme, layout, and display preferences.',
    icon: Palette,
    href: null,
  },
]

export default function SettingsPage() {
  const router = useRouter()

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Configure ExposureScopeX platform settings" />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {settingsSections.map((section) => {
          const Icon = section.icon
          const clickable = !!section.href
          return (
            <Card
              key={section.title}
              className={clickable ? 'cursor-pointer hover:border-primary/30 transition-colors' : 'opacity-60'}
              onClick={() => { if (section.href) router.push(section.href) }}
            >
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <Icon className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-sm">{section.title}</CardTitle>
                      {!clickable && (
                        <Badge variant="secondary" className="text-[10px] px-1.5 py-0">Soon</Badge>
                      )}
                    </div>
                    <CardDescription className="text-xs">{section.description}</CardDescription>
                  </div>
                </div>
              </CardHeader>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
