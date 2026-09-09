'use client'

import { ExternalLink } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader } from '@/components/shared/page-header'

interface PrivescTool {
  name: string
  purpose: string
  platform: string
  url: string
  techniques: string[]
}

const windowsTools: PrivescTool[] = [
  { name: 'WinPEAS', purpose: 'Automated Windows privilege escalation enumeration. Finds misconfigurations, credentials, and escalation paths.', platform: 'Windows', url: 'https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS', techniques: ['T1552', 'T1574', 'T1053'] },
  { name: 'PrivescCheck', purpose: 'PowerShell script for Windows privilege escalation checks. Service misconfigs, scheduled tasks, registry.', platform: 'Windows', url: 'https://github.com/itm4n/PrivescCheck', techniques: ['T1574.010', 'T1574.011'] },
  { name: 'Priv2Admin', purpose: 'Map Windows privileges to admin/system access. SeImpersonatePrivilege, SeDebugPrivilege, etc.', platform: 'Windows', url: 'https://github.com/gtworek/Priv2Admin', techniques: ['T1134', 'T1068'] },
  { name: 'wesng', purpose: 'Windows Exploit Suggester - Next Generation. Compare systeminfo output against known exploits.', platform: 'Windows', url: 'https://github.com/bitsadmin/wesng', techniques: ['T1068', 'T1203'] },
  { name: 'PowerUp', purpose: 'PowerShell privilege escalation framework. Service abuse, DLL hijacking, registry autoruns.', platform: 'Windows', url: 'https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1', techniques: ['T1574', 'T1547'] },
  { name: 'SharpUp', purpose: 'C# port of PowerUp. .NET-based privilege escalation checks for Windows environments.', platform: 'Windows', url: 'https://github.com/GhostPack/SharpUp', techniques: ['T1574', 'T1547'] },
  { name: 'Seatbelt', purpose: 'Security-oriented host-survey tool. Gather system, user, and security configuration data.', platform: 'Windows', url: 'https://github.com/GhostPack/Seatbelt', techniques: ['T1082', 'T1016', 'T1033'] },
  { name: 'BeRoot', purpose: 'Automated privilege escalation path detection for Windows.', platform: 'Windows', url: 'https://github.com/AlessandroZ/BeRoot', techniques: ['T1574', 'T1068'] },
]

const linuxTools: PrivescTool[] = [
  { name: 'LinPEAS', purpose: 'Automated Linux/macOS privilege escalation enumeration. Comprehensive system analysis.', platform: 'Linux', url: 'https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS', techniques: ['T1552', 'T1068', 'T1548'] },
  { name: 'LinEnum', purpose: 'Linux enumeration and privilege escalation checker. Kernel, network, users, SUID files.', platform: 'Linux', url: 'https://github.com/rebootuser/LinEnum', techniques: ['T1082', 'T1083'] },
  { name: 'linux-exploit-suggester', purpose: 'Suggest kernel exploits based on kernel version. Quick exploit identification.', platform: 'Linux', url: 'https://github.com/mzet-/linux-exploit-suggester', techniques: ['T1068'] },
  { name: 'pspy', purpose: 'Monitor Linux processes without root. Discover cron jobs, scripts, and background tasks.', platform: 'Linux', url: 'https://github.com/DominicBreuker/pspy', techniques: ['T1057', 'T1053'] },
  { name: 'GTFOBins', purpose: 'Curated list of Unix binaries that can be exploited to bypass local security restrictions.', platform: 'Linux', url: 'https://gtfobins.github.io', techniques: ['T1548.001', 'T1059'] },
  { name: 'linux-smart-enumeration', purpose: 'Linux enumeration tool with verbosity levels. Gradually increase detail.', platform: 'Linux', url: 'https://github.com/diego-treitos/linux-smart-enumeration', techniques: ['T1082', 'T1083'] },
  { name: 'SUDO_KILLER', purpose: 'Identify and exploit sudo misconfigurations. CVE checks, rule analysis.', platform: 'Linux', url: 'https://github.com/TH3xACE/SUDO_KILLER', techniques: ['T1548.003'] },
]

function ToolTable({ tools }: { tools: PrivescTool[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Tool</TableHead>
          <TableHead className="w-[40%]">Purpose</TableHead>
          <TableHead>MITRE Techniques</TableHead>
          <TableHead className="text-right">Link</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tools.map((tool) => (
          <TableRow key={tool.name}>
            <TableCell className="font-medium">{tool.name}</TableCell>
            <TableCell className="text-sm text-muted-foreground">{tool.purpose}</TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
                {tool.techniques.map((t) => (
                  <Badge key={t} variant="outline" className="text-[10px] font-mono">{t}</Badge>
                ))}
              </div>
            </TableCell>
            <TableCell className="text-right">
              <a href={tool.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                Open <ExternalLink className="h-3 w-3" />
              </a>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export default function PrivescPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Privilege Escalation" description="Privilege escalation tools and techniques reference" />

      <Tabs defaultValue="windows">
        <TabsList>
          <TabsTrigger value="windows">Windows</TabsTrigger>
          <TabsTrigger value="linux">Linux</TabsTrigger>
        </TabsList>
        <TabsContent value="windows">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Windows Privilege Escalation Tools</CardTitle>
              <CardDescription>Tools for identifying and exploiting Windows privilege escalation vectors</CardDescription>
            </CardHeader>
            <CardContent>
              <ToolTable tools={windowsTools} />
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="linux">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Linux Privilege Escalation Tools</CardTitle>
              <CardDescription>Tools for identifying and exploiting Linux/Unix privilege escalation vectors</CardDescription>
            </CardHeader>
            <CardContent>
              <ToolTable tools={linuxTools} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
