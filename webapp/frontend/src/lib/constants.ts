import {
  LayoutDashboard,
  Crosshair,
  Server,
  ShieldAlert,
  Bug,
  Search,
  Swords,
  ArrowUpCircle,
  Skull,
  Eye,
  Bot,
  FileSearch,
  FileText,
  BookOpen,
  GraduationCap,
  Bell,
  Settings,
  Target,
  Radar,
  Activity,
  Plug,
  Network,
  Waypoints,
  ListChecks,
  Gauge,
  type LucideIcon,
} from 'lucide-react'

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#64748b',
}

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

export type SeverityLevel = (typeof SEVERITY_ORDER)[number]

export const SCAN_PHASES = [
  { id: 'passive', label: 'Passive Recon', icon: 'Eye', description: 'Zero-packet OSINT gathering' },
  { id: 'enumeration', label: 'Enumeration', icon: 'Search', description: 'Subdomain discovery & DNS' },
  { id: 'dns', label: 'DNS Recon', icon: 'Globe', description: 'DNS records & zone transfers' },
  { id: 'osint', label: 'OSINT', icon: 'Eye', description: 'Shodan, VirusTotal, Censys' },
  { id: 'port_scan', label: 'Port Scan', icon: 'Scan', description: 'Nmap + masscan port scanning' },
  { id: 'ssl', label: 'SSL/TLS', icon: 'Lock', description: 'Certificate & header analysis' },
  { id: 'cloud', label: 'Cloud', icon: 'Cloud', description: 'Cloud misconfiguration detection' },
  { id: 'crawler', label: 'Deep Crawler', icon: 'Spider', description: 'Web crawling & discovery' },
  { id: 'web', label: 'Web Testing', icon: 'Globe', description: 'Directory brute-force, SQLi, XSS' },
  { id: 'api', label: 'API Security', icon: 'Code', description: 'OpenAPI, GraphQL, secrets' },
  { id: 'screenshots', label: 'Screenshots', icon: 'Camera', description: 'Visual web snapshots' },
  { id: 'vuln', label: 'Vuln Scan', icon: 'ShieldAlert', description: 'Nuclei template scanning' },
  { id: 'cve', label: 'CVE Match', icon: 'Database', description: 'NVD CVE correlation' },
  { id: 'exploit', label: 'Exploitation', icon: 'Zap', description: 'Hydra SSH brute-force' },
] as const

export interface NavItem {
  label: string
  href: string
  icon: LucideIcon
  badge?: number
}

export interface NavSection {
  title: string
  items: NavItem[]
}

export const NAV_ITEMS: NavSection[] = [
  {
    title: 'OPERATIONS',
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
      { label: 'ASM', href: '/asm', icon: Radar },
      { label: 'Assessments', href: '/assessments', icon: Crosshair },
      { label: 'Scans', href: '/scans', icon: Activity },
      { label: 'Operations', href: '/operations', icon: Gauge },
      { label: 'Assets', href: '/assets', icon: Server },
      { label: 'Exposure Graph', href: '/attack-surface', icon: Waypoints },
      { label: 'Coverage', href: '/coverage', icon: ListChecks },
      { label: 'Vulnerabilities', href: '/vulnerabilities', icon: ShieldAlert },
      { label: 'Findings', href: '/findings', icon: Bug },
    ],
  },
  {
    title: 'INTELLIGENCE',
    items: [
      { label: 'Recon & OSINT', href: '/recon', icon: Search },
      { label: 'Security Testing', href: '/security-testing', icon: Swords },
      { label: 'Bug Hunting', href: '/bug-hunting', icon: Target },
      { label: 'MCP Security', href: '/mcp-security', icon: Network },
      { label: 'Privilege Escalation', href: '/privesc', icon: ArrowUpCircle },
      { label: 'Malware Analysis', href: '/malware', icon: Skull },
      { label: 'Threat Intel', href: '/threat-intel', icon: Eye },
    ],
  },
  {
    title: 'ANALYSIS',
    items: [
      { label: 'AI Analyst', href: '/ai-analyst', icon: Bot },
      { label: 'Cases', href: '/investigations', icon: FileSearch },
      { label: 'Reports', href: '/reports', icon: FileText },
    ],
  },
  {
    title: 'KNOWLEDGE',
    items: [
      { label: 'Resources', href: '/resources', icon: BookOpen },
      { label: 'Learning', href: '/learning', icon: GraduationCap },
    ],
  },
  {
    title: 'SYSTEM',
    items: [
      { label: 'Notifications', href: '/notifications', icon: Bell },
      { label: 'Integrations', href: '/settings/integrations', icon: Plug },
      { label: 'Settings', href: '/settings', icon: Settings },
    ],
  },
]

export const ASSET_TYPES = ['domain', 'subdomain', 'ip', 'url', 'cidr', 'image', 'cloud_resource'] as const

export const SCAN_MODES = [
  { value: 'light', label: 'Light', description: 'Quick scan, minimal footprint' },
  { value: 'medium', label: 'Medium', description: 'Balanced speed and coverage' },
  { value: 'aggressive', label: 'Aggressive', description: 'Full coverage, slower' },
] as const

export const SCAN_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled'] as const
