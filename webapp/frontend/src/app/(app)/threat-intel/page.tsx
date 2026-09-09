'use client'

import { ExternalLink, Shield, AlertTriangle, Globe, Database, FileText } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'

const threatIntelResources = [
  {
    category: 'Vulnerability Databases',
    icon: Database,
    items: [
      { name: 'NVD (National Vulnerability Database)', description: 'US government repository of standards-based vulnerability data. CVSS scores, CPE, CWE.', url: 'https://nvd.nist.gov', status: 'integrated' },
      { name: 'CISA KEV Catalog', description: 'Known Exploited Vulnerabilities catalog. Actively exploited CVEs requiring urgent patching.', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', status: 'integrated' },
      { name: 'EPSS (Exploit Prediction)', description: 'Exploit Prediction Scoring System. Probability a vulnerability will be exploited in the wild.', url: 'https://www.first.org/epss/', status: 'integrated' },
      { name: 'VulnCheck', description: 'Real-time vulnerability intelligence. Initial access, threat actor, and exploit intelligence.', url: 'https://vulncheck.com', status: 'external' },
    ],
  },
  {
    category: 'Threat Actor Intelligence',
    icon: AlertTriangle,
    items: [
      { name: 'MITRE ATT&CK', description: 'Knowledge base of adversary tactics and techniques based on real-world observations.', url: 'https://attack.mitre.org', status: 'external' },
      { name: 'APT Groups & Operations', description: 'Comprehensive spreadsheet of known APT groups, their campaigns, and tools.', url: 'https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU', status: 'external' },
      { name: 'Malpedia', description: 'Curated database of malware families, threat actors, and YARA rules.', url: 'https://malpedia.caad.fkie.fraunhofer.de', status: 'external' },
      { name: 'Ransom Watch', description: 'Track ransomware groups, their victims, and data leak sites.', url: 'https://ransomwatch.telemetry.ltd', status: 'external' },
    ],
  },
  {
    category: 'IOC Feeds & Blocklists',
    icon: Shield,
    items: [
      { name: 'abuse.ch', description: 'Community-driven threat intelligence. Malware, botnet, and phishing tracking.', url: 'https://abuse.ch', status: 'external' },
      { name: 'AlienVault OTX', description: 'Open Threat Exchange. Community-contributed IOCs and threat intelligence pulses.', url: 'https://otx.alienvault.com', status: 'external' },
      { name: 'ThreatCrowd', description: 'Open source threat intelligence search engine. Domains, IPs, emails, and file hashes.', url: 'https://www.threatcrowd.org', status: 'external' },
      { name: 'PhishTank', description: 'Community-verified phishing URL database. Submit and check suspicious URLs.', url: 'https://phishtank.org', status: 'external' },
    ],
  },
  {
    category: 'Reporting & Analysis',
    icon: FileText,
    items: [
      { name: 'Mandiant Threat Intelligence', description: 'Threat intelligence and incident response expertise from Google Cloud.', url: 'https://www.mandiant.com/advantage/threat-intelligence', status: 'external' },
      { name: 'Recorded Future', description: 'AI-powered threat intelligence. Real-time threat insights from open, dark, and technical sources.', url: 'https://www.recordedfuture.com', status: 'external' },
      { name: 'VirusTotal Intelligence', description: 'Advanced malware hunting and threat intelligence. YARA, behavior, and similarity search.', url: 'https://www.virustotal.com/gui/intelligence-overview', status: 'integrated' },
      { name: 'Pulsedive', description: 'Free threat intelligence platform. Enrich, correlate, and share IOCs.', url: 'https://pulsedive.com', status: 'external' },
    ],
  },
]

export default function ThreatIntelPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Threat Intelligence" description="Threat intelligence feeds, databases, and analysis resources" />

      {threatIntelResources.map((section) => {
        const Icon = section.icon
        return (
          <div key={section.category}>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Icon className="h-5 w-5 text-primary" /> {section.category}
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 mb-6">
              {section.items.map((item) => (
                <Card key={item.name} className="group hover:border-primary/30 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="text-sm font-medium">{item.name}</h3>
                      <div className="flex items-center gap-2">
                        <Badge variant={item.status === 'integrated' ? 'success' : 'outline'} className="text-[10px]">
                          {item.status}
                        </Badge>
                        <a href={item.url} target="_blank" rel="noopener noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity">
                          <ExternalLink className="h-3.5 w-3.5 text-primary" />
                        </a>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground">{item.description}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
