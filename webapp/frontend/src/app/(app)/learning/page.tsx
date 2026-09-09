'use client'

import { ExternalLink, GraduationCap, Headphones, BookOpen, Award, Newspaper, FlaskConical } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader } from '@/components/shared/page-header'

interface LearningResource {
  name: string
  description: string
  url: string
  type: string
  difficulty?: string
}

const sections = [
  {
    title: 'Practice Labs',
    icon: FlaskConical,
    description: 'Hands-on cybersecurity training platforms',
    items: [
      { name: 'TryHackMe', description: 'Guided cybersecurity training. Beginner to advanced rooms with step-by-step walkthroughs.', url: 'https://tryhackme.com', type: 'Lab', difficulty: 'All Levels' },
      { name: 'Hack The Box', description: 'Challenge-based penetration testing labs. Retire machines, pro labs, and competitive CTFs.', url: 'https://www.hackthebox.com', type: 'Lab', difficulty: 'Intermediate-Advanced' },
      { name: 'PentesterLab', description: 'Learn web penetration testing. Exercises covering OWASP Top 10 and advanced techniques.', url: 'https://pentesterlab.com', type: 'Lab', difficulty: 'All Levels' },
      { name: 'OverTheWire', description: 'Free wargames for learning security concepts. Bandit, Natas, Leviathan, and more.', url: 'https://overthewire.org', type: 'Lab', difficulty: 'Beginner-Intermediate' },
      { name: 'VulnHub', description: 'Vulnerable virtual machines for practice. Download and hack in your own environment.', url: 'https://www.vulnhub.com', type: 'Lab', difficulty: 'All Levels' },
      { name: 'OWASP WebGoat', description: 'Deliberately insecure web application. Learn web security vulnerabilities hands-on.', url: 'https://owasp.org/www-project-webgoat/', type: 'Lab', difficulty: 'Beginner' },
    ],
  },
  {
    title: 'News & Research',
    icon: Newspaper,
    description: 'Stay current with cybersecurity news and threat research',
    items: [
      { name: 'BleepingComputer', description: 'Technology news with focus on cybersecurity. Breaking news, malware analysis, tutorials.', url: 'https://www.bleepingcomputer.com', type: 'News' },
      { name: 'The Hacker News', description: 'Most trusted cybersecurity news source. Vulnerability disclosures, data breaches, threat research.', url: 'https://thehackernews.com', type: 'News' },
      { name: 'Krebs on Security', description: 'In-depth security news and investigation by Brian Krebs. Cybercrime, breaches, and policy.', url: 'https://krebsonsecurity.com', type: 'News' },
      { name: 'Dark Reading', description: 'Enterprise cybersecurity news and analysis. Threat intelligence, vulnerability management.', url: 'https://www.darkreading.com', type: 'News' },
      { name: 'Threatpost', description: 'Independent news site covering IT security. Vulnerability analysis and zero-day reports.', url: 'https://threatpost.com', type: 'News' },
    ],
  },
  {
    title: 'Standards & Frameworks',
    icon: BookOpen,
    description: 'Industry standards, frameworks, and compliance guidelines',
    items: [
      { name: 'NIST Cybersecurity Framework', description: 'Framework for improving critical infrastructure cybersecurity. Identify, Protect, Detect, Respond, Recover.', url: 'https://www.nist.gov/cyberframework', type: 'Framework' },
      { name: 'OWASP Top 10', description: 'Standard awareness document for web application security. Top 10 most critical risks.', url: 'https://owasp.org/www-project-top-ten/', type: 'Standard' },
      { name: 'MITRE ATT&CK', description: 'Knowledge base of adversary tactics and techniques. Industry standard for threat modeling.', url: 'https://attack.mitre.org', type: 'Framework' },
      { name: 'CIS Benchmarks', description: 'Best practice security configuration guides. OS, cloud, network, and application hardening.', url: 'https://www.cisecurity.org/cis-benchmarks', type: 'Standard' },
      { name: 'PTES', description: 'Penetration Testing Execution Standard. Methodology for conducting professional pentests.', url: 'http://www.pentest-standard.org', type: 'Standard' },
    ],
  },
  {
    title: 'Certifications',
    icon: Award,
    description: 'Industry-recognized cybersecurity certifications',
    items: [
      { name: 'OSCP', description: 'Offensive Security Certified Professional. Hands-on penetration testing certification with 24-hour exam.', url: 'https://www.offsec.com/courses/pen-200/', type: 'Certification', difficulty: 'Advanced' },
      { name: 'CEH', description: 'Certified Ethical Hacker by EC-Council. Knowledge-based certification covering ethical hacking methodologies.', url: 'https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/', type: 'Certification', difficulty: 'Intermediate' },
      { name: 'CompTIA Security+', description: 'Vendor-neutral security certification. Foundation-level cert covering security concepts and best practices.', url: 'https://www.comptia.org/certifications/security', type: 'Certification', difficulty: 'Beginner' },
      { name: 'CISSP', description: 'Certified Information Systems Security Professional. Senior-level certification for security managers.', url: 'https://www.isc2.org/certifications/cissp', type: 'Certification', difficulty: 'Advanced' },
      { name: 'OSWE', description: 'Offensive Security Web Expert. Advanced web application penetration testing certification.', url: 'https://www.offsec.com/courses/web-300/', type: 'Certification', difficulty: 'Expert' },
    ],
  },
  {
    title: 'Podcasts',
    icon: Headphones,
    description: 'Cybersecurity podcasts for continuous learning',
    items: [
      { name: 'Darknet Diaries', description: 'True stories from the dark side of the internet. Hackers, breaches, and cybercrime investigations.', url: 'https://darknetdiaries.com', type: 'Podcast' },
      { name: 'Security Now', description: 'Steve Gibson and Leo Laporte discuss security topics. Weekly deep dives into cybersecurity.', url: 'https://www.grc.com/securitynow.htm', type: 'Podcast' },
      { name: 'Risky Business', description: 'Weekly information security podcast. News and in-depth interviews with industry leaders.', url: 'https://risky.biz', type: 'Podcast' },
      { name: 'Malicious Life', description: 'Untold stories of the history of cybersecurity. From the Morris Worm to modern APTs.', url: 'https://malicious.life', type: 'Podcast' },
      { name: 'SANS Internet Storm Center', description: 'Daily podcast from SANS ISC handlers. Current threat landscape and incident analysis.', url: 'https://isc.sans.edu/podcast.html', type: 'Podcast' },
    ],
  },
]

export default function LearningPage() {
  return (
    <div className="space-y-8">
      <PageHeader title="Learning Center" description="Cybersecurity education, training, and professional development" />

      {sections.map((section) => {
        const Icon = section.icon
        return (
          <div key={section.title}>
            <div className="flex items-center gap-2 mb-4">
              <Icon className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold">{section.title}</h2>
              <span className="text-xs text-muted-foreground">-- {section.description}</span>
            </div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {section.items.map((item) => (
                <Card key={item.name} className="group hover:border-primary/30 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="text-sm font-medium">{item.name}</h3>
                      <a href={item.url} target="_blank" rel="noopener noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity">
                        <ExternalLink className="h-3.5 w-3.5 text-primary" />
                      </a>
                    </div>
                    <p className="text-xs text-muted-foreground mb-3">{item.description}</p>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-[10px]">{item.type}</Badge>
                      {'difficulty' in item && item.difficulty && <Badge variant="outline" className="text-[10px]">{item.difficulty}</Badge>}
                    </div>
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
