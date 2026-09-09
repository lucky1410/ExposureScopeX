import { Badge } from '@/components/ui/badge'

interface SeverityBadgeProps {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const variant = severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'
  const validVariants = ['critical', 'high', 'medium', 'low', 'info']
  const badgeVariant = validVariants.includes(variant) ? variant : 'info'

  return (
    <Badge variant={badgeVariant} className={className}>
      {severity.toUpperCase()}
    </Badge>
  )
}
