import { AlertTriangle } from 'lucide-react'

export function DemoBanner() {
  return (
    <div className="mb-4 flex items-center gap-2 rounded-md border border-yellow-500/20 bg-yellow-500/5 px-4 py-2.5 text-sm text-yellow-400">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="font-medium">DEMO DATA</span>
      <span className="text-yellow-400/70">&mdash; This assessment contains simulated data for demonstration purposes</span>
    </div>
  )
}
