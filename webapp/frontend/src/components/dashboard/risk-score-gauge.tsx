'use client'

import { getRiskScoreColor, getRiskScoreLabel } from '@/lib/utils'

interface RiskScoreGaugeProps {
  score: number
}

export function RiskScoreGauge({ score }: RiskScoreGaugeProps) {
  const color = getRiskScoreColor(score)
  const label = getRiskScoreLabel(score)
  const percentage = (score / 10) * 100
  const circumference = 2 * Math.PI * 45
  const strokeDashoffset = circumference - (percentage / 100) * circumference * 0.75
  const rotation = -135

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-32 w-32">
        <svg className="h-full w-full" viewBox="0 0 100 100">
          {/* Background arc */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="hsl(220, 30%, 15%)"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            transform={`rotate(${rotation} 50 50)`}
          />
          {/* Value arc */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeDashoffset={strokeDashoffset}
            transform={`rotate(${rotation} 50 50)`}
            className="transition-all duration-1000 ease-out"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{score.toFixed(1)}</span>
          <span className="text-[10px] text-muted-foreground">{label}</span>
        </div>
      </div>
    </div>
  )
}
