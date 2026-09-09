'use client'

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { VulnTrendPoint } from '@/lib/types'
import { SEVERITY_COLORS } from '@/lib/constants'

interface VulnTrendChartProps {
  data: VulnTrendPoint[]
}

export function VulnTrendChart({ data }: VulnTrendChartProps) {
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Vulnerability Trend (30 Days)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={SEVERITY_COLORS.CRITICAL} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={SEVERITY_COLORS.CRITICAL} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={SEVERITY_COLORS.HIGH} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={SEVERITY_COLORS.HIGH} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={SEVERITY_COLORS.MEDIUM} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={SEVERITY_COLORS.MEDIUM} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={SEVERITY_COLORS.LOW} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={SEVERITY_COLORS.LOW} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 30%, 15%)" />
              <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 10, fill: 'hsl(217, 15%, 55%)' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: 'hsl(217, 15%, 55%)' }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(224, 45%, 10%)',
                  border: '1px solid hsl(220, 30%, 18%)',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
                labelFormatter={formatDate}
                itemStyle={{ color: 'hsl(217, 30%, 90%)' }}
              />
              <Area type="monotone" dataKey="critical" stackId="1" stroke={SEVERITY_COLORS.CRITICAL} fill="url(#colorCritical)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="high" stackId="1" stroke={SEVERITY_COLORS.HIGH} fill="url(#colorHigh)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="medium" stackId="1" stroke={SEVERITY_COLORS.MEDIUM} fill="url(#colorMedium)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="low" stackId="1" stroke={SEVERITY_COLORS.LOW} fill="url(#colorLow)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}
