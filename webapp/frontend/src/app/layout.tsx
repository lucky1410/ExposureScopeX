import type { Metadata } from 'next'
import './globals.css'
import { Toaster } from '@/components/ui/toaster'

export const metadata: Metadata = {
  title: 'ExposureScopeX | External Exposure Intelligence',
  description: 'ExposureScopeX maps external attack surface, benchmarks risk, and turns reconnaissance into a continuously monitored security platform.',
  icons: {
    icon: [
      { url: '/images/logo-light.png', media: '(prefers-color-scheme: light)' },
      { url: '/images/logo-dark.png', media: '(prefers-color-scheme: dark)' },
      { url: '/images/logo-dark.png' },
    ],
    shortcut: ['/images/logo-dark.png'],
    apple: ['/images/logo-dark.png'],
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="antialiased bg-background text-foreground brand-noise">
        {children}
        <Toaster />
      </body>
    </html>
  )
}
