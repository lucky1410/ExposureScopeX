'use client'

import React, { useState, useRef, useEffect } from 'react'
import { Bot, Send, User, Sparkles } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { PageHeader } from '@/components/shared/page-header'
import { cn } from '@/lib/utils'
import { sendChatMessage } from '@/lib/api'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

const sampleQuestions = [
  'What are the most critical findings in the current assessment?',
  'Which assets have the highest risk scores?',
  'What remediation steps should we prioritize?',
  'Are there any exposed credentials or secrets?',
  'Summarize the findings for the latest scan',
]

const systemMessage: Message = {
  id: 'system-1',
  role: 'assistant',
  content: `Welcome to the ExposureScopeX AI Security Analyst. I can help you with:

- **Attack Surface Analysis** — Understand your exposure and risk profile
- **Vulnerability Assessment** — Prioritize findings by exploitability and impact
- **Investigation Support** — Correlate indicators and trace attack paths
- **Remediation Planning** — Generate actionable fix recommendations
- **OSINT Analysis** — Interpret reconnaissance data and threat intelligence

Ask me anything about your assessments, assets, or security posture.`,
  timestamp: new Date(),
}

export default function AIAnalystPage() {
  const [messages, setMessages] = useState<Message[]>([systemMessage])
  const [input, setInput] = useState('')
  const [isTyping, setIsTyping] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  const sendMessage = async (content: string) => {
    if (!content.trim()) return

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: content.trim(),
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput('')
    setIsTyping(true)

    try {
      const result = await sendChatMessage(content.trim())
      const aiMessage: Message = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: result.response,
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, aiMessage])
    } catch (err: any) {
      const errorMessage: Message = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: err?.response?.data?.detail || 'Failed to get a response. Please check that the AI analyst is configured (ANTHROPIC_API_KEY required).',
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsTyping(false)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    sendMessage(input)
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]">
      <PageHeader title="AI Security Analyst" description="Powered by Claude — Ask about your attack surface, vulnerabilities, or investigation leads" />

      <Card className="flex-1 flex flex-col overflow-hidden">
        <CardContent className="flex-1 flex flex-col p-0 overflow-hidden">
          <ScrollArea className="flex-1 p-4" ref={scrollRef}>
            <div className="space-y-4 max-w-3xl mx-auto">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={cn(
                    'flex gap-3',
                    message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
                  )}
                >
                  <div className={cn(
                    'flex h-8 w-8 shrink-0 items-center justify-center rounded-full',
                    message.role === 'user' ? 'bg-primary/10' : 'bg-muted'
                  )}>
                    {message.role === 'user' ? (
                      <User className="h-4 w-4 text-primary" />
                    ) : (
                      <Bot className="h-4 w-4 text-primary" />
                    )}
                  </div>
                  <div className={cn(
                    'rounded-lg px-4 py-3 max-w-[80%]',
                    message.role === 'user'
                      ? 'bg-primary/10 text-foreground'
                      : 'bg-muted/50 text-foreground'
                  )}>
                    <div className="text-sm whitespace-pre-wrap prose prose-invert prose-sm max-w-none">
                      {message.content.split('\n').map((line, i) => {
                        if (line.startsWith('**') && line.endsWith('**')) {
                          return <p key={i} className="font-semibold">{line.replace(/\*\*/g, '')}</p>
                        }
                        if (line.startsWith('- ')) {
                          return <p key={i} className="ml-2">{line}</p>
                        }
                        if (line.match(/^\d+\./)) {
                          return <p key={i} className="ml-2">{line}</p>
                        }
                        return <p key={i}>{line || '\u00A0'}</p>
                      })}
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-2">
                      {message.timestamp.toLocaleTimeString()}
                    </p>
                  </div>
                </div>
              ))}
              {isTyping && (
                <div className="flex gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                    <Bot className="h-4 w-4 text-primary" />
                  </div>
                  <div className="rounded-lg bg-muted/50 px-4 py-3">
                    <div className="flex items-center gap-1">
                      <div className="h-2 w-2 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '0ms' }} />
                      <div className="h-2 w-2 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '150ms' }} />
                      <div className="h-2 w-2 rounded-full bg-primary/60 animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>

          {messages.length <= 1 && (
            <div className="px-4 pb-2">
              <div className="flex items-center gap-2 mb-2">
                <Sparkles className="h-3.5 w-3.5 text-primary" />
                <span className="text-xs text-muted-foreground">Try asking:</span>
              </div>
              <div className="flex flex-wrap gap-2 max-w-3xl mx-auto">
                {sampleQuestions.map((q) => (
                  <button
                    key={q}
                    onClick={() => sendMessage(q)}
                    className="rounded-full border border-primary/20 bg-primary/5 px-3 py-1.5 text-xs text-primary hover:bg-primary/10 transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="border-t p-4">
            <form onSubmit={handleSubmit} className="flex gap-2 max-w-3xl mx-auto">
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about your attack surface, vulnerabilities, or investigation leads..."
                disabled={isTyping}
                className="flex-1"
              />
              <Button type="submit" disabled={!input.trim() || isTyping} size="icon">
                <Send className="h-4 w-4" />
              </Button>
            </form>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
