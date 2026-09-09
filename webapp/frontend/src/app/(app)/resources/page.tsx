'use client'

import { useEffect, useState } from 'react'
import { ExternalLink, Star, Search } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { PageHeader } from '@/components/shared/page-header'
import { getResources, toggleResourceFavorite } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { Resource } from '@/lib/types'

export default function ResourcesPage() {
  const [resources, setResources] = useState<Resource[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [activeCategory, setActiveCategory] = useState<string | null>(null)

  useEffect(() => {
    getResources()
      .then((res) => setResources(res.items))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const categories = Array.from(new Set(resources.map((r) => r.category)))

  const filtered = resources.filter((r) => {
    const matchesSearch = r.name.toLowerCase().includes(filter.toLowerCase()) ||
      r.description.toLowerCase().includes(filter.toLowerCase()) ||
      r.tags.some((t) => t.toLowerCase().includes(filter.toLowerCase()))
    const matchesCategory = !activeCategory || r.category === activeCategory
    return matchesSearch && matchesCategory
  })

  const toggleFavorite = async (id: string) => {
    try {
      const result = await toggleResourceFavorite(id)
      setResources((prev) =>
        prev.map((r) => (r.id === id ? { ...r, is_favorite: result.is_favorite } : r))
      )
    } catch {
      setResources((prev) =>
        prev.map((r) => (r.id === id ? { ...r, is_favorite: !r.is_favorite } : r))
      )
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Resources" description="Security tools, references, and bookmarks" />

      <div className="flex flex-col gap-4 lg:flex-row">
        <div className="w-full lg:w-56 space-y-2">
          <Input
            placeholder="Search resources..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="mb-2"
          />
          <Button variant={!activeCategory ? 'default' : 'ghost'} size="sm" className="w-full justify-start" onClick={() => setActiveCategory(null)}>
            All Resources
          </Button>
          {categories.map((cat) => (
            <Button key={cat} variant={activeCategory === cat ? 'default' : 'ghost'} size="sm" className="w-full justify-start" onClick={() => setActiveCategory(cat === activeCategory ? null : cat)}>
              {cat}
            </Button>
          ))}
        </div>

        <div className="flex-1">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {filtered.map((resource) => (
                  <Card key={resource.id} className="group hover:border-primary/30 transition-colors">
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <CardTitle className="text-sm">{resource.name}</CardTitle>
                        <div className="flex items-center gap-1">
                          <button onClick={() => toggleFavorite(resource.id)} className="p-1 rounded hover:bg-muted transition-colors">
                            <Star className={cn('h-3.5 w-3.5', resource.is_favorite ? 'fill-yellow-500 text-yellow-500' : 'text-muted-foreground')} />
                          </button>
                          <a href={resource.url} target="_blank" rel="noopener noreferrer" className="p-1 rounded hover:bg-muted transition-colors opacity-0 group-hover:opacity-100">
                            <ExternalLink className="h-3.5 w-3.5 text-primary" />
                          </a>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <p className="text-xs text-muted-foreground mb-3">{resource.description}</p>
                      <div className="flex items-center justify-between">
                        <div className="flex flex-wrap gap-1">
                          {resource.tags.slice(0, 3).map((tag) => (
                            <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>
                          ))}
                        </div>
                        <Badge variant={resource.integration_status === 'integrated' ? 'success' : resource.integration_status === 'available' ? 'outline' : 'outline'} className="text-[10px]">
                          {resource.integration_status}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
              {filtered.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12">
                  <Search className="h-8 w-8 text-muted-foreground mb-3" />
                  <p className="text-sm text-muted-foreground">
                    {resources.length === 0 ? 'No resources configured yet' : 'No resources match your search'}
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
