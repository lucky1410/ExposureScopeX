'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'

type ThemeMode = 'light' | 'dark'

interface AppShellContextValue {
  collapsed: boolean
  setCollapsed: (value: boolean) => void
  toggleCollapsed: () => void
  theme: ThemeMode
  setTheme: (value: ThemeMode) => void
  toggleTheme: () => void
}

const AppShellContext = createContext<AppShellContextValue | null>(null)

const THEME_STORAGE_KEY = 'exsx-theme'
const SIDEBAR_STORAGE_KEY = 'exsx-sidebar-collapsed'

export function AppShellProvider({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsedState] = useState(false)
  const [theme, setThemeState] = useState<ThemeMode>('dark')

  useEffect(() => {
    if (typeof window === 'undefined') return

    const savedCollapsed = window.localStorage.getItem(SIDEBAR_STORAGE_KEY)
    if (savedCollapsed) {
      setCollapsedState(savedCollapsed === 'true')
    }

    const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY) as ThemeMode | null
    const preferredDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    setThemeState(savedTheme || (preferredDark ? 'dark' : 'light'))
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return
    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed))
  }, [collapsed])

  useEffect(() => {
    if (typeof document === 'undefined') return
    const root = document.documentElement
    root.classList.remove('light', 'dark')
    root.classList.add(theme)
    root.style.colorScheme = theme
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme)
    }
  }, [theme])

  const setCollapsed = useCallback((value: boolean) => {
    setCollapsedState(value)
  }, [])

  const toggleCollapsed = useCallback(() => {
    setCollapsedState((value) => !value)
  }, [])

  const setTheme = useCallback((value: ThemeMode) => {
    setThemeState(value)
  }, [])

  const toggleTheme = useCallback(() => {
    setThemeState((value) => (value === 'dark' ? 'light' : 'dark'))
  }, [])

  const value = useMemo(
    () => ({
      collapsed,
      setCollapsed,
      toggleCollapsed,
      theme,
      setTheme,
      toggleTheme,
    }),
    [collapsed, setCollapsed, toggleCollapsed, theme, setTheme, toggleTheme]
  )

  return <AppShellContext.Provider value={value}>{children}</AppShellContext.Provider>
}

export function useAppShell() {
  const context = useContext(AppShellContext)
  if (!context) {
    throw new Error('useAppShell must be used within AppShellProvider')
  }
  return context
}
