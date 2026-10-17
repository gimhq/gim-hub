import type * as React from 'react'
import type { Theme, ThemeContextValue } from './theme-context'
import { useEffect, useMemo, useState } from 'react'
import { ThemeContext } from './theme-context'

const STORAGE_KEY = 'gim-admin-theme'

function readTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY)
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system'
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>(readTheme)

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)')
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && !!media?.matches)
      document.documentElement.classList.toggle('dark', dark)
    }
    apply()
    if (theme !== 'system' || !media)
      return
    media.addEventListener('change', apply)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  const value = useMemo<ThemeContextValue>(() => ({
    theme,
    setTheme: (next) => {
      localStorage.setItem(STORAGE_KEY, next)
      setTheme(next)
    },
  }), [theme])

  return <ThemeContext value={value}>{children}</ThemeContext>
}
