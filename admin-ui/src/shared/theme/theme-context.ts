import { createContext, use } from 'react'

export type Theme = 'light' | 'dark' | 'system'

export interface ThemeContextValue {
  theme: Theme
  setTheme: (theme: Theme) => void
}

export const ThemeContext = createContext<ThemeContextValue | null>(null)

export function useTheme() {
  const ctx = use(ThemeContext)
  if (!ctx)
    throw new Error('useTheme must be used inside ThemeProvider')
  return ctx
}
