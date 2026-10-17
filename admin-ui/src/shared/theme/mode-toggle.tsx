import type { Theme } from './theme-context'
import { Monitor, Moon, Sun } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/components/ui/button'
import { useTheme } from './theme-context'

const NEXT: Record<Theme, Theme> = { light: 'dark', dark: 'system', system: 'light' }
const ICON = { light: Sun, dark: Moon, system: Monitor }

export function ModeToggle() {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const Icon = ICON[theme]
  const label = t('theme.toggle', { mode: t(`theme.${theme}`) })
  return (
    <Button variant="ghost" size="icon" aria-label={label} title={label} onClick={() => setTheme(NEXT[theme])}>
      <Icon />
    </Button>
  )
}
