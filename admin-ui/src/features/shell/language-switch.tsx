import { Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/components/ui/button'

// Toggles between English and Chinese; the choice persists in localStorage.
export function LanguageSwitch() {
  const { t, i18n } = useTranslation()
  const next = i18n.resolvedLanguage === 'zh-CN' ? 'en' : 'zh-CN'
  return (
    <Button
      variant="ghost"
      size="sm"
      lang={next}
      aria-label={t('language.switch_to', { language: t(`language.${next}`) })}
      onClick={() => void i18n.changeLanguage(next)}
    >
      <Languages />
      {t(`language.${next}`)}
    </Button>
  )
}
