import { useTranslation } from 'react-i18next'

export function NotFound() {
  const { t } = useTranslation()
  return <p className="p-6 text-muted-foreground">{t('common.not_found')}</p>
}
