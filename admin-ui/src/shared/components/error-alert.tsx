import { CircleAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Alert, AlertDescription, AlertTitle } from '@/shared/components/ui/alert'
import { errorMessage } from '@/shared/lib/error-message'

export function ErrorAlert({ error }: { error: unknown }) {
  const { t } = useTranslation()
  return (
    <Alert variant="destructive" role="alert">
      <CircleAlert />
      <AlertTitle>{t('common.error')}</AlertTitle>
      <AlertDescription>{errorMessage(error, t('common.error_generic'))}</AlertDescription>
    </Alert>
  )
}
