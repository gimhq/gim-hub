import { useTranslation } from 'react-i18next'
import { Skeleton } from '@/shared/components/ui/skeleton'

export function Loading() {
  const { t } = useTranslation()
  return (
    <div role="status" aria-live="polite" className="flex flex-col gap-2">
      <span className="sr-only">{t('common.loading')}</span>
      <Skeleton className="h-6 w-1/3" />
      <Skeleton className="h-24 w-full" />
    </div>
  )
}
