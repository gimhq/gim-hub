import type { PushCounters } from './api'
import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { StatList } from '@/shared/components/stat-list'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { formatBytes, formatDateTime, formatNumber, splitDuration } from '@/shared/lib/format'
import { useOverviewQuery } from './api'

const PUSH_KEYS: (keyof PushCounters)[] = [
  'enqueued',
  'coalesced',
  'upgraded',
  'dropped',
  'sent',
  'skipped',
  'invalid_token',
  'retried',
  'failed',
]

export function OverviewPage() {
  const { t, i18n } = useTranslation()
  const lng = i18n.language
  const { data, error, isPending } = useOverviewQuery()

  return (
    <>
      <PageHeader title={t('nav.overview')} />
      {isPending
        ? <Loading />
        : error
          ? <ErrorAlert error={error} />
          : (
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader><CardTitle>{t('overview.hub')}</CardTitle></CardHeader>
                  <CardContent>
                    <StatList
                      items={[
                        [t('overview.version'), `${data.version} (${data.revision})`],
                        [t('overview.hub_id'), data.hub_id],
                        [t('overview.public_url'), data.public_url ?? '—'],
                        [t('overview.started_at'), formatDateTime(data.started_at, lng)],
                        [t('overview.uptime'), t('overview.uptime_value', splitDuration(data.uptime_seconds))],
                        [t('overview.retention'), t('overview.retention_value', { count: data.event_retention_days })],
                      ]}
                    />
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle>{t('overview.storage_counts')}</CardTitle></CardHeader>
                  <CardContent>
                    <StatList
                      items={[
                        [t('overview.db_bytes'), formatBytes(data.storage.db_bytes, lng)],
                        [t('overview.blob_bytes'), formatBytes(data.storage.blob_bytes, lng)],
                        [t('overview.users'), formatNumber(data.counts.users, lng)],
                        [t('overview.devices'), formatNumber(data.counts.devices, lng)],
                        [t('overview.groups'), formatNumber(data.counts.groups, lng)],
                        [t('overview.blobs'), formatNumber(data.counts.blobs, lng)],
                      ]}
                    />
                  </CardContent>
                </Card>
                <Card className="md:col-span-2">
                  <CardHeader><CardTitle>{t('overview.push')}</CardTitle></CardHeader>
                  <CardContent>
                    <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                      {PUSH_KEYS.map(key => (
                        <div key={key} className="rounded-lg bg-muted/50 p-2">
                          <dt className="text-xs text-muted-foreground">{t(`overview.push_${key}`)}</dt>
                          <dd className="font-mono text-lg">{formatNumber(data.push[key], lng)}</dd>
                        </div>
                      ))}
                    </dl>
                  </CardContent>
                </Card>
              </div>
            )}
    </>
  )
}
