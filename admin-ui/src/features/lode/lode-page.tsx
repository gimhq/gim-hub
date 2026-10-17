import type { LodeAction } from './api'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ConfirmAction } from '@/shared/components/confirm-action'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { StatList } from '@/shared/components/stat-list'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { formatDateTime } from '@/shared/lib/format'
import { useLodeActionMutation, useLodeQuery } from './api'

export function LodePage() {
  const { t, i18n } = useTranslation()
  const lng = i18n.language
  const lode = useLodeQuery()
  const action = useLodeActionMutation()
  const [notice, setNotice] = useState<string | null>(null)

  async function run(next: LodeAction) {
    setNotice(null)
    await action.mutateAsync(next)
    setNotice(t(`lode.requested_${next.kind}`))
  }

  if (lode.isPending)
    return <Loading />
  if (lode.error)
    return <ErrorAlert error={lode.error} />
  if (!lode.data.supervised)
    return <p className="text-muted-foreground">{t('lode.not_supervised')}</p>

  const data = lode.data
  return (
    <>
      <PageHeader
        title={t('nav.lode')}
        actions={(
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={action.isPending}
              onClick={() => void run({ kind: 'check' }).catch(() => {})}
            >
              {t('lode.check')}
            </Button>
            <ConfirmAction
              disabled={!data.available || data.available === data.current}
              trigger={t('lode.update')}
              title={t('lode.update_title')}
              description={t('lode.update_description', { from: data.current, to: data.available ?? '' })}
              confirmLabel={t('lode.update')}
              onConfirm={() => run({ kind: 'update', version: data.available! })}
            />
            <ConfirmAction
              trigger={t('lode.restart')}
              title={t('lode.restart_title')}
              description={t('lode.restart_description')}
              confirmLabel={t('lode.restart')}
              onConfirm={() => run({ kind: 'restart' })}
            />
            <ConfirmAction
              variant="destructive"
              disabled={!data.last_good || data.last_good === data.current}
              trigger={t('lode.rollback')}
              title={t('lode.rollback_title')}
              description={t('lode.rollback_description', { to: data.last_good ?? '' })}
              confirmLabel={t('lode.rollback')}
              onConfirm={() => run({ kind: 'rollback' })}
            />
          </div>
        )}
      />
      {notice && <p role="status" className="text-sm text-muted-foreground">{notice}</p>}
      {action.isError && action.variables?.kind === 'check' && <ErrorAlert error={action.error} />}
      <Card>
        <CardHeader><CardTitle>{t('lode.state')}</CardTitle></CardHeader>
        <CardContent>
          <StatList
            items={[
              [t('lode.status'), <Badge key="status" variant="secondary">{data.status}</Badge>],
              [t('lode.current'), data.current],
              [t('lode.available'), data.available ?? '—'],
              [t('lode.last_good'), data.last_good ?? '—'],
              [t('lode.last_check'), formatDateTime(data.last_check, lng)],
              [t('lode.last_error'), data.last_error ?? '—'],
            ]}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t('lode.history')}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('lode.version')}</TableHead>
                <TableHead>{t('lode.at')}</TableHead>
                <TableHead>{t('lode.result')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.history.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground">{t('lode.no_history')}</TableCell>
                </TableRow>
              )}
              {data.history.map(entry => (
                <TableRow key={`${entry.version}-${entry.at}`}>
                  <TableCell className="font-mono">{entry.version}</TableCell>
                  <TableCell>{formatDateTime(entry.at, lng)}</TableCell>
                  <TableCell>
                    <Badge variant={entry.result === 'good' ? 'secondary' : 'destructive'}>{entry.result}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  )
}
