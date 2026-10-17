import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { formatDateTime } from '@/shared/lib/format'
import { useAuditQuery } from './api'

export function AuditPage() {
  const { t, i18n } = useTranslation()
  const audit = useAuditQuery()
  const items = audit.data?.pages.flatMap(page => page.items) ?? []

  return (
    <>
      <PageHeader title={t('nav.audit')} />
      {audit.isPending
        ? <Loading />
        : audit.error
          ? <ErrorAlert error={audit.error} />
          : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('audit.at')}</TableHead>
                      <TableHead>{t('audit.actor')}</TableHead>
                      <TableHead>{t('audit.action')}</TableHead>
                      <TableHead>{t('audit.target')}</TableHead>
                      <TableHead>{t('audit.source_ip')}</TableHead>
                      <TableHead>{t('audit.result')}</TableHead>
                      <TableHead>{t('audit.detail')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={7} className="text-muted-foreground">{t('audit.empty')}</TableCell>
                      </TableRow>
                    )}
                    {items.map(entry => (
                      <TableRow key={entry.id}>
                        <TableCell>{formatDateTime(entry.at, i18n.language)}</TableCell>
                        <TableCell className="font-mono">{entry.actor}</TableCell>
                        <TableCell className="font-mono">{entry.action}</TableCell>
                        <TableCell className="font-mono">{entry.target ?? '—'}</TableCell>
                        <TableCell className="font-mono">{entry.source_ip}</TableCell>
                        <TableCell>
                          <Badge variant={entry.result === 'ok' ? 'secondary' : 'destructive'}>
                            {t(`audit.result_${entry.result}`)}
                          </Badge>
                        </TableCell>
                        <TableCell className="whitespace-normal break-all">{entry.detail ?? '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {audit.hasNextPage && (
                  <Button variant="outline" disabled={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>
                    {t('common.load_more')}
                  </Button>
                )}
              </>
            )}
    </>
  )
}
