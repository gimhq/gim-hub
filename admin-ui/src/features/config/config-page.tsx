import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { Badge } from '@/shared/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { useConfigQuery } from './api'

export function ConfigPage() {
  const { t } = useTranslation()
  const config = useConfigQuery()

  return (
    <>
      <PageHeader title={t('nav.config')} />
      <p className="text-sm text-muted-foreground">{t('config.description')}</p>
      {config.isPending
        ? <Loading />
        : config.error
          ? <ErrorAlert error={config.error} />
          : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('config.key')}</TableHead>
                    <TableHead>{t('config.value')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {config.data.items.map(item => (
                    <TableRow key={item.key}>
                      <TableCell className="font-mono">{item.key}</TableCell>
                      <TableCell className="font-mono whitespace-normal break-all">
                        {item.redacted
                          ? <Badge variant="outline">{t('config.redacted')}</Badge>
                          : item.value ?? <span className="text-muted-foreground">{t('config.unset')}</span>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
    </>
  )
}
