import type { Allowlist } from './api'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { StatList } from '@/shared/components/stat-list'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Label } from '@/shared/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { Textarea } from '@/shared/components/ui/textarea'
import { errorMessage } from '@/shared/lib/error-message'
import { formatDateTime } from '@/shared/lib/format'
import { useAllowlistQuery, useFederationQuery, useSaveAllowlistMutation } from './api'

export function FederationPage() {
  const { t, i18n } = useTranslation()
  const federation = useFederationQuery()
  const allowlist = useAllowlistQuery()

  return (
    <>
      <PageHeader title={t('nav.federation')} />
      {federation.isPending
        ? <Loading />
        : federation.error
          ? <ErrorAlert error={federation.error} />
          : !federation.data.enabled
              ? <p className="text-muted-foreground">{t('federation.disabled')}</p>
              : (
                  <>
                    <Card>
                      <CardHeader><CardTitle>{t('federation.self')}</CardTitle></CardHeader>
                      <CardContent>
                        <StatList
                          items={[
                            [t('federation.peer_id'), federation.data.peer_id ?? '—'],
                            [t('federation.listen_addrs'), federation.data.listen_addrs.join('\n') || '—'],
                            [t('federation.external_addrs'), federation.data.external_addrs.join('\n') || '—'],
                          ]}
                        />
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader><CardTitle>{t('federation.peers')}</CardTitle></CardHeader>
                      <CardContent>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>{t('federation.hub_id')}</TableHead>
                              <TableHead>{t('federation.connection')}</TableHead>
                              <TableHead>{t('federation.backlog')}</TableHead>
                              <TableHead>{t('federation.last_seen')}</TableHead>
                              <TableHead>{t('federation.last_error')}</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {federation.data.peers.length === 0 && (
                              <TableRow>
                                <TableCell colSpan={5} className="text-muted-foreground">{t('federation.no_peers')}</TableCell>
                              </TableRow>
                            )}
                            {federation.data.peers.map(peer => (
                              <TableRow key={peer.hub_id}>
                                <TableCell className="font-mono">{peer.hub_id}</TableCell>
                                <TableCell>
                                  <Badge variant={peer.connected ? 'secondary' : 'outline'}>
                                    {peer.connected ? t('federation.connected') : t('federation.disconnected')}
                                  </Badge>
                                </TableCell>
                                <TableCell>{peer.outbox_backlog}</TableCell>
                                <TableCell>{formatDateTime(peer.last_seen, i18n.language)}</TableCell>
                                <TableCell className="whitespace-normal break-all">{peer.last_error ?? '—'}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  </>
                )}
      {allowlist.isPending
        ? null
        : allowlist.error
          ? <ErrorAlert error={allowlist.error} />
          : allowlist.data && <AllowlistEditor allowlist={allowlist.data} />}
    </>
  )
}

function AllowlistEditor({ allowlist }: { allowlist: Allowlist }) {
  const { t } = useTranslation()
  const save = useSaveAllowlistMutation()
  const [text, setText] = useState(allowlist.text)
  const [saved, setSaved] = useState(false)
  const invalid = save.isError
  const readOnly = allowlist.read_only

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('federation.allowlist')}</CardTitle>
        <CardDescription>
          {allowlist.source === 'file'
            ? t('federation.allowlist_description_file', { path: allowlist.path ?? '' })
            : t('federation.allowlist_description_stored')}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            setSaved(false)
            save.mutate(text, {
              onSuccess: (data) => {
                setText(data.text)
                setSaved(true)
              },
            })
          }}
        >
          <Label htmlFor="allowlist-text">{t('federation.allowlist_text')}</Label>
          <Textarea
            id="allowlist-text"
            className="min-h-48 font-mono text-xs"
            spellCheck={false}
            disabled={readOnly}
            value={text}
            aria-invalid={invalid || undefined}
            aria-describedby={invalid ? 'allowlist-error' : undefined}
            onChange={(event) => {
              setText(event.target.value)
              setSaved(false)
            }}
          />
          {invalid && (
            <p id="allowlist-error" role="alert" className="font-mono text-sm whitespace-pre-wrap text-destructive">
              {errorMessage(save.error, t('common.error_generic'))}
            </p>
          )}
          {readOnly && <p className="text-sm text-muted-foreground">{t('federation.allowlist_read_only')}</p>}
          {saved && <p role="status" className="text-sm text-muted-foreground">{t('federation.allowlist_saved')}</p>}
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={readOnly || save.isPending || text === allowlist.text}>
              {t('federation.allowlist_save')}
            </Button>
            <span className="text-xs text-muted-foreground">
              {t('federation.allowlist_entries', { count: allowlist.entries.length })}
            </span>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
