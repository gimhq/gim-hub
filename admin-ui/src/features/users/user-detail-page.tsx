import type { UserDetail } from './api'
import { getRouteApi, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ConfirmAction } from '@/shared/components/confirm-action'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { StatList } from '@/shared/components/stat-list'
import { Badge } from '@/shared/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Input } from '@/shared/components/ui/input'
import { Label } from '@/shared/components/ui/label'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { formatDateTime } from '@/shared/lib/format'
import {
  useReleaseHandleMutation,
  useRevokeSessionsMutation,
  useSuspendMutation,
  useUnsuspendMutation,
  useUserQuery,
} from './api'

const route = getRouteApi('/_authed/users/$userId')

export function UserDetailPage() {
  const { t } = useTranslation()
  const { userId } = route.useParams()
  const user = useUserQuery(userId)

  return (
    <>
      <Link to="/users" className="text-sm text-muted-foreground hover:underline">{t('users.back')}</Link>
      <PageHeader title={t('users.detail_title', { id: userId })} />
      {user.isPending
        ? <Loading />
        : user.error
          ? <ErrorAlert error={user.error} />
          : <UserDetailView user={user.data} />}
    </>
  )
}

function UserDetailView({ user }: { user: UserDetail }) {
  const { t, i18n } = useTranslation()
  const lng = i18n.language
  const suspend = useSuspendMutation(user.user_id)
  const unsuspend = useUnsuspendMutation(user.user_id)
  const release = useReleaseHandleMutation()
  const revoke = useRevokeSessionsMutation(user.user_id)
  const [reason, setReason] = useState('')
  const [notice, setNotice] = useState<string | null>(null)

  return (
    <>
      {notice && <p role="status" className="text-sm text-muted-foreground">{notice}</p>}
      <Card>
        <CardHeader><CardTitle>{t('users.account')}</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <StatList
            items={[
              [t('users.user_id'), user.user_id],
              [t('users.handle'), user.handle ?? '—'],
              [t('users.status'), user.suspended
                ? <Badge key="status" variant="destructive">{t('users.suspended_since', { at: formatDateTime(user.suspended_at, lng) })}</Badge>
                : <Badge key="status" variant="secondary">{t('users.active')}</Badge>],
              [t('users.created_at'), formatDateTime(user.created_at, lng)],
              [t('users.hosting_hubs'), user.hosting_hubs.length ? user.hosting_hubs.join(', ') : '—'],
            ]}
          />
          <div className="flex flex-wrap gap-2">
            {user.suspended
              ? (
                  <ConfirmAction
                    trigger={t('users.unsuspend')}
                    title={t('users.unsuspend_title')}
                    description={t('users.unsuspend_description', { id: user.user_id })}
                    confirmLabel={t('users.unsuspend')}
                    onConfirm={() => unsuspend.mutateAsync()}
                  />
                )
              : (
                  <ConfirmAction
                    variant="destructive"
                    trigger={t('users.suspend')}
                    title={t('users.suspend_title')}
                    description={t('users.suspend_description', { id: user.user_id })}
                    confirmLabel={t('users.suspend')}
                    onConfirm={async () => {
                      await suspend.mutateAsync(reason.trim())
                      setReason('')
                    }}
                  >
                    <div className="flex flex-col gap-1.5">
                      <Label htmlFor="suspend-reason">{t('users.suspend_reason')}</Label>
                      <Input id="suspend-reason" value={reason} onChange={event => setReason(event.target.value)} />
                    </div>
                  </ConfirmAction>
                )}
            {user.handle && (
              <ConfirmAction
                variant="destructive"
                trigger={t('users.release_handle')}
                title={t('users.release_title')}
                description={t('users.release_description', { handle: user.handle })}
                confirmLabel={t('users.release_handle')}
                onConfirm={() => release.mutateAsync(user.handle!)}
              />
            )}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t('users.devices')}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('users.device_id')}</TableHead>
                <TableHead>{t('users.status')}</TableHead>
                <TableHead>{t('users.created_at')}</TableHead>
                <TableHead>{t('users.last_seen')}</TableHead>
                <TableHead>{t('users.sessions')}</TableHead>
                <TableHead><span className="sr-only">{t('common.actions')}</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {user.devices.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground">{t('users.no_devices')}</TableCell>
                </TableRow>
              )}
              {user.devices.map(device => (
                <TableRow key={device.device_id}>
                  <TableCell className="font-mono">{device.device_id}</TableCell>
                  <TableCell>
                    <Badge variant={device.active ? 'secondary' : 'outline'}>
                      {device.active ? t('users.active') : t('users.inactive')}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatDateTime(device.created_at, lng)}</TableCell>
                  <TableCell>{formatDateTime(device.last_seen, lng)}</TableCell>
                  <TableCell>
                    {device.sessions.length === 0
                      ? '—'
                      : (
                          <ul className="flex flex-col gap-0.5">
                            {device.sessions.map(session => (
                              <li key={session.session_ref} className="font-mono text-xs">
                                {session.session_ref}
                                <span className="ml-2 text-muted-foreground">
                                  {t('users.session_expires', { at: formatDateTime(session.expires_at, lng) })}
                                </span>
                              </li>
                            ))}
                          </ul>
                        )}
                  </TableCell>
                  <TableCell className="text-right">
                    <ConfirmAction
                      variant="destructive"
                      disabled={device.sessions.length === 0}
                      trigger={t('users.revoke')}
                      title={t('users.revoke_title')}
                      description={t('users.revoke_description', { id: device.device_id })}
                      confirmLabel={t('users.revoke')}
                      onConfirm={async () => {
                        const result = await revoke.mutateAsync(device.device_id)
                        setNotice(t('users.revoked', { count: result.revoked }))
                      }}
                    />
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
