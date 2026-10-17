import { getRouteApi, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Input } from '@/shared/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { formatDateTime } from '@/shared/lib/format'
import { useUsersQuery } from './api'

const route = getRouteApi('/_authed/users/')

export function UsersPage() {
  const { t, i18n } = useTranslation()
  const query = route.useSearch().q ?? ''
  const navigate = route.useNavigate()
  const [draft, setDraft] = useState(query)
  const users = useUsersQuery(query)
  const items = users.data?.pages.flatMap(page => page.items) ?? []

  return (
    <>
      <PageHeader title={t('nav.users')} />
      <form
        role="search"
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          const q = draft.trim()
          void navigate({ search: q ? { q } : {} })
        }}
      >
        <Input
          aria-label={t('users.search_label')}
          placeholder={t('users.search_placeholder')}
          value={draft}
          onChange={event => setDraft(event.target.value)}
          className="max-w-md"
        />
        <Button type="submit">{t('users.search')}</Button>
      </form>
      {users.isPending
        ? <Loading />
        : users.error
          ? <ErrorAlert error={users.error} />
          : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('users.user_id')}</TableHead>
                      <TableHead>{t('users.handle')}</TableHead>
                      <TableHead>{t('users.status')}</TableHead>
                      <TableHead>{t('users.devices')}</TableHead>
                      <TableHead>{t('users.created_at')}</TableHead>
                      <TableHead>{t('users.last_seen')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={6} className="text-muted-foreground">{t('users.empty')}</TableCell>
                      </TableRow>
                    )}
                    {items.map(user => (
                      <TableRow key={user.user_id}>
                        <TableCell className="font-mono">
                          <Link to="/users/$userId" params={{ userId: user.user_id }} className="underline-offset-4 hover:underline">
                            {user.user_id}
                          </Link>
                        </TableCell>
                        <TableCell>{user.handle ?? '—'}</TableCell>
                        <TableCell>
                          {user.suspended
                            ? <Badge variant="destructive">{t('users.suspended')}</Badge>
                            : <Badge variant="secondary">{t('users.active')}</Badge>}
                        </TableCell>
                        <TableCell>{user.device_count}</TableCell>
                        <TableCell>{formatDateTime(user.created_at, i18n.language)}</TableCell>
                        <TableCell>{formatDateTime(user.last_seen, i18n.language)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {users.hasNextPage && (
                  <Button variant="outline" disabled={users.isFetchingNextPage} onClick={() => void users.fetchNextPage()}>
                    {t('common.load_more')}
                  </Button>
                )}
              </>
            )}
    </>
  )
}
