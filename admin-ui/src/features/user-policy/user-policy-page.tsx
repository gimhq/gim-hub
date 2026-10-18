import type { UserPolicy, UserPolicyMode } from './api'
import { useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSaveSettingMutation } from '@/features/settings/api'
import { ConfirmAction } from '@/shared/components/confirm-action'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { Alert, AlertDescription, AlertTitle } from '@/shared/components/ui/alert'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Input } from '@/shared/components/ui/input'
import { Label } from '@/shared/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/shared/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/shared/components/ui/table'
import { Textarea } from '@/shared/components/ui/textarea'
import { errorMessage } from '@/shared/lib/error-message'
import { formatDateTime } from '@/shared/lib/format'
import {
  addTarget,
  listText,
  MODE_KEY,
  useAddUserMutation,
  useRemoveUserMutation,
  useReplaceUserListMutation,
  useUserPolicyQuery,
} from './api'

const MODES: UserPolicyMode[] = ['open', 'allow', 'deny']

export function UserPolicyPage() {
  const { t } = useTranslation()
  const policy = useUserPolicyQuery()

  return (
    <>
      <PageHeader title={t('nav.user_policy')} />
      <p className="text-sm text-muted-foreground">{t('user_policy.description')}</p>
      {policy.isPending
        ? <Loading />
        : policy.error
          ? <ErrorAlert error={policy.error} />
          : (
              <>
                <Warnings policy={policy.data} />
                <ModeCard policy={policy.data} />
                <ListCard policy={policy.data} />
                <BulkCard key={listText(policy.data.entries)} policy={policy.data} />
              </>
            )}
    </>
  )
}

function Warnings({ policy }: { policy: UserPolicy }) {
  const { t } = useTranslation()
  const nobody = policy.mode === 'allow' && policy.entries.length === 0
  return (
    <>
      {nobody && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('user_policy.warning_empty_allow')}</AlertTitle>
          <AlertDescription>{t('user_policy.warning_empty_allow_description')}</AlertDescription>
        </Alert>
      )}
      {!nobody && policy.not_admitted_users > 0 && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{t('user_policy.warning_locked_out', { count: policy.not_admitted_users })}</AlertTitle>
          <AlertDescription>{t('user_policy.warning_locked_out_description')}</AlertDescription>
        </Alert>
      )}
    </>
  )
}

function ModeCard({ policy }: { policy: UserPolicy }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const save = useSaveSettingMutation(MODE_KEY)
  const [draft, setDraft] = useState<UserPolicyMode>(policy.mode)
  const readOnly = policy.mode_source === 'env'

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('user_policy.mode')}</CardTitle>
        <CardDescription>{t(`user_policy.mode_${policy.mode}_description`)}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge variant={policy.mode === 'open' ? 'outline' : 'secondary'}>{t(`user_policy.modes.${policy.mode}`)}</Badge>
          <span className="text-muted-foreground">{t(`settings.source_${policy.mode_source}`)}</span>
        </div>
        {readOnly
          ? (
              <p className="text-sm text-muted-foreground">
                {t('user_policy.mode_read_only')}
                {' '}
                <Link to="/settings" className="underline underline-offset-4">{t('user_policy.open_settings')}</Link>
              </p>
            )
          : (
              <form
                className="flex flex-wrap items-center gap-2"
                onSubmit={(event) => {
                  event.preventDefault()
                  save.mutate(draft, { onSuccess: () => queryClient.invalidateQueries({ queryKey: ['user-policy'] }) })
                }}
              >
                <Select value={draft} onValueChange={value => setDraft((value ?? 'open') as UserPolicyMode)}>
                  <SelectTrigger aria-label={t('user_policy.new_mode')} className="min-w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {MODES.map(mode => <SelectItem key={mode} value={mode}>{t(`user_policy.modes.${mode}`)}</SelectItem>)}
                  </SelectContent>
                </Select>
                <Button type="submit" size="sm" disabled={save.isPending || draft === policy.mode}>
                  {t('user_policy.apply_mode')}
                </Button>
              </form>
            )}
        {save.isError && (
          <p role="alert" className="text-sm text-destructive">{errorMessage(save.error, t('common.error_generic'))}</p>
        )}
      </CardContent>
    </Card>
  )
}

function ListCard({ policy }: { policy: UserPolicy }) {
  const { t, i18n } = useTranslation()
  const add = useAddUserMutation()
  const remove = useRemoveUserMutation()
  const [user, setUser] = useState('')
  const [note, setNote] = useState('')

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('user_policy.list')}</CardTitle>
        <CardDescription>{t('user_policy.list_description')}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            add.mutate(addTarget(user, note), {
              onSuccess: () => {
                setUser('')
                setNote('')
              },
            })
          }}
        >
          <div className="flex min-w-64 flex-1 flex-col gap-1">
            <Label htmlFor="user-policy-add">{t('user_policy.add_user')}</Label>
            <Input
              id="user-policy-add"
              placeholder={t('user_policy.add_placeholder')}
              value={user}
              aria-invalid={add.isError || undefined}
              aria-describedby={add.isError ? 'user-policy-add-error' : undefined}
              onChange={event => setUser(event.target.value)}
            />
          </div>
          <div className="flex min-w-48 flex-col gap-1">
            <Label htmlFor="user-policy-note">{t('user_policy.note')}</Label>
            <Input id="user-policy-note" value={note} onChange={event => setNote(event.target.value)} />
          </div>
          <Button type="submit" disabled={add.isPending || user.trim() === ''}>{t('user_policy.add')}</Button>
        </form>
        {add.isError && (
          <p id="user-policy-add-error" role="alert" className="text-sm text-destructive">
            {errorMessage(add.error, t('common.error_generic'))}
          </p>
        )}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('users.user_id')}</TableHead>
              <TableHead>{t('users.handle')}</TableHead>
              <TableHead>{t('user_policy.added_at')}</TableHead>
              <TableHead>{t('user_policy.note')}</TableHead>
              <TableHead>{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {policy.entries.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground">{t('user_policy.empty')}</TableCell>
              </TableRow>
            )}
            {policy.entries.map(entry => (
              <TableRow key={entry.user_id}>
                <TableCell className="font-mono">{entry.user_id}</TableCell>
                <TableCell>{entry.handle ? `@${entry.handle}` : '—'}</TableCell>
                <TableCell>
                  {t('settings.updated_value', { at: formatDateTime(entry.added_at, i18n.language), by: entry.added_by })}
                </TableCell>
                <TableCell className="whitespace-normal">{entry.note ?? '—'}</TableCell>
                <TableCell>
                  <ConfirmAction
                    trigger={t('user_policy.remove')}
                    title={t('user_policy.remove_title')}
                    description={t('user_policy.remove_description', { id: entry.handle ? `@${entry.handle}` : entry.user_id })}
                    confirmLabel={t('user_policy.remove')}
                    variant="destructive"
                    onConfirm={() => remove.mutateAsync(entry.user_id)}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function BulkCard({ policy }: { policy: UserPolicy }) {
  const { t } = useTranslation()
  const replace = useReplaceUserListMutation()
  const initial = listText(policy.entries)
  const [text, setText] = useState(initial)
  const invalid = replace.isError

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('user_policy.bulk')}</CardTitle>
        <CardDescription>{t('user_policy.bulk_description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            replace.mutate(text)
          }}
        >
          <Label htmlFor="user-policy-text">{t('user_policy.bulk_text')}</Label>
          <Textarea
            id="user-policy-text"
            className="min-h-40 font-mono text-xs"
            spellCheck={false}
            value={text}
            aria-invalid={invalid || undefined}
            aria-describedby={invalid ? 'user-policy-text-error' : undefined}
            onChange={event => setText(event.target.value)}
          />
          {invalid && (
            <p id="user-policy-text-error" role="alert" className="font-mono text-sm whitespace-pre-wrap text-destructive">
              {errorMessage(replace.error, t('common.error_generic'))}
            </p>
          )}
          <div>
            <Button type="submit" disabled={replace.isPending || text === initial}>{t('user_policy.bulk_save')}</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
