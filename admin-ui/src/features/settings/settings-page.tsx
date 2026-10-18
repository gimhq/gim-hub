import type { TFunction } from 'i18next'
import type { Setting, SettingValue } from './api'
import { RotateCw } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLodeActionMutation, useLodeQuery } from '@/features/lode/api'
import { ConfirmAction } from '@/shared/components/confirm-action'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Loading } from '@/shared/components/loading'
import { PageHeader } from '@/shared/components/page-header'
import { Alert, AlertDescription, AlertTitle } from '@/shared/components/ui/alert'
import { Badge } from '@/shared/components/ui/badge'
import { Button } from '@/shared/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Input } from '@/shared/components/ui/input'
import { Label } from '@/shared/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/shared/components/ui/select'
import { Switch } from '@/shared/components/ui/switch'
import { Textarea } from '@/shared/components/ui/textarea'
import { errorMessage } from '@/shared/lib/error-message'
import { formatDateTime } from '@/shared/lib/format'
import { useResetSettingMutation, useSaveSettingMutation, useSettingsQuery } from './api'

export function SettingsPage() {
  const { t } = useTranslation()
  const settings = useSettingsQuery()

  return (
    <>
      <PageHeader title={t('nav.settings')} />
      <p className="text-sm text-muted-foreground">{t('settings.description')}</p>
      {settings.isPending
        ? <Loading />
        : settings.error
          ? <ErrorAlert error={settings.error} />
          : (
              <>
                {settings.data.restart_pending && <RestartBanner />}
                {groupBy(settings.data.items).map(([group, items]) => (
                  <Card key={group}>
                    <CardHeader>
                      <CardTitle>{t(`settings.groups.${group}`, { defaultValue: group })}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="flex flex-col divide-y">
                        {items.map(item => <SettingRow key={item.key} item={item} />)}
                      </ul>
                    </CardContent>
                  </Card>
                ))}
              </>
            )}
    </>
  )
}

// Groups in the order the API lists them.
function groupBy(items: Setting[]): [string, Setting[]][] {
  const groups = new Map<string, Setting[]>()
  for (const item of items)
    groups.set(item.group, [...(groups.get(item.group) ?? []), item])
  return [...groups]
}

function RestartBanner() {
  const { t } = useTranslation()
  const lode = useLodeQuery()
  const restart = useLodeActionMutation()
  const [requested, setRequested] = useState(false)

  return (
    <Alert>
      <RotateCw />
      <AlertTitle>{t('settings.restart_pending')}</AlertTitle>
      <AlertDescription className="flex flex-col gap-2">
        <span>{t('settings.restart_pending_description')}</span>
        {lode.data?.supervised
          ? (
              <div>
                <ConfirmAction
                  trigger={t('settings.restart_now')}
                  title={t('lode.restart_title')}
                  description={t('lode.restart_description')}
                  confirmLabel={t('settings.restart_now')}
                  onConfirm={async () => {
                    await restart.mutateAsync({ kind: 'restart' })
                    setRequested(true)
                  }}
                />
              </div>
            )
          : lode.data && <span className="font-medium">{t('settings.restart_manually')}</span>}
        {requested && <span role="status">{t('lode.requested_restart')}</span>}
      </AlertDescription>
    </Alert>
  )
}

function formatValue(item: Setting, value: SettingValue, t: TFunction): string {
  if (value === null)
    return '—'
  if (typeof value === 'boolean')
    return value ? t('settings.on') : t('settings.off')
  if (Array.isArray(value))
    return value.length ? value.join(', ') : '—'
  if (item.type === 'duration_seconds')
    return t('settings.seconds', { count: Number(value) })
  return String(value)
}

const sourceVariant = { env: 'default', stored: 'secondary', default: 'outline' } as const

function SettingRow({ item }: { item: Setting }) {
  const { t, i18n } = useTranslation()
  const reset = useResetSettingMutation(item.key)
  const [editing, setEditing] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const secret = item.type === 'secret'

  return (
    <li className="flex flex-col gap-1.5 py-3 first:pt-0 last:pb-0" aria-label={item.key}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-medium break-all">{item.key}</span>
        <Badge variant={sourceVariant[item.source]}>{t(`settings.source_${item.source}`)}</Badge>
        <Badge variant={item.apply === 'live' ? 'outline' : 'secondary'}>{t(`settings.apply_${item.apply}`)}</Badge>
        {item.restart_pending && <Badge variant="destructive">{t('settings.pending')}</Badge>}
      </div>
      <p className="text-sm text-muted-foreground">{item.description}</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
        <dt className="text-muted-foreground">{t('settings.value')}</dt>
        <dd className="font-mono break-all">
          {secret
            ? <Badge variant={item.is_set ? 'secondary' : 'outline'}>{item.is_set ? t('settings.secret_set') : t('settings.secret_unset')}</Badge>
            : formatValue(item, item.value, t)}
        </dd>
        {!secret && (
          <>
            <dt className="text-muted-foreground">{t('settings.default')}</dt>
            <dd className="font-mono break-all">{formatValue(item, item.default, t)}</dd>
          </>
        )}
        {item.updated_at !== null && (
          <>
            <dt className="text-muted-foreground">{t('settings.updated')}</dt>
            <dd>{t('settings.updated_value', { at: formatDateTime(item.updated_at, i18n.language), by: item.updated_by ?? '—' })}</dd>
          </>
        )}
      </dl>
      {item.read_only
        ? <p className="text-sm text-muted-foreground">{t('settings.set_by_env')}</p>
        : editing
          ? (
              <SettingEditor
                item={item}
                onCancel={() => setEditing(false)}
                onSaved={() => {
                  setEditing(false)
                  setNotice(t('settings.saved'))
                }}
              />
            )
          : (
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setNotice(null)
                    setEditing(true)
                  }}
                >
                  {secret ? t('settings.replace') : t('settings.edit')}
                </Button>
                <ConfirmAction
                  variant="destructive"
                  disabled={item.source !== 'stored'}
                  trigger={secret ? t('settings.clear') : t('settings.reset')}
                  title={secret ? t('settings.clear_title') : t('settings.reset_title')}
                  description={t(secret ? 'settings.clear_description' : 'settings.reset_description', {
                    key: item.key,
                    value: formatValue(item, item.default, t),
                  })}
                  confirmLabel={secret ? t('settings.clear') : t('settings.reset')}
                  onConfirm={async () => {
                    setNotice(null)
                    await reset.mutateAsync()
                    setNotice(secret ? t('settings.cleared') : t('settings.reset_done'))
                  }}
                />
                {notice && <span role="status" className="text-sm text-muted-foreground">{notice}</span>}
              </div>
            )}
    </li>
  )
}

function initialDraft(item: Setting): string | boolean {
  if (item.type === 'bool')
    return item.value === true
  if (item.type === 'secret' || item.value === null)
    return ''
  if (Array.isArray(item.value))
    return item.value.join('\n')
  return String(item.value)
}

// Converts the draft to the JSON value of the contract. Numbers that do not
// parse are sent as typed, so the hub's parser reports them (422).
function toValue(item: Setting, draft: string | boolean): SettingValue {
  if (typeof draft === 'boolean')
    return draft
  switch (item.type) {
    case 'integer':
    case 'duration_seconds':
      return /^-?\d+$/.test(draft.trim()) ? Number(draft.trim()) : draft
    case 'list':
      return draft.split('\n').map(line => line.trim()).filter(Boolean)
    default:
      return draft
  }
}

function SettingEditor({ item, onCancel, onSaved }: { item: Setting, onCancel: () => void, onSaved: () => void }) {
  const { t } = useTranslation()
  const save = useSaveSettingMutation(item.key)
  const [draft, setDraft] = useState(() => initialDraft(item))
  const id = `setting-${item.key}`
  const errorId = `${id}-error`
  const invalid = save.isError
  const label = t('settings.new_value_for', { key: item.key })
  const field = {
    'id': id,
    'aria-invalid': invalid || undefined,
    'aria-describedby': invalid ? errorId : undefined,
  }

  function editor() {
    switch (item.type) {
      case 'bool':
        return (
          <Switch
            {...field}
            aria-label={label}
            checked={draft === true}
            onCheckedChange={checked => setDraft(checked)}
          />
        )
      case 'enum':
        return (
          <Select value={String(draft)} onValueChange={value => setDraft(String(value ?? ''))}>
            <SelectTrigger {...field} aria-label={label} className="min-w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(item.enum ?? []).map(choice => <SelectItem key={choice} value={choice}>{choice}</SelectItem>)}
            </SelectContent>
          </Select>
        )
      case 'list':
        return (
          <Textarea
            {...field}
            className="min-h-24 font-mono text-xs"
            spellCheck={false}
            value={String(draft)}
            onChange={event => setDraft(event.target.value)}
          />
        )
      case 'integer':
      case 'duration_seconds':
        return (
          <Input
            {...field}
            type="number"
            step={1}
            className="max-w-60"
            value={String(draft)}
            onChange={event => setDraft(event.target.value)}
          />
        )
      case 'secret':
        return (
          <Input
            {...field}
            type="password"
            autoComplete="new-password"
            className="max-w-sm"
            value={String(draft)}
            onChange={event => setDraft(event.target.value)}
          />
        )
      default:
        return (
          <Input
            {...field}
            type="text"
            inputMode={item.type === 'url' ? 'url' : undefined}
            className="max-w-xl"
            value={String(draft)}
            onChange={event => setDraft(event.target.value)}
          />
        )
    }
  }

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(event) => {
        event.preventDefault()
        save.mutate(toValue(item, draft), { onSuccess: onSaved })
      }}
    >
      {item.type !== 'bool' && item.type !== 'enum' && <Label htmlFor={id}>{label}</Label>}
      {editor()}
      {item.type === 'list' && <p className="text-xs text-muted-foreground">{t('settings.list_hint')}</p>}
      {item.type === 'duration_seconds' && <p className="text-xs text-muted-foreground">{t('settings.duration_hint')}</p>}
      {invalid && (
        <p id={errorId} role="alert" className="font-mono text-sm whitespace-pre-wrap text-destructive">
          {errorMessage(save.error, t('common.error_generic'))}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={save.isPending || (item.type === 'secret' && draft === '')}>
          {t('settings.save')}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onCancel}>{t('common.cancel')}</Button>
      </div>
    </form>
  )
}
