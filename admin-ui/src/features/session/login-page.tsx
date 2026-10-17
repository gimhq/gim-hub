import { useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { LanguageSwitch } from '@/features/shell/language-switch'
import { ErrorAlert } from '@/shared/components/error-alert'
import { Button } from '@/shared/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/components/ui/card'
import { Input } from '@/shared/components/ui/input'
import { Label } from '@/shared/components/ui/label'
import { useLoginMutation } from './api'

export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useLoginMutation()
  const [token, setToken] = useState('')

  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-4 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>{t('login.title')}</CardTitle>
          <CardDescription>{t('login.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-3"
            onSubmit={(event) => {
              event.preventDefault()
              login.mutate(token.trim(), {
                onSuccess: () => {
                  setToken('')
                  void navigate({ to: '/' })
                },
              })
            }}
          >
            <Label htmlFor="admin-token">{t('login.token')}</Label>
            <Input
              id="admin-token"
              type="password"
              autoComplete="current-password"
              required
              value={token}
              onChange={event => setToken(event.target.value)}
            />
            {login.isError && <ErrorAlert error={login.error} />}
            <Button type="submit" disabled={login.isPending || !token.trim()}>
              {t('login.submit')}
            </Button>
          </form>
        </CardContent>
      </Card>
      <LanguageSwitch />
    </main>
  )
}
