import { useQuery } from '@tanstack/react-query'
import { Link, Navigate, Outlet, useNavigate } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { lodeQueryOptions } from '@/features/lode/api'
import { sessionQueryOptions, useLogoutMutation } from '@/features/session/api'
import { Button } from '@/shared/components/ui/button'
import { ModeToggle } from '@/shared/theme/mode-toggle'
import { LanguageSwitch } from './language-switch'

const linkClass
  = 'rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 outline-none data-[status=active]:bg-muted data-[status=active]:text-foreground'

export function AppShell() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useQuery(sessionQueryOptions)
  const lode = useQuery(lodeQueryOptions)
  const logout = useLogoutMutation()

  // The session can disappear after a 401 or a failed CSRF refetch.
  if (session.data === null)
    return <Navigate to="/login" />

  return (
    <div className="flex min-h-svh flex-col">
      <header className="flex flex-wrap items-center gap-2 border-b px-4 py-2">
        <span className="mr-4 font-heading font-semibold">{t('app.title')}</span>
        <nav aria-label={t('app.nav')} className="flex flex-1 flex-wrap gap-1">
          <Link to="/" className={linkClass} activeOptions={{ exact: true }}>{t('nav.overview')}</Link>
          <Link to="/users" className={linkClass}>{t('nav.users')}</Link>
          <Link to="/federation" className={linkClass}>{t('nav.federation')}</Link>
          {lode.data?.supervised && <Link to="/lode" className={linkClass}>{t('nav.lode')}</Link>}
          <Link to="/config" className={linkClass}>{t('nav.config')}</Link>
          <Link to="/audit" className={linkClass}>{t('nav.audit')}</Link>
        </nav>
        <span className="text-xs text-muted-foreground">{session.data?.actor}</span>
        <LanguageSwitch />
        <ModeToggle />
        <Button
          variant="outline"
          size="sm"
          disabled={logout.isPending}
          onClick={() => logout.mutate(undefined, { onSettled: () => void navigate({ to: '/login' }) })}
        >
          {t('app.logout')}
        </Button>
      </header>
      <main className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-4">
        <Outlet />
      </main>
    </div>
  )
}
