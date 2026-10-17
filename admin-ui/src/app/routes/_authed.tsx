import { createFileRoute, redirect } from '@tanstack/react-router'
import { sessionQueryOptions } from '@/features/session/api'
import { AppShell } from '@/features/shell/app-shell'

export const Route = createFileRoute('/_authed')({
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQueryOptions)
    if (!session)
      throw redirect({ to: '/login' })
  },
  component: AppShell,
})
