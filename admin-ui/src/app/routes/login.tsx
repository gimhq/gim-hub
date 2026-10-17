import { createFileRoute, redirect } from '@tanstack/react-router'
import { sessionQueryOptions } from '@/features/session/api'
import { LoginPage } from '@/features/session/login-page'

export const Route = createFileRoute('/login')({
  // A session that already exists (or one created from a trusted proxy
  // header) skips the token form.
  beforeLoad: async ({ context }) => {
    const session = await context.queryClient.ensureQueryData(sessionQueryOptions)
    if (session)
      throw redirect({ to: '/' })
  },
  component: LoginPage,
})
