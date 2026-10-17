import type { QueryClient } from '@tanstack/react-query'
import type { RouterHistory } from '@tanstack/react-router'
import { createRouter } from '@tanstack/react-router'
import { sessionKey, sessionQueryOptions } from '@/features/session/api'
import { configureHttp } from '@/shared/lib/http'
import { routeTree } from './routeTree.gen'

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  const router = createRouter({
    routeTree,
    history,
    basepath: '/admin',
    context: { queryClient },
    defaultPreload: false,
  })

  configureHttp({
    getCsrfToken: () => queryClient.getQueryData(sessionQueryOptions.queryKey)?.csrf_token,
    onUnauthorized: () => {
      queryClient.setQueryData(sessionQueryOptions.queryKey, null)
      if (!router.state.matches.some(match => match.routeId === '/login'))
        void router.navigate({ to: '/login' })
    },
    onCsrfFailed: () => {
      void queryClient.invalidateQueries({ queryKey: sessionKey })
    },
  })

  return router
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>
  }
}
