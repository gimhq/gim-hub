import { createMemoryHistory, RouterProvider } from '@tanstack/react-router'
import { render } from '@testing-library/react'
import { Providers } from '@/app/providers'
import { createQueryClient } from '@/app/query-client'
import { createAppRouter } from '@/app/router'

// Renders the whole app at `path` (relative to the /admin base path).
export function renderApp(path = '/') {
  const queryClient = createQueryClient()
  const history = createMemoryHistory({ initialEntries: [`/admin${path}`] })
  const router = createAppRouter(queryClient, history)
  const result = render(
    <Providers queryClient={queryClient}>
      <RouterProvider router={router} />
    </Providers>,
  )
  return { ...result, router, queryClient }
}
