import { QueryClient } from '@tanstack/react-query'
import { ApiError } from '@/shared/lib/http'

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        // Never retry client errors (401, 403, 404, ...).
        retry: (count, error) => !(error instanceof ApiError && error.status < 500) && count < 1,
      },
    },
  })
}
