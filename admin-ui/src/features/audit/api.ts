import { useInfiniteQuery } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export interface AuditEntry {
  id: number | string
  at: number | string
  actor: string
  action: string
  target: string | null
  source_ip: string
  result: 'ok' | 'error'
  detail: string | null
}

const PAGE_SIZE = 50

export function useAuditQuery() {
  return useInfiniteQuery({
    queryKey: ['audit'],
    queryFn: ({ pageParam }) =>
      request<{ items: AuditEntry[], next_cursor: string | null }>('/audit', {
        query: { limit: PAGE_SIZE, cursor: pageParam },
      }),
    initialPageParam: null as string | null,
    getNextPageParam: last => last.next_cursor,
  })
}
