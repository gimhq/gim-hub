import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export interface LodeHistoryEntry {
  version: string
  at: string
  result: string
}

export type Lode
  = | { supervised: false }
    | {
      supervised: true
      status: string
      current: string
      available: string | null
      last_good: string | null
      last_check: string | null
      last_error: string | null
      history: LodeHistoryEntry[]
    }

export const lodeQueryOptions = queryOptions({
  queryKey: ['lode'],
  queryFn: () => request<Lode>('/lode'),
})

export function useLodeQuery() {
  return useQuery(lodeQueryOptions)
}

export type LodeAction
  = | { kind: 'check' }
    | { kind: 'update', version: string }
    | { kind: 'restart' }
    | { kind: 'rollback' }

export function useLodeActionMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (action: LodeAction) => {
      switch (action.kind) {
        case 'update':
          return request<void>('/lode/update', { method: 'POST', body: { version: action.version } })
        case 'rollback':
          return request<void>('/lode/rollback', { method: 'POST', body: {} })
        default:
          return request<void>(`/lode/${action.kind}`, { method: 'POST' })
      }
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['lode'] }),
  })
}
