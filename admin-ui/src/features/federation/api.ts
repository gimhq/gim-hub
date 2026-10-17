import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, request } from '@/shared/lib/http'

export interface FederationPeer {
  hub_id: string
  connected: boolean
  outbox_backlog: number
  last_error: string | null
  last_seen: number | string | null
}

export interface Federation {
  enabled: boolean
  peer_id: string | null
  listen_addrs: string[]
  external_addrs: string[]
  peers: FederationPeer[]
}

export interface Allowlist {
  path: string
  text: string
  entries: { hub_id: string, addrs: string[] }[]
}

export function useFederationQuery() {
  return useQuery({
    queryKey: ['federation'],
    queryFn: () => request<Federation>('/federation'),
  })
}

const allowlistKey = ['federation', 'allowlist'] as const

// Resolves to null when federation is off (404).
export const allowlistQueryOptions = queryOptions({
  queryKey: allowlistKey,
  queryFn: async (): Promise<Allowlist | null> => {
    try {
      return await request<Allowlist>('/federation/allowlist')
    }
    catch (error) {
      if (error instanceof ApiError && error.status === 404)
        return null
      throw error
    }
  },
})

export function useAllowlistQuery() {
  return useQuery(allowlistQueryOptions)
}

export function useSaveAllowlistMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (text: string) =>
      request<Allowlist>('/federation/allowlist', { method: 'PUT', body: { text } }),
    onSuccess: (data) => {
      queryClient.setQueryData(allowlistKey, data)
      void queryClient.invalidateQueries({ queryKey: ['federation'], exact: true })
    },
  })
}
