import type { QueryClient } from '@tanstack/react-query'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export type SettingType
  = | 'string'
    | 'integer'
    | 'bool'
    | 'url'
    | 'duration_seconds'
    | 'list'
    | 'secret'
    | 'enum'

export type SettingValue = string | number | boolean | string[] | null

export interface Setting {
  key: string
  group: string
  type: SettingType
  enum: string[] | null
  description: string
  default: SettingValue
  // Always null for secrets; `is_set` tells whether one exists.
  value: SettingValue
  is_set: boolean
  source: 'env' | 'stored' | 'default'
  read_only: boolean
  apply: 'live' | 'restart'
  restart_pending: boolean
  updated_at: number | null
  updated_by: string | null
}

export interface SettingsList {
  items: Setting[]
  restart_pending: boolean
}

const settingsKey = ['settings'] as const

export function useSettingsQuery() {
  return useQuery({
    queryKey: settingsKey,
    queryFn: () => request<SettingsList>('/settings'),
  })
}

// The list carries the global restart_pending flag, and live settings show up
// in the overview and the effective configuration, so every change refetches them.
function invalidateAfterChange(queryClient: QueryClient) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: settingsKey }),
    queryClient.invalidateQueries({ queryKey: ['overview'] }),
    queryClient.invalidateQueries({ queryKey: ['config'] }),
  ])
}

export function useSaveSettingMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (value: SettingValue) =>
      request<Setting>(`/settings/${encodeURIComponent(key)}`, { method: 'PUT', body: { value } }),
    onSuccess: () => invalidateAfterChange(queryClient),
  })
}

export function useResetSettingMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => request<Setting>(`/settings/${encodeURIComponent(key)}`, { method: 'DELETE' }),
    onSuccess: () => invalidateAfterChange(queryClient),
  })
}
