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

// The list carries the global restart_pending flag, so every change refetches it.
export function useSaveSettingMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (value: SettingValue) =>
      request<Setting>(`/settings/${encodeURIComponent(key)}`, { method: 'PUT', body: { value } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: settingsKey }),
  })
}

export function useResetSettingMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => request<Setting>(`/settings/${encodeURIComponent(key)}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: settingsKey }),
  })
}
