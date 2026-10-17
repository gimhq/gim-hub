import { useQuery } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export interface ConfigItem {
  key: string
  value: string | null
  redacted: boolean
}

export function useConfigQuery() {
  return useQuery({
    queryKey: ['config'],
    queryFn: () => request<{ items: ConfigItem[] }>('/config'),
  })
}
