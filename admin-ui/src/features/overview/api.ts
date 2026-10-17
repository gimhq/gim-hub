import { queryOptions, useQuery } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export interface PushCounters {
  enqueued: number
  coalesced: number
  upgraded: number
  dropped: number
  sent: number
  skipped: number
  invalid_token: number
  retried: number
  failed: number
}

export interface Overview {
  version: string
  revision: string
  hub_id: string
  public_url: string | null
  started_at: number | string
  uptime_seconds: number
  storage: { db_bytes: number, blob_bytes: number }
  counts: { users: number, devices: number, groups: number, blobs: number }
  push: PushCounters
  event_retention_days: number
}

export const overviewQueryOptions = queryOptions({
  queryKey: ['overview'],
  queryFn: () => request<Overview>('/overview'),
})

export function useOverviewQuery() {
  return useQuery(overviewQueryOptions)
}
