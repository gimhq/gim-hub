import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export interface UserSummary {
  user_id: string
  handle: string | null
  suspended: boolean
  created_at: number | string
  device_count: number
  last_seen: number | string | null
}

export interface DeviceSession {
  session_ref: string
  created_at: number | string
  expires_at: number | string
}

export interface Device {
  device_id: string
  created_at: number | string
  last_seen: number | string | null
  active: boolean
  sessions: DeviceSession[]
}

export interface UserDetail {
  user_id: string
  handle: string | null
  suspended: boolean
  suspended_at: number | string | null
  created_at: number | string
  hosting_hubs: string[]
  devices: Device[]
}

interface Page<T> {
  items: T[]
  next_cursor: string | null
}

const PAGE_SIZE = 50

export function useUsersQuery(q: string) {
  return useInfiniteQuery({
    queryKey: ['users', 'list', q],
    queryFn: ({ pageParam }) =>
      request<Page<UserSummary>>('/users', { query: { q, limit: PAGE_SIZE, cursor: pageParam } }),
    initialPageParam: null as string | null,
    getNextPageParam: last => last.next_cursor,
  })
}

const userKey = (userId: string) => ['users', 'detail', userId] as const

export function useUserQuery(userId: string) {
  return useQuery({
    queryKey: userKey(userId),
    queryFn: () => request<UserDetail>(`/users/${encodeURIComponent(userId)}`),
  })
}

function useUserMutation<TVars, TResult = void>(fn: (vars: TVars) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useSuspendMutation(userId: string) {
  return useUserMutation((reason: string) =>
    request<void>(`/users/${encodeURIComponent(userId)}/suspend`, {
      method: 'POST',
      body: reason ? { reason } : {},
    }))
}

export function useUnsuspendMutation(userId: string) {
  return useUserMutation((_: void) =>
    request<void>(`/users/${encodeURIComponent(userId)}/unsuspend`, { method: 'POST' }))
}

export function useRevokeSessionsMutation(userId: string) {
  return useUserMutation((deviceId: string) =>
    request<{ revoked: number }>(
      `/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(deviceId)}/sessions`,
      { method: 'DELETE' },
    ))
}

export function useReleaseHandleMutation() {
  return useUserMutation((handle: string) =>
    request<void>(`/handles/${encodeURIComponent(handle)}/release`, { method: 'POST' }))
}
