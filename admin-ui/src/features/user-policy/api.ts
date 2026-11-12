import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from '@/shared/lib/http'

export type UserPolicyMode = 'open' | 'allow' | 'deny'

// The setting that selects the mode; edited through the settings API.
export const MODE_KEY = 'GIM_HUB_USER_POLICY'

export interface UserPolicyEntry {
  user_id: string
  added_at: number | string
  added_by: string
  note: string | null
}

export interface UserPolicy {
  mode: UserPolicyMode
  // "env" when GIM_HUB_USER_POLICY is set in the environment: read-only here.
  mode_source: 'env' | 'stored' | 'default'
  // Users of this hub the mode in force does not admit.
  not_admitted_users: number
  entries: UserPolicyEntry[]
}

export interface UserPolicyAdd {
  user_id: string
  note?: string
}

const policyKey = ['user-policy'] as const

export function useUserPolicyQuery() {
  return useQuery({
    queryKey: policyKey,
    queryFn: () => request<UserPolicy>('/users/policy'),
  })
}

// Every change applies at once and may sign users out, so the user list and
// the overview are refetched too.
function useApply() {
  const queryClient = useQueryClient()
  return (data: UserPolicy) => {
    queryClient.setQueryData(policyKey, data)
    void queryClient.invalidateQueries({ queryKey: ['users'] })
    void queryClient.invalidateQueries({ queryKey: ['overview'] })
  }
}

export function useReplaceUserListMutation() {
  const apply = useApply()
  return useMutation({
    mutationFn: (text: string) => request<UserPolicy>('/users/policy', { method: 'PUT', body: { text } }),
    onSuccess: apply,
  })
}

export function useAddUserMutation() {
  const apply = useApply()
  return useMutation({
    mutationFn: (body: UserPolicyAdd) =>
      request<UserPolicy>('/users/policy/entries', { method: 'POST', body }),
    onSuccess: apply,
  })
}

export function useRemoveUserMutation() {
  const apply = useApply()
  return useMutation({
    mutationFn: (userId: string) =>
      request<UserPolicy>(`/users/policy/entries/${encodeURIComponent(userId)}`, { method: 'DELETE' }),
    onSuccess: apply,
  })
}

export function addTarget(input: string, note: string): UserPolicyAdd {
  const extra = note.trim() ? { note: note.trim() } : {}
  return { user_id: input.trim(), ...extra }
}

// The list in the PUT text format: one user ID per line.
export function listText(entries: UserPolicyEntry[]): string {
  return entries.map(entry => `${entry.user_id}\n`).join('')
}
