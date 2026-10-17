import { queryOptions, useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError, request } from '@/shared/lib/http'

export interface Session {
  actor: string
  auth: 'token' | 'header'
  csrf_token: string
  expires_at: number
}

interface LoginResponse {
  actor: string
  csrf_token: string
  expires_at: number
}

export const sessionKey = ['session'] as const

// Resolves to null when there is no session (401). In proxy-header mode the
// hub creates the session on this call.
export const sessionQueryOptions = queryOptions({
  queryKey: sessionKey,
  queryFn: async (): Promise<Session | null> => {
    try {
      return await request<Session>('/session', { allowUnauthorized: true })
    }
    catch (error) {
      if (error instanceof ApiError && error.status === 401)
        return null
      throw error
    }
  },
  staleTime: Infinity,
  retry: false,
})

export function useLoginMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (token: string) =>
      request<LoginResponse>('/login', { method: 'POST', body: { token }, allowUnauthorized: true }),
    onSuccess: (data) => {
      const session: Session = { ...data, auth: 'token' }
      queryClient.setQueryData(sessionQueryOptions.queryKey, session)
    },
  })
}

export function useLogoutMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => request<void>('/logout', { method: 'POST', allowUnauthorized: true }),
    onSettled: () => {
      queryClient.clear()
      queryClient.setQueryData(sessionQueryOptions.queryKey, null)
    },
  })
}
