import { createFileRoute } from '@tanstack/react-router'
import { UsersPage } from '@/features/users/users-page'

interface UsersSearch {
  q?: string
}

export const Route = createFileRoute('/_authed/users/')({
  validateSearch: (search: Record<string, unknown>): UsersSearch =>
    typeof search.q === 'string' && search.q ? { q: search.q } : {},
  component: UsersPage,
})
