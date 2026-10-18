import { createFileRoute } from '@tanstack/react-router'
import { UserPolicyPage } from '@/features/user-policy/user-policy-page'

export const Route = createFileRoute('/_authed/user-policy')({
  component: UserPolicyPage,
})
