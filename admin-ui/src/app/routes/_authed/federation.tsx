import { createFileRoute } from '@tanstack/react-router'
import { FederationPage } from '@/features/federation/federation-page'

export const Route = createFileRoute('/_authed/federation')({
  component: FederationPage,
})
