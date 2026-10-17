import { createFileRoute } from '@tanstack/react-router'
import { ConfigPage } from '@/features/config/config-page'

export const Route = createFileRoute('/_authed/config')({
  component: ConfigPage,
})
