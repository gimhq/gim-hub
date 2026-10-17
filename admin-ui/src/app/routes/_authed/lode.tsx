import { createFileRoute } from '@tanstack/react-router'
import { LodePage } from '@/features/lode/lode-page'

export const Route = createFileRoute('/_authed/lode')({
  component: LodePage,
})
