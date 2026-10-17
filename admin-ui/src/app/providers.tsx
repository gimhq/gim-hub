import type { QueryClient } from '@tanstack/react-query'
import type * as React from 'react'
import { QueryClientProvider } from '@tanstack/react-query'
import { I18nextProvider } from 'react-i18next'
import { ThemeProvider } from '@/shared/theme/theme-provider'
import i18n from './i18n'

export function Providers({ queryClient, children }: { queryClient: QueryClient, children: React.ReactNode }) {
  return (
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>{children}</ThemeProvider>
      </QueryClientProvider>
    </I18nextProvider>
  )
}
