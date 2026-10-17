import { cleanup } from '@testing-library/react'
import i18n from '@/app/i18n'
import { mockFetch, resetMockState, server } from './server'
import '@testing-library/jest-dom/vitest'

vi.stubGlobal('fetch', mockFetch)

beforeEach(async () => {
  localStorage.clear()
  resetMockState()
  await i18n.changeLanguage('en')
})

afterEach(() => {
  cleanup()
  server.resetHandlers()
})
