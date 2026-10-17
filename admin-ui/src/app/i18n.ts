import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'
import en from './locales/en.json'
import zhCN from './locales/zh-CN.json'

export const LANGUAGES = ['en', 'zh-CN'] as const
export type Language = (typeof LANGUAGES)[number]

// Resources are bundled: the hub serves the SPA from its binary, and only
// /admin/assets/ is guaranteed to be static.
void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      'en': { translation: en },
      'zh-CN': { translation: zhCN },
    },
    supportedLngs: [...LANGUAGES],
    fallbackLng: 'en',
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'gim-admin-lang',
      caches: ['localStorage'],
      convertDetectedLanguage: (lng: string) => (lng.toLowerCase().startsWith('zh') ? 'zh-CN' : lng),
    },
    interpolation: { escapeValue: false },
  })

i18n.on('languageChanged', (lng) => {
  document.documentElement.lang = lng
})

export default i18n
