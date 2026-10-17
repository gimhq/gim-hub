// Timestamps from the admin API are unix seconds; lode state.json uses strings.
export function toDate(value: number | string | null | undefined): Date | null {
  if (value === null || value === undefined || value === '')
    return null
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatDateTime(value: number | string | null | undefined, locale: string): string {
  const date = toDate(value)
  return date ? date.toLocaleString(locale) : '—'
}

export function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value)
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']

export function formatBytes(bytes: number, locale: string): string {
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit++
  }
  const digits = unit === 0 ? 0 : 1
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: digits }).format(value)} ${UNITS[unit]}`
}

export function splitDuration(totalSeconds: number) {
  const s = Math.max(0, Math.floor(totalSeconds))
  return {
    days: Math.floor(s / 86400),
    hours: Math.floor((s % 86400) / 3600),
    minutes: Math.floor((s % 3600) / 60),
  }
}
