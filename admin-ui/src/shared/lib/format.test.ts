import { formatBytes, formatDateTime, splitDuration, toDate } from './format'

describe('format', () => {
  it('reads unix seconds and ISO strings', () => {
    expect(toDate(1_000)?.toISOString()).toBe('1970-01-01T00:16:40.000Z')
    expect(toDate('2026-10-17T08:00:00Z')?.getUTCHours()).toBe(8)
    expect(toDate(null)).toBeNull()
    expect(toDate('garbage')).toBeNull()
    expect(formatDateTime(undefined, 'en')).toBe('—')
  })

  it('formats bytes and durations', () => {
    expect(formatBytes(512, 'en')).toBe('512 B')
    expect(formatBytes(1536, 'en')).toBe('1.5 KiB')
    expect(splitDuration(90_061)).toEqual({ days: 1, hours: 1, minutes: 1 })
  })
})
