import { ApiError } from './http'

// The envelope message of an API error, or the fallback for anything else.
export function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}
