import type * as React from 'react'

export function PageHeader({ title, actions }: { title: string, actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h1 className="font-heading text-xl font-semibold">{title}</h1>
      {actions}
    </div>
  )
}
