import type * as React from 'react'

// A definition list of label/value pairs.
export function StatList({ items }: { items: [label: string, value: React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
      {items.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 font-mono text-sm break-all whitespace-pre-line">{value}</dd>
        </div>
      ))}
    </dl>
  )
}
