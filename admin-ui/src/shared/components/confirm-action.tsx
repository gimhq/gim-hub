import type * as React from 'react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ErrorAlert } from '@/shared/components/error-alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/shared/components/ui/alert-dialog'
import { Button } from '@/shared/components/ui/button'

interface ConfirmActionProps {
  trigger: React.ReactNode
  title: string
  description: string
  confirmLabel: string
  onConfirm: () => Promise<unknown>
  variant?: React.ComponentProps<typeof Button>['variant']
  disabled?: boolean
  children?: React.ReactNode
}

// A button that opens a confirmation dialog. The dialog stays open and shows
// the error envelope message when the action fails.
export function ConfirmAction({
  trigger,
  title,
  description,
  confirmLabel,
  onConfirm,
  variant = 'outline',
  disabled,
  children,
}: ConfirmActionProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)

  async function confirm() {
    setPending(true)
    setError(null)
    try {
      await onConfirm()
      setOpen(false)
    }
    catch (err) {
      setError(err)
    }
    finally {
      setPending(false)
    }
  }

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (next)
          setError(null)
      }}
    >
      <AlertDialogTrigger
        disabled={disabled}
        render={<Button variant={variant} size="sm" />}
      >
        {trigger}
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {children}
        {error !== null && <ErrorAlert error={error} />}
        <AlertDialogFooter>
          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
          <AlertDialogAction
            variant={variant === 'destructive' ? 'destructive' : 'default'}
            disabled={pending}
            onClick={() => void confirm()}
          >
            {confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
