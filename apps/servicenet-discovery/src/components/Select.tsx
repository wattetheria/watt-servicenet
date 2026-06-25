import { useEffect, useId, useRef, useState } from 'react'

export interface SelectOption<T extends string> {
  value: T
  label: string
}

interface SelectProps<T extends string> {
  value: T
  options: SelectOption<T>[]
  onChange: (value: T) => void
  className?: string
  ariaLabel?: string
}

// Themed dropdown that replaces the native <select>. The native control's open
// option list is painted by the OS and can't be styled, so we render our own
// listbox to keep the dark/cyber look consistent and add keyboard support.
export function Select<T extends string>({
  value,
  options,
  onChange,
  className = '',
  ariaLabel,
}: SelectProps<T>) {
  const [open, setOpen] = useState(false)
  const [highlight, setHighlight] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const listId = useId()

  const selectedIndex = Math.max(
    0,
    options.findIndex((option) => option.value === value),
  )
  const selected = options[selectedIndex]

  useEffect(() => {
    if (!open) return
    setHighlight(selectedIndex)
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open, selectedIndex])

  function commit(index: number) {
    const option = options[index]
    if (option) onChange(option.value)
    setOpen(false)
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === 'Escape') {
      setOpen(false)
      return
    }
    if (!open) {
      if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        setOpen(true)
      }
      return
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setHighlight((current) => Math.min(options.length - 1, current + 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setHighlight((current) => Math.max(0, current - 1))
    } else if (event.key === 'Home') {
      event.preventDefault()
      setHighlight(0)
    } else if (event.key === 'End') {
      event.preventDefault()
      setHighlight(options.length - 1)
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      commit(highlight)
    }
  }

  return (
    <div ref={rootRef} className={`relative ${className}`}>
      <button
        type="button"
        className="pixel-input flex h-full w-full items-center justify-between gap-2 text-left"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-label={ariaLabel}
        onClick={() => setOpen((current) => !current)}
        onKeyDown={onKeyDown}
      >
        <span className="truncate">{selected?.label ?? ''}</span>
        <svg
          width="12"
          height="12"
          viewBox="0 0 12 12"
          aria-hidden="true"
          className={`shrink-0 text-text-1 transition-transform duration-150 ${open ? 'rotate-180' : ''}`}
        >
          <path
            d="M2 4.5l4 4 4-4"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="square"
          />
        </svg>
      </button>

      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-label={ariaLabel}
          className="absolute left-0 right-0 top-[calc(100%+4px)] z-50 max-h-64 overflow-auto rounded-panel border border-border-light bg-bg-1 py-1 shadow-[0_8px_28px_rgba(0,0,0,0.18)]"
        >
          {options.map((option, index) => {
            const isSelected = option.value === value
            const isActive = index === highlight
            return (
              <li key={option.value} role="option" aria-selected={isSelected}>
                <button
                  type="button"
                  className={`flex w-full items-center gap-2 px-3 py-2 text-left font-mono text-sm ${
                    isActive ? 'bg-bg-3' : ''
                  } ${isSelected ? 'text-accent' : 'text-text-1'}`}
                  onMouseEnter={() => setHighlight(index)}
                  onClick={() => commit(index)}
                >
                  <span className="w-3 shrink-0 text-accent">{isSelected ? '✓' : ''}</span>
                  <span className="truncate">{option.label}</span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
