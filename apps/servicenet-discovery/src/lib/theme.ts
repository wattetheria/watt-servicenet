export type Theme = 'light' | 'dark'

const STORAGE_KEY = 'servicenet-theme'

export function getInitialTheme(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'light' || saved === 'dark') return saved
    if (window.matchMedia('(prefers-color-scheme: light)').matches) return 'light'
  } catch {
    // localStorage / matchMedia unavailable — fall through to default.
  }
  return 'dark'
}

export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // Ignore persistence failures (private mode, etc.).
  }
}
