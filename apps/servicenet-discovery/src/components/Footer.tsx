const LINKS = [
  { href: 'https://hs-df36fa00.mintlify.app/', label: 'Docs' },
  { href: 'https://github.com/wattetheria/watt-servicenet', label: 'GitHub' },
  { href: 'https://discord.gg/cyR9bxK2rm', label: 'Discord' },
]

export function Footer() {
  return (
    <footer className="flex shrink-0 items-center justify-between gap-4 border-t border-border bg-bg-0 px-4 py-3.5 lg:px-6">
      <span className="text-xs text-text-2">© 2026 Wattetheria ServiceNet</span>
      <nav className="flex items-center gap-5">
        {LINKS.map((link) => (
          <a
            key={link.label}
            href={link.href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-text-1 transition-colors hover:text-text-0"
          >
            {link.label}
            <svg
              width="10"
              height="10"
              viewBox="0 0 10 10"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.3"
              aria-hidden="true"
              className="opacity-60"
            >
              <path d="M3 7L7 3M7 3H3.5M7 3v3.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </a>
        ))}
      </nav>
    </footer>
  )
}
