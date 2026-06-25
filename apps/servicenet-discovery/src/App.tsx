import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import {
  listArdAgents,
  listServiceNetAgents,
  submitArdCatalog,
} from '@/api/servicenet'
import { Footer } from '@/components/Footer'
import { ThemeToggle } from '@/components/ThemeToggle'
import { applyTheme, getInitialTheme, type Theme } from '@/lib/theme'
import {
  ardToDiscovery,
  matchesAgent,
  serviceNetToDiscovery,
} from '@/lib/agents'
import type {
  ArdAgentRecord,
  DiscoveryAgent,
  InvocationProtocol,
  SubmitArdCatalogResponse,
} from '@/lib/types'

type View = 'native' | 'catalogs' | 'register'

const viewLabels: Record<View, string> = {
  native: 'Native',
  catalogs: 'Catalogs',
  register: 'Register',
}

const PAGE_SIZE = 20

interface PageMeta {
  offset: number
  limit: number
  count: number
  knownCount: number
  hasMore: boolean
}

interface SubmitCatalogForm {
  publisherDomain: string
  catalogUrl: string
}

const initialSubmitForm: SubmitCatalogForm = {
  publisherDomain: '',
  catalogUrl: '',
}

const protocolLabels: Record<InvocationProtocol, string> = {
  a2a: 'A2A',
  mcp: 'MCP',
  openapi: 'OpenAPI',
  unsupported: 'Unsupported',
}
function formatDate(value?: string): string {
  if (!value) return 'not recorded'
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value))
}

function App() {
  const [view, setView] = useState<View>('native')
  const [serviceNetAgents, setServiceNetAgents] = useState<DiscoveryAgent[]>([])
  const [ardAgents, setArdAgents] = useState<DiscoveryAgent[]>([])
  const [selectedNativeId, setSelectedNativeId] = useState<string | null>(null)
  const [selectedArdId, setSelectedArdId] = useState<string | null>(null)
  const [nativeQuery, setNativeQuery] = useState('')
  const [ardQuery, setArdQuery] = useState('')
  const [nativeOffset, setNativeOffset] = useState(0)
  const [ardOffset, setArdOffset] = useState(0)
  const [nativePage, setNativePage] = useState<PageMeta>({
    offset: 0,
    limit: PAGE_SIZE,
    count: 0,
    knownCount: 0,
    hasMore: false,
  })
  const [ardPage, setArdPage] = useState<PageMeta>({
    offset: 0,
    limit: PAGE_SIZE,
    count: 0,
    knownCount: 0,
    hasMore: false,
  })
  const [loadingNative, setLoadingNative] = useState(true)
  const [loadingArd, setLoadingArd] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitForm, setSubmitForm] = useState<SubmitCatalogForm>(initialSubmitForm)
  const [submitResult, setSubmitResult] = useState<SubmitArdCatalogResponse | null>(null)
  const [theme, setTheme] = useState<Theme>(getInitialTheme)

  function toggleTheme() {
    setTheme((current) => {
      const next = current === 'dark' ? 'light' : 'dark'
      applyTheme(next)
      return next
    })
  }

  const loadNative = useCallback(async () => {
    setLoadingNative(true)
    setError(null)
    try {
      const response = await listServiceNetAgents({
        limit: PAGE_SIZE,
        offset: nativeOffset,
      })
      setServiceNetAgents(response.items.map(serviceNetToDiscovery))
      setNativePage({
        offset: response.offset ?? nativeOffset,
        limit: response.limit ?? PAGE_SIZE,
        count: response.count ?? response.items.length,
        knownCount: response.known_count ?? response.items.length,
        hasMore: response.has_more ?? false,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load native agents')
    } finally {
      setLoadingNative(false)
    }
  }, [nativeOffset])

  const loadArd = useCallback(async () => {
    setLoadingArd(true)
    setError(null)
    try {
      const response = await listArdAgents({
        limit: PAGE_SIZE,
        offset: ardOffset,
        q: ardQuery,
      })
      setArdAgents(response.items.map(ardToDiscovery))
      setArdPage({
        offset: response.offset ?? ardOffset,
        limit: response.limit ?? PAGE_SIZE,
        count: response.count ?? response.items.length,
        knownCount: response.known_count ?? response.items.length,
        hasMore: response.has_more ?? false,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load ARD catalogs')
    } finally {
      setLoadingArd(false)
    }
  }, [ardOffset, ardQuery])

  useEffect(() => {
    void loadNative()
  }, [loadNative])

  useEffect(() => {
    void loadArd()
  }, [loadArd])

  const filteredNativeAgents = useMemo(
    () => serviceNetAgents.filter((agent) => matchesAgent(agent, nativeQuery)),
    [nativeQuery, serviceNetAgents],
  )

  const selectedNativeAgent = useMemo(
    () =>
      filteredNativeAgents.find((agent) => agent.id === selectedNativeId) ??
      filteredNativeAgents[0] ??
      null,
    [filteredNativeAgents, selectedNativeId],
  )

  const selectedArdAgent = useMemo(
    () => ardAgents.find((agent) => agent.id === selectedArdId) ?? ardAgents[0] ?? null,
    [ardAgents, selectedArdId],
  )

  const metrics = {
    total: nativePage.knownCount + ardPage.knownCount,
    native: nativePage.knownCount,
    ard: ardPage.knownCount,
    page: view === 'catalogs' ? ardPage.count : nativePage.count,
  }

  async function handleSubmitCatalog(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    setSubmitResult(null)
    try {
      const result = await submitArdCatalog({
        publisher_domain: submitForm.publisherDomain.trim().toLowerCase(),
        catalog_url: submitForm.catalogUrl.trim() || undefined,
      })
      setSubmitResult(result)
      setArdOffset(0)
      setView('catalogs')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to submit ARD catalog')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex h-screen flex-col bg-bg-0 text-text-0">
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[260px_1fr]">
        <aside className="hidden border-r-2 border-border bg-bg-1 lg:block">
          <div className="flex h-full flex-col">
            <div className="border-b-2 border-border p-5">
              <div className="flex items-center gap-3">
                <span
                  className="block h-11 w-11 shrink-0 overflow-hidden rounded-lg border border-border"
                  style={{ background: '#060A12' }}
                >
                  <img
                    src="/logo.png"
                    alt="Wattetheria"
                    className="h-full w-full object-cover"
                  />
                </span>
                <div>
                  <div className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
                    Wattetheria
                  </div>
                  <h1 className="mt-1 text-2xl font-bold tracking-normal">ServiceNet</h1>
                </div>
              </div>
            </div>
            <nav className="flex flex-col gap-2 p-4">
              {(['native', 'catalogs', 'register'] as View[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  className={`pixel-btn h-11 px-4 text-left uppercase ${view === item ? 'pixel-btn-active' : ''
                    }`}
                  onClick={() => setView(item)}
                >
                  {viewLabels[item]}
                </button>
              ))}
            </nav>
          </div>
        </aside>

        <main className="flex min-w-0 flex-col overflow-hidden">
          <header className="border-b-2 border-border bg-bg-1">
            <div className="flex flex-col gap-3 p-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="font-mono text-xs uppercase tracking-[0.18em] text-text-1">
                  public registry
                </div>
                <div className="mt-1 text-xl font-bold">Wattetheria Agents Discovery Portal</div>
              </div>
              <div className="flex items-center gap-3">
                <div className="grid flex-1 grid-cols-4 gap-2 text-xs uppercase md:w-[520px]">
                  <Metric label="Total" value={metrics.total} />
                  <Metric label="Native" value={metrics.native} />
                  <Metric label="ARD" value={metrics.ard} />
                  <Metric label="Page" value={metrics.page} />
                </div>
                <ThemeToggle theme={theme} onToggle={toggleTheme} />
              </div>
              <div className="flex gap-2 lg:hidden">
                {(['native', 'catalogs', 'register'] as View[]).map((item) => (
                  <button
                    key={item}
                    type="button"
                    className={`pixel-btn h-10 flex-1 px-3 uppercase ${view === item ? 'pixel-btn-active' : ''
                      }`}
                    onClick={() => setView(item)}
                  >
                    {viewLabels[item]}
                  </button>
                ))}
              </div>
            </div>
          </header>

          {error && (
            <div className="border-b-2 border-red bg-red/10 px-4 py-3 font-mono text-sm text-red">
              {error}
            </div>
          )}

          <div className="min-h-0 flex-1 overflow-auto p-4 lg:p-6">
            {view === 'native' && (
              <AgentListView
                title="Native ServiceNet Agents"
                agents={filteredNativeAgents}
                loading={loadingNative}
                query={nativeQuery}
                queryPlaceholder="Search current native page"
                page={nativePage}
                selectedAgent={selectedNativeAgent}
                emptyTitle="No native agents matched"
                onQueryChange={setNativeQuery}
                onSelect={setSelectedNativeId}
                onPrev={() => setNativeOffset(Math.max(0, nativePage.offset - nativePage.limit))}
                onNext={() => setNativeOffset(nativePage.offset + nativePage.limit)}
              />
            )}
            {view === 'catalogs' && (
              <AgentListView
                title="ARD Catalog Agents"
                agents={ardAgents}
                loading={loadingArd}
                query={ardQuery}
                queryPlaceholder="Search ARD agents, publishers, capabilities"
                page={ardPage}
                selectedAgent={selectedArdAgent}
                emptyTitle="No ARD agents matched"
                actionLabel="Register"
                onAction={() => setView('register')}
                onQueryChange={(value) => {
                  setArdQuery(value)
                  setArdOffset(0)
                }}
                onSelect={setSelectedArdId}
                onPrev={() => setArdOffset(Math.max(0, ardPage.offset - ardPage.limit))}
                onNext={() => setArdOffset(ardPage.offset + ardPage.limit)}
              />
            )}
            {view === 'register' && (
              <SubmitCatalogView
                form={submitForm}
                submitting={submitting}
                result={submitResult}
                onChange={(patch) => setSubmitForm((current) => ({ ...current, ...patch }))}
                onSubmit={handleSubmitCatalog}
              />
            )}
          </div>
        </main>
      </div>
      <Footer />
    </div>
  )
}

interface MetricProps {
  label: string
  value: number
}

function Metric({ label, value }: MetricProps) {
  return (
    <div className="game-panel px-3 py-2">
      <div className="font-mono text-[10px] text-text-2">{label}</div>
      <div className="mt-1 text-lg font-bold text-text-0">{value}</div>
    </div>
  )
}

interface AgentListViewProps {
  title: string
  agents: DiscoveryAgent[]
  loading: boolean
  query: string
  queryPlaceholder: string
  page: PageMeta
  selectedAgent: DiscoveryAgent | null
  emptyTitle: string
  actionLabel?: string
  onQueryChange: (value: string) => void
  onSelect: (id: string) => void
  onPrev: () => void
  onNext: () => void
  onAction?: () => void
}

function AgentListView({
  title,
  agents,
  loading,
  query,
  queryPlaceholder,
  page,
  selectedAgent,
  emptyTitle,
  actionLabel,
  onQueryChange,
  onSelect,
  onPrev,
  onNext,
  onAction,
}: AgentListViewProps) {
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
      <section className="min-w-0">
        <div className="game-panel p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="section-title">{title}</div>
            <div className="font-mono text-xs uppercase text-text-2">
              {page.knownCount} indexed
            </div>
          </div>
          <div className={`grid gap-3 ${actionLabel ? 'lg:grid-cols-[1fr_128px]' : 'lg:grid-cols-1'}`}>
            <input
              className="pixel-input h-11"
              value={query}
              onChange={(event) => onQueryChange(event.target.value)}
              placeholder={queryPlaceholder}
            />
            {actionLabel && onAction && (
              <button type="button" className="pixel-btn pixel-btn-active h-11" onClick={onAction}>
                {actionLabel}
              </button>
            )}
          </div>
        </div>

        <div className="mt-4 grid gap-3">
          {loading && <EmptyState title="Loading registry" />}
          {!loading && agents.length === 0 && <EmptyState title={emptyTitle} />}
          {agents.map((agent) => (
            <button
              key={`${agent.source}-${agent.id}`}
              type="button"
              className={`agent-row text-left ${selectedAgent?.id === agent.id ? 'agent-row-active' : ''
                }`}
              onClick={() => onSelect(agent.id)}
            >
              <div className="flex min-w-0 flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`source-pill source-${agent.source}`}>
                      {agent.source === 'ard' ? 'ARD' : 'ServiceNet'}
                    </span>
                    <span className="source-pill">{protocolLabels[agent.protocol]}</span>
                    <span className={`status-pill status-${agent.status}`}>{agent.status}</span>
                  </div>
                  <h2 className="mt-3 truncate text-lg font-bold">{agent.title}</h2>
                  <p className="mt-2 line-clamp-2 text-sm leading-6 text-text-1">
                    {agent.description}
                  </p>
                </div>
                <div className="grid shrink-0 grid-cols-2 gap-2 text-xs uppercase text-text-1 lg:w-52">
                  <div>
                    <div className="font-mono text-text-2">Publisher</div>
                    <div className="truncate text-text-0">{agent.publisher}</div>
                  </div>
                  <div>
                    <div className="font-mono text-text-2">Version</div>
                    <div className="truncate text-text-0">{agent.version}</div>
                  </div>
                </div>
              </div>
            </button>
          ))}
        </div>
        <Pagination page={page} onPrev={onPrev} onNext={onNext} />
      </section>

      <AgentDetails agent={selectedAgent} />
    </div>
  )
}

function Pagination({
  page,
  onPrev,
  onNext,
}: {
  page: PageMeta
  onPrev: () => void
  onNext: () => void
}) {
  const start = page.knownCount === 0 ? 0 : page.offset + 1
  const end = page.offset + page.count
  return (
    <div className="mt-4 flex flex-col gap-3 rounded-lg border border-border bg-bg-1 p-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="font-mono text-xs uppercase text-text-2">
        {start}-{end} of {page.knownCount}
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          className="pixel-btn h-10 px-4 uppercase"
          disabled={page.offset === 0}
          onClick={onPrev}
        >
          Previous
        </button>
        <button
          type="button"
          className="pixel-btn h-10 px-4 uppercase"
          disabled={!page.hasMore}
          onClick={onNext}
        >
          Next
        </button>
      </div>
    </div>
  )
}

interface AgentDetailsProps {
  agent: DiscoveryAgent | null
}

function AgentDetails({ agent }: AgentDetailsProps) {
  if (!agent) {
    return <EmptyState title="Select an agent" />
  }
  const isArd = agent.source === 'ard'
  const ard = isArd ? (agent.raw as ArdAgentRecord) : null
  const nativeInvoke =
    agent.source === 'servicenet' && 'invoke' in agent.raw ? agent.raw.invoke?.sync_url : undefined

  return (
    <aside className="game-panel sticky top-0 h-fit p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-mono text-xs uppercase tracking-[0.16em] text-accent">
            {agent.source === 'ard' ? 'ARD Agent' : 'ServiceNet Agent'}
          </div>
          <h2 className="mt-2 text-xl font-bold">{agent.title}</h2>
        </div>
        <span className={`status-pill status-${agent.status}`}>{agent.status}</span>
      </div>
      <p className="mt-4 text-sm leading-6 text-text-1">{agent.description}</p>

      <div className="mt-5 grid gap-3 text-sm">
        <Detail label="Publisher" value={agent.publisher} />
        <Detail label="Protocol" value={protocolLabels[agent.protocol]} />
        <Detail label="Version" value={agent.version} />
        <Detail label="Updated" value={formatDate(agent.updatedAt)} />
        {ard && <Detail label="Identifier" value={ard.identifier} />}
        {ard && <Detail label="Artifact" value={ard.artifact_type} />}
      </div>

      <div className="mt-5">
        <div className="font-mono text-xs uppercase text-text-2">Capabilities</div>
        <div className="mt-2 flex flex-wrap gap-2">
          {agent.capabilities.length === 0 && <span className="text-sm text-text-2">none</span>}
          {agent.capabilities.map((capability) => (
            <span key={capability} className="source-pill">
              {capability}
            </span>
          ))}
        </div>
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {nativeInvoke && (
          <a className="pixel-btn pixel-btn-active px-4 py-2 uppercase" href={nativeInvoke}>
            Invoke
          </a>
        )}
      </div>
    </aside>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-border/70 pb-2">
      <div className="font-mono text-xs uppercase text-text-2">{label}</div>
      <div className="mt-1 break-words text-text-0">{value}</div>
    </div>
  )
}

interface SubmitCatalogViewProps {
  form: SubmitCatalogForm
  submitting: boolean
  result: SubmitArdCatalogResponse | null
  onChange: (patch: Partial<SubmitCatalogForm>) => void
  onSubmit: (event: FormEvent) => void
}

function SubmitCatalogView({
  form,
  submitting,
  result,
  onChange,
  onSubmit,
}: SubmitCatalogViewProps) {
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
      <form className="game-panel p-5" onSubmit={onSubmit}>
        <div className="section-title">ARD Catalog Registration</div>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-text-1">
          Register a public ARD catalog so ServiceNet can discover and list the agents
          published by your domain.
        </p>
        <div className="mt-5 grid gap-4">
          <Field label="Publisher Domain">
            <input
              required
              className="pixel-input h-11 w-full"
              value={form.publisherDomain}
              onChange={(event) => onChange({ publisherDomain: event.target.value })}
              placeholder="example.com"
            />
          </Field>
          <Field label="Catalog URL">
            <input
              className="pixel-input h-11 w-full"
              value={form.catalogUrl}
              onChange={(event) => onChange({ catalogUrl: event.target.value })}
              placeholder="https://example.com/.well-known/ai-catalog.json"
            />
          </Field>
        </div>
        <div className="mt-5 flex justify-end">
          <button
            type="submit"
            className="pixel-btn pixel-btn-active h-12 px-6 uppercase"
            disabled={submitting}
          >
            {submitting ? 'Registering' : 'Register ARD Catalog'}
          </button>
        </div>
      </form>

      <aside className="game-panel p-5">
        <div className="section-title">About ARD Registration</div>
        <div className="mt-5 grid gap-4 text-sm leading-6 text-text-1">
          <InfoBlock
            title="What gets registered"
            body="ServiceNet stores the publisher domain and the public ai-catalog.json URL. Agents declared in that catalog are indexed for discovery."
          />
          <InfoBlock
            title="Catalog location"
            body="Use a public HTTPS URL. When Catalog URL is empty, ServiceNet reads https://{domain}/.well-known/ai-catalog.json."
          />
          <InfoBlock
            title="Discovery scope"
            body="ServiceNet lists ARD agents, metadata, capabilities, artifact references, and trust metadata. It does not take ownership of the agent runtime."
          />
          <InfoBlock
            title="Invocation and auth"
            body="Calling an ARD agent follows the publisher's ARD metadata. Runtime authentication and authorization stay between the caller and the publisher."
          />
          <InfoBlock
            title="Updates"
            body="After registration, ServiceNet refreshes the catalog in the background and updates the public directory from the latest catalog content."
          />
        </div>
        {result && (
          <div className="mt-5 rounded-lg border border-border bg-bg-2 p-3 text-sm leading-6 text-text-1">
            Registered <span className="font-medium text-text-0">{result.source.publisher_domain}</span>
            {' '}with status <span className="font-medium text-text-0">{result.source.status}</span>.
          </div>
        )}
      </aside>
    </div>
  )
}

function InfoBlock({ title, body }: { title: string; body: string }) {
  return (
    <div className="border-b border-border/70 pb-3 last:border-b-0 last:pb-0">
      <div className="font-mono text-xs uppercase tracking-[0.12em] text-text-2">{title}</div>
      <div className="mt-1 text-text-1">{body}</div>
    </div>
  )
}

function Field({
  label,
  wide,
  children,
}: {
  label: string
  wide?: boolean
  children: React.ReactNode
}) {
  return (
    <label className={wide ? 'lg:col-span-2' : ''}>
      <span className="mb-2 block font-mono text-xs uppercase tracking-[0.14em] text-text-1">
        {label}
      </span>
      {children}
    </label>
  )
}

function EmptyState({ title }: { title: string }) {
  return (
    <div className="game-panel flex min-h-40 items-center justify-center p-6 text-center">
      <div className="font-mono text-sm uppercase tracking-[0.14em] text-text-1">{title}</div>
    </div>
  )
}

export default App
