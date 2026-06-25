import type {
  ArdAgentRecord,
  CreateArdAgentRequest,
  ServiceNetAgent,
  SubmitArdCatalogRequest,
  SubmitArdCatalogResponse,
  UpdateArdAgentRequest,
} from '@/lib/types'

const API_BASE = import.meta.env.VITE_SERVICENET_API_BASE ?? '/api/servicenet'

interface ListResponse<T> {
  items: T[]
  count?: number
  limit?: number
  offset?: number
  next_offset?: number | null
  has_more?: boolean
  known_count?: number
}

export interface PageParams {
  limit: number
  offset: number
  q?: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers ?? {}),
    },
  })
  if (!response.ok) {
    let message = `request failed with ${response.status}`
    try {
      const body = (await response.json()) as { error?: string }
      if (body.error) message = body.error
    } catch {
      // Keep the HTTP status message.
    }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

export async function listServiceNetAgents(
  params: PageParams,
): Promise<ListResponse<ServiceNetAgent>> {
  const search = new URLSearchParams({
    limit: String(params.limit),
    offset: String(params.offset),
  })
  return request<ListResponse<ServiceNetAgent>>(`/v1/agents?${search.toString()}`)
}

export async function listArdAgents(
  params: PageParams,
): Promise<ListResponse<ArdAgentRecord>> {
  const search = new URLSearchParams({
    limit: String(params.limit),
    offset: String(params.offset),
  })
  const query = params.q?.trim()
  if (query) search.set('q', query)
  return request<ListResponse<ArdAgentRecord>>(`/v1/ard/agents?${search.toString()}`)
}

export async function createArdAgent(payload: CreateArdAgentRequest): Promise<ArdAgentRecord> {
  return request<ArdAgentRecord>('/v1/ard/agents', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function updateArdAgent(
  ardAgentId: string,
  payload: UpdateArdAgentRequest,
): Promise<ArdAgentRecord> {
  return request<ArdAgentRecord>(`/v1/ard/agents/${ardAgentId}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export async function deleteArdAgent(ardAgentId: string): Promise<ArdAgentRecord> {
  return request<ArdAgentRecord>(`/v1/ard/agents/${ardAgentId}`, {
    method: 'DELETE',
  })
}

export async function submitArdCatalog(
  payload: SubmitArdCatalogRequest,
): Promise<SubmitArdCatalogResponse> {
  return request<SubmitArdCatalogResponse>('/v1/ard/catalog-submissions', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
