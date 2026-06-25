export type ArdAgentStatus = 'draft' | 'published' | 'disabled'
export type ArdArtifactMode = 'url' | 'inline_json'

export interface ServiceNetAgent {
  agent_id: string
  service_address?: string
  provider_id: string
  version: string
  status: string
  agent_card?: {
    name?: string
    description?: string
    skills?: Array<{ id?: string; name?: string; description?: string }>
  }
  review?: {
    risk_level?: string
    data_classes?: string[]
    allowed_regions?: string[]
  }
  updated_at?: string
  invoke?: {
    sync_url?: string
    async_url?: string
  }
}

export interface ArdAgentRecord {
  ard_agent_id: string
  identifier: string
  publisher_domain: string
  display_name: string
  description: string
  artifact_type: string
  artifact_mode: ArdArtifactMode
  artifact_url?: string
  artifact_data?: unknown
  capabilities: string[]
  representative_queries: string[]
  trust_identity_type?: string
  trust_identity?: string
  trust_manifest?: unknown
  version: string
  tags: string[]
  status: ArdAgentStatus
  created_at: string
  updated_at: string
}

export interface CreateArdAgentRequest {
  identifier: string
  publisher_domain: string
  display_name: string
  description: string
  artifact_type: string
  artifact_mode: ArdArtifactMode
  artifact_url?: string
  artifact_data?: unknown
  capabilities: string[]
  representative_queries: string[]
  trust_identity_type?: string
  trust_identity?: string
  trust_manifest?: unknown
  version: string
  tags: string[]
  status?: ArdAgentStatus
}

export interface UpdateArdAgentRequest {
  identifier?: string
  publisher_domain?: string
  display_name?: string
  description?: string
  artifact_type?: string
  artifact_mode?: ArdArtifactMode
  artifact_url?: string | null
  artifact_data?: unknown | null
  capabilities?: string[]
  representative_queries?: string[]
  trust_identity_type?: string | null
  trust_identity?: string | null
  trust_manifest?: unknown | null
  version?: string
  tags?: string[]
  status?: ArdAgentStatus
}

export type ArdCatalogSourceStatus = 'pending' | 'active' | 'disabled'

export interface PublicArdCatalogSource {
  publisher_domain: string
  catalog_url: string
  status: ArdCatalogSourceStatus
  created_at: string
  updated_at: string
  last_crawled_at?: string
  last_error?: string
}

export interface SubmitArdCatalogRequest {
  publisher_domain: string
  catalog_url?: string
}

export interface SubmitArdCatalogResponse {
  source: PublicArdCatalogSource
}

export type AgentSource = 'servicenet' | 'ard'
export type InvocationProtocol = 'a2a' | 'mcp' | 'openapi' | 'unsupported'

export interface DiscoveryAgent {
  id: string
  title: string
  description: string
  source: AgentSource
  publisher: string
  protocol: InvocationProtocol
  status: string
  version: string
  updatedAt?: string
  risk?: string
  capabilities: string[]
  raw: ServiceNetAgent | ArdAgentRecord
}
