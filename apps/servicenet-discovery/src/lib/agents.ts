import type {
  ArdAgentRecord,
  DiscoveryAgent,
  InvocationProtocol,
  ServiceNetAgent,
} from '@/lib/types'

export const ARTIFACT_TYPES = [
  'application/a2a-agent-card+json',
  'application/mcp-server-card+json',
  'application/openapi+json',
]

export function protocolFromArtifactType(artifactType: string): InvocationProtocol {
  const normalized = artifactType.toLowerCase()
  if (normalized.includes('a2a')) return 'a2a'
  if (normalized.includes('mcp')) return 'mcp'
  if (normalized.includes('openapi')) return 'openapi'
  return 'unsupported'
}

export function serviceNetToDiscovery(agent: ServiceNetAgent): DiscoveryAgent {
  const card = agent.agent_card ?? {}
  const skills = card.skills ?? []
  return {
    id: agent.agent_id,
    title: card.name || agent.service_address || agent.agent_id,
    description: card.description || 'ServiceNet native published agent.',
    source: 'servicenet',
    publisher: agent.provider_id,
    protocol: 'a2a',
    status: agent.status.toLowerCase(),
    version: agent.version,
    updatedAt: agent.updated_at,
    risk: agent.review?.risk_level,
    capabilities: skills
      .map((skill) => skill.id || skill.name)
      .filter((skill): skill is string => Boolean(skill)),
    raw: agent,
  }
}

export function ardToDiscovery(agent: ArdAgentRecord): DiscoveryAgent {
  return {
    id: agent.ard_agent_id,
    title: agent.display_name,
    description: agent.description,
    source: 'ard',
    publisher: agent.publisher_domain,
    protocol: protocolFromArtifactType(agent.artifact_type),
    status: agent.status,
    version: agent.version,
    updatedAt: agent.updated_at,
    capabilities: agent.capabilities,
    raw: agent,
  }
}

export function matchesAgent(agent: DiscoveryAgent, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (!needle) return true
  return [
    agent.title,
    agent.description,
    agent.publisher,
    agent.source,
    agent.protocol,
    agent.status,
    agent.version,
    ...(agent.capabilities ?? []),
  ].some((value) => value.toLowerCase().includes(needle))
}

export function splitList(value: string): string[] {
  return value
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)
}
