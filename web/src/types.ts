export type RangeName = '24h' | '7d' | '1month' | 'all'

export interface User {
  id: string
  username: string
  displayName: string
  avatarUrl: string
  totalFlights: number
  lastFlightAt: string | null
}

export interface UserStatus extends User {
  canTakeoff: boolean
  nextAllowedAt: string | null
}

export interface Flight {
  id: number
  createdAt: string
  user: User
}

export interface Dashboard {
  generatedAt: string
  revision: number
  range: RangeName
  summary: {
    totalFlights: number
    rangeFlights: number
    totalUsers: number
    activeUsers: number
    lastFlightAt: string | null
  }
  trend: Array<{ bucketStart: string; count: number }>
  leaderboard: Array<{
    rank: number
    user: User
    flightCount: number
    lastFlightAt: string | null
  }>
  heatmap: Array<{ weekday: number; hour: number; count: number }>
  recentFlights: Flight[]
}

export interface PublicConfig {
  siteName: string
  turnstileSiteKey: string
  rateLimitMinutes: number
  timezone: string
  shareTTLHours: number
}

export type Me =
  | { authenticated: false }
  | {
      authenticated: true
      user: User
      canTakeoff: boolean
      nextAllowedAt: string | null
    }

export interface UsersPage {
  users: UserStatus[]
  nextCursor?: string
}

export interface RealtimeEvent {
  type: 'connected' | 'flight.created'
  revision: number
  flight?: Flight
}

export interface LegacyPublicJWK {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
  ext?: boolean
  key_ops?: string[]
}

export interface OKPPublicJWK {
  kty: 'OKP'
  crv: 'Ed25519' | 'X25519'
  x: string
  ext?: boolean
  key_ops?: string[]
}

export type PublicJWK = LegacyPublicJWK | OKPPublicJWK

export interface ExchangeKey {
  keyId: string
  publicJwk: OKPPublicJWK
  fingerprint: string
}

export interface ShareRecipient extends User {
  deviceCount: number
}

export interface KeyEnvelope {
  keyId: string
  salt: string
  iv: string
  wrappedKey: string
}

export interface ShareCreateRequest {
  encrypted: boolean
  payload: string
  iv: string
  signature: string
  keyId: string
  signatureVersion: 2
  cryptoSuite: 'Ed25519' | 'X25519-HKDF-SHA256-AES-256-GCM+Ed25519'
  recipientUserId: string
  ephemeralPublicJwk?: OKPPublicJWK
  keyEnvelopes: KeyEnvelope[]
}

export interface ShareRecord {
  id: string
  encrypted: boolean
  payload: string
  iv: string
  signature: string
  createdAt: string
  expiresAt: string
  signer: User
  keyId: string
  signatureVersion: number
  cryptoSuite: string
  signingAlgorithm: 'ECDSA-P256-SHA256' | 'Ed25519'
  recipientUserId: string
  ephemeralPublicJwk?: OKPPublicJWK
  keyEnvelopes: KeyEnvelope[]
  publicJwk: PublicJWK
  fingerprint: string
}

export interface SharePayload {
  version: 1
  sharedAt: string
  message: string
  user: Pick<User, 'id' | 'username' | 'displayName' | 'avatarUrl' | 'totalFlights' | 'lastFlightAt'>
  snapshot: {
    totalFlights: number
    totalUsers: number
    rangeFlights: number
    range: RangeName
  }
}

export class APIError extends Error {
  status: number
  code: string
  retryAfterSeconds?: number
  nextAllowedAt?: string

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.retryAfterSeconds = details?.retryAfterSeconds as number | undefined
    this.nextAllowedAt = details?.nextAllowedAt as string | undefined
  }
}
