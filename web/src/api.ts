import { APIError, type Dashboard, type ExchangeKey, type Me, type OKPPublicJWK, type PublicConfig, type RangeName, type ShareCreateRequest, type ShareRecipient, type ShareRecord, type UsersPage } from './types'

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: { code: 'request_failed', message: '请求失败' } }))
    const error = payload.error ?? {}
    throw new APIError(response.status, error.code ?? 'request_failed', error.message ?? '请求失败', error)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  config: () => request<PublicConfig>('/api/public-config'),
  me: () => request<Me>('/api/me'),
  dashboard: (range: RangeName) => request<Dashboard>(`/api/dashboard?range=${range}`),
  users: (sort = 'last_flight', cursor = '') => {
    const query = new URLSearchParams({ sort, limit: '30' })
    if (cursor) query.set('cursor', cursor)
    return request<UsersPage>(`/api/users?${query}`)
  },
  takeoff: (turnstileToken: string) =>
    request<{ nextAllowedAt: string }>('/api/flights', {
      method: 'POST',
      body: JSON.stringify({ turnstileToken }),
    }),
  logout: () => request<void>('/api/auth/logout', { method: 'POST' }),
  registerKey: (publicJwk: OKPPublicJWK) => request<{ keyId: string; fingerprint: string; algorithm: 'Ed25519' }>('/api/keys', {
    method: 'POST', body: JSON.stringify({ publicJwk }),
  }),
  registerExchangeKey: (publicJwk: OKPPublicJWK, signingKeyId: string, bindingSignature: string) => request<{ keyId: string; fingerprint: string; algorithm: 'X25519' }>('/api/exchange-keys', {
    method: 'POST', body: JSON.stringify({ publicJwk, signingKeyId, bindingVersion: 1, bindingSignature }),
  }),
  shareRecipients: () => request<{ recipients: ShareRecipient[] }>('/api/share-recipients'),
  recipientKeys: (userId: string) => request<{ keys: ExchangeKey[] }>(`/api/share-recipients/${encodeURIComponent(userId)}/keys`),
  createShare: (body: ShareCreateRequest) =>
    request<{ id: string; url: string; expiresAt: string }>('/api/shares', {
      method: 'POST',
      // Enumerate the wire fields so encryption keys or other client-only data can
      // never be included if a structurally compatible object is passed here.
      body: JSON.stringify({
        encrypted: body.encrypted,
        payload: body.payload,
        iv: body.iv,
        signature: body.signature,
        keyId: body.keyId,
        signatureVersion: body.signatureVersion,
        cryptoSuite: body.cryptoSuite,
        recipientUserId: body.recipientUserId,
        ephemeralPublicJwk: body.ephemeralPublicJwk,
        keyEnvelopes: body.keyEnvelopes,
      }),
    }),
  share: (id: string) => request<ShareRecord>(`/api/shares/${encodeURIComponent(id)}`),
}
