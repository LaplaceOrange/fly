import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './api'

describe('share API', () => {
  afterEach(() => vi.restoreAllMocks())

  it('never sends the URL-fragment AES key to the server', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      id: 'share-id',
      url: 'https://example.com/share/share-id',
      expiresAt: '2026-08-11T00:00:00Z',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))

    await api.createShare({
      encrypted: true,
      payload: 'ciphertext',
      iv: 'iv',
      signature: 'signature',
      keyId: 'key-id',
      senderUserId: 'sender',
      signatureVersion: 3,
      cryptoSuite: 'X25519-OTPK-HKDF-SHA256-AES-256-GCM+Ed25519',
      recipientUserId: 'recipient',
      keyEnvelopes: [],
      expiresAt: '2026-08-11T00:00:00Z',
      prekeyClaimToken: 'claim-token',
      fragmentKey: 'must-stay-in-the-url-fragment',
    } as Parameters<typeof api.createShare>[0] & { fragmentKey: string })

    const request = fetchMock.mock.calls[0][1] as RequestInit
    expect(JSON.parse(request.body as string)).toEqual({
      encrypted: true,
      payload: 'ciphertext',
      iv: 'iv',
      signature: 'signature',
      keyId: 'key-id',
      senderUserId: 'sender',
      signatureVersion: 3,
      cryptoSuite: 'X25519-OTPK-HKDF-SHA256-AES-256-GCM+Ed25519',
      recipientUserId: 'recipient',
      keyEnvelopes: [],
      expiresAt: '2026-08-11T00:00:00Z',
      prekeyClaimToken: 'claim-token',
    })
    expect(request.body).not.toContain('must-stay-in-the-url-fragment')
  })

  it('sends the Ed25519 binding proof with an X25519 registration', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      keyId: 'exchange-key', fingerprint: 'fingerprint', algorithm: 'X25519',
    }), { status: 201, headers: { 'Content-Type': 'application/json' } }))

    await api.registerExchangeKey({ kty: 'OKP', crv: 'X25519', x: 'exchange-x' }, 'signing-key', 'binding-signature', '测试设备')

    const request = fetchMock.mock.calls[0][1] as RequestInit
    expect(JSON.parse(request.body as string)).toEqual({
      publicJwk: { kty: 'OKP', crv: 'X25519', x: 'exchange-x' },
      signingKeyId: 'signing-key', bindingVersion: 1, bindingSignature: 'binding-signature',
      deviceLabel: '测试设备',
    })
  })
})
