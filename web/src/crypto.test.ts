import { describe, expect, it } from 'vitest'
import { decryptWithExchangePrivateKey, encryptForRecipients, legacyShareSigningInput, modernShareSigningInput } from './crypto'
import type { OKPPublicJWK } from './types'

describe('share cryptography', () => {
  it('keeps legacy signatures verifiable and canonicalizes v2 envelopes', () => {
    expect(legacyShareSigningInput(true, 'ciphertext', 'iv')).toBe('share-sign-v1\n1\nciphertext\niv')
    expect(modernShareSigningInput({
      encrypted: false, payload: '起飞', iv: '', cryptoSuite: 'Ed25519', recipientUserId: '', keyEnvelopes: [],
    })).toBe('share-sign-v2\n7:Ed25519\n5:false\n6:起飞\n0:\n0:\n0:\n1:0\n')
    const input = modernShareSigningInput({
      encrypted: true,
      payload: 'ciphertext',
      iv: 'content-iv',
      cryptoSuite: 'X25519-HKDF-SHA256-AES-256-GCM+Ed25519',
      recipientUserId: 'recipient',
      ephemeralPublicJwk: { kty: 'OKP', crv: 'X25519', x: 'ephemeral-x' },
      keyEnvelopes: [
        { keyId: 'device-b', salt: 'salt-b', iv: 'iv-b', wrappedKey: 'wrapped-b' },
        { keyId: 'device-a', salt: 'salt-a', iv: 'iv-a', wrappedKey: 'wrapped-a' },
      ],
    })
    expect(input).toMatch(/^share-sign-v2\n/)
    expect(input.indexOf('device-a')).toBeLessThan(input.indexOf('device-b'))
    expect(input).toContain('9:recipient\n')
  })

  it('round-trips a content key through X25519, HKDF and AES-GCM', async () => {
    const recipient = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', recipient.publicKey) as OKPPublicJWK
    const encrypted = await encryptForRecipients('真正的端到端加密', [{
      keyId: 'recipient-device', publicJwk, fingerprint: 'fingerprint',
    }])
    const plaintext = await decryptWithExchangePrivateKey(recipient.privateKey, 'recipient-device', {
      encrypted: true,
      signatureVersion: 2,
      ephemeralPublicJwk: encrypted.ephemeralPublicJwk,
      keyEnvelopes: encrypted.keyEnvelopes,
      iv: encrypted.iv,
      payload: encrypted.payload,
    })
    expect(plaintext).toBe('真正的端到端加密')
  })
})
