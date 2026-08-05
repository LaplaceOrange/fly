import { describe, expect, it } from 'vitest'
import { decryptWithPrekeyPrivateKey, encryptForPrekeys, exchangeKeyBindingInput, legacyShareSigningInput, modernShareSigningInput, okpPublicKeyFingerprint, parseSharePayload, prekeyBindingInput, verifyRecipientPrekeys, verifyShare } from './crypto'
import type { OKPPublicJWK, OneTimePrekey, ShareRecord } from './types'

describe('share cryptography', () => {
  it('binds signature version, sender, expiry and sorted envelopes in v3', async () => {
    expect(legacyShareSigningInput(true, 'ciphertext', 'iv')).toBe('share-sign-v1\n1\nciphertext\niv')
    const input = modernShareSigningInput({
      signatureVersion: 3,
      senderUserId: 'sender',
      encrypted: true,
      payload: 'ciphertext',
      iv: 'content-iv',
      cryptoSuite: 'X25519-OTPK-HKDF-SHA256-AES-256-GCM+Ed25519',
      recipientUserId: 'recipient',
      ephemeralPublicJwk: { kty: 'OKP', crv: 'X25519', x: 'ephemeral-x' },
      expiresAt: '2026-08-11T00:00:00Z',
      keyEnvelopes: [
        { keyId: 'prekey-b', salt: 'salt-b', iv: 'iv-b', wrappedKey: 'wrapped-b' },
        { keyId: 'prekey-a', salt: 'salt-a', iv: 'iv-a', wrappedKey: 'wrapped-a' },
      ],
    })
    expect(input).toMatch(/^share-sign-v3\n1:3\n6:sender\n/)
    expect(input.indexOf('prekey-a')).toBeLessThan(input.indexOf('prekey-b'))
    expect(input).toContain('20:2026-08-11T00:00:00Z\n')
    expect(exchangeKeyBindingInput('用户', 'sig', { kty: 'OKP', crv: 'X25519', x: 'x' }))
      .toBe('exchange-key-binding-v1\n6:用户\n3:sig\n7:Ed25519\n6:X25519\n1:x\n')
    expect(prekeyBindingInput('用户', 'sig', 'device', { kty: 'OKP', crv: 'X25519', x: 'x' }))
      .toBe('prekey-binding-v1\n6:用户\n3:sig\n6:device\n7:Ed25519\n6:X25519\n1:x\n')
    await expect(okpPublicKeyFingerprint({ kty: 'OKP', crv: 'X25519', x: 'x' }))
      .resolves.toBe('WrTGFJjPeIHHytZ5ehJyyCmZdmf6dEMtnhnHFKhqMYU')
  })

  it('round-trips with an Ed25519-bound one-time X25519 prekey', async () => {
    const signing = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair
    const signingPublicJwk = await crypto.subtle.exportKey('jwk', signing.publicKey) as OKPPublicJWK
    const exchange = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const exchangePublicJwk = await crypto.subtle.exportKey('jwk', exchange.publicKey) as OKPPublicJWK
    const prekey = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const prekeyPublicJwk = await crypto.subtle.exportKey('jwk', prekey.publicKey) as OKPPublicJWK
    const signingKeyId = 'recipient-signing-device'
    const exchangeKeyId = 'recipient-exchange-device'
    const exchangeBinding = await crypto.subtle.sign(
      { name: 'Ed25519' }, signing.privateKey,
      new TextEncoder().encode(exchangeKeyBindingInput('recipient', signingKeyId, exchangePublicJwk)),
    )
    const prekeyBinding = await crypto.subtle.sign(
      { name: 'Ed25519' }, signing.privateKey,
      new TextEncoder().encode(prekeyBindingInput('recipient', signingKeyId, exchangeKeyId, prekeyPublicJwk)),
    )
    const boundKey: OneTimePrekey = {
      keyId: 'one-time-prekey', publicJwk: prekeyPublicJwk, fingerprint: await okpPublicKeyFingerprint(prekeyPublicJwk),
      exchangeKeyId, exchangePublicJwk, exchangeFingerprint: await okpPublicKeyFingerprint(exchangePublicJwk),
      exchangeBindingSignature: toBase64URL(new Uint8Array(exchangeBinding)), signingKeyId, signingPublicJwk,
      signingFingerprint: await okpPublicKeyFingerprint(signingPublicJwk), bindingVersion: 1,
      bindingSignature: toBase64URL(new Uint8Array(prekeyBinding)), deviceLabel: '测试设备',
    }
    await expect(verifyRecipientPrekeys('wrong-recipient', [boundKey])).rejects.toThrow('绑定签名无效')
    await expect(verifyRecipientPrekeys('recipient', [{ ...boundKey, fingerprint: 'tampered' }])).rejects.toThrow('绑定签名无效')
    const encrypted = await encryptForPrekeys('具有前向保密的端到端加密', 'recipient', [boundKey])
    const plaintext = await decryptWithPrekeyPrivateKey(prekey.privateKey, boundKey.keyId, {
      encrypted: true,
      signatureVersion: 3,
      ephemeralPublicJwk: encrypted.ephemeralPublicJwk,
      keyEnvelopes: encrypted.keyEnvelopes,
      iv: encrypted.iv,
      payload: encrypted.payload,
    })
    expect(plaintext).toBe('具有前向保密的端到端加密')
  })

  it('strictly validates decrypted payload identity and fields', () => {
    const raw = JSON.stringify({
      version: 1, sharedAt: '2026-08-05T00:00:00Z', message: '起飞',
      user: { id: 'sender', username: 's', displayName: 'Sender', avatarUrl: '', totalFlights: 1, lastFlightAt: null },
      snapshot: { totalFlights: 2, totalUsers: 1, rangeFlights: 1, range: '24h' },
    })
    expect(parseSharePayload(raw, 'sender').message).toBe('起飞')
    expect(() => parseSharePayload(raw, 'other')).toThrow('分享者身份')
    expect(() => parseSharePayload(JSON.stringify({ ...JSON.parse(raw), injected: true }), 'sender')).toThrow('字段无效')
  })

  it('rejects a server-supplied signing fingerprint that does not match the Ed25519 key', async () => {
    const signing = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', signing.publicKey) as OKPPublicJWK
    const unsigned = {
      signatureVersion: 3 as const, senderUserId: 'sender', encrypted: false, payload: '{}', iv: '',
      cryptoSuite: 'Ed25519' as const, recipientUserId: '', keyEnvelopes: [], expiresAt: '2026-08-11T00:00:00Z',
    }
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, signing.privateKey, new TextEncoder().encode(modernShareSigningInput(unsigned)))
    const share: ShareRecord = {
      id: 'share', encrypted: false, payload: '{}', iv: '', signature: toBase64URL(new Uint8Array(signature)),
      createdAt: '2026-08-05T00:00:00Z', expiresAt: unsigned.expiresAt,
      signer: { id: 'sender', username: 'sender', displayName: 'Sender', avatarUrl: '', totalFlights: 0, lastFlightAt: null },
      keyId: 'signing-key', signatureVersion: 3, cryptoSuite: 'Ed25519', signingAlgorithm: 'Ed25519', recipientUserId: '',
      keyEnvelopes: [], publicJwk, fingerprint: await okpPublicKeyFingerprint(publicJwk),
    }
    await expect(verifyShare(share)).resolves.toBe(true)
    await expect(verifyShare({ ...share, fingerprint: 'server-substituted' })).resolves.toBe(false)
  })
})

function toBase64URL(bytes: Uint8Array) {
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}
