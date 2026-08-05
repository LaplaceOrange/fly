import { api } from './api'
import type { ExchangeKey, KeyEnvelope, LegacyPublicJWK, OKPPublicJWK, ShareCreateRequest, ShareRecord } from './types'

interface StoredDeviceKey {
  userId: string
  // Legacy ECDSA fields are retained so old encrypted links remain readable.
  keyId?: string
  fingerprint?: string
  publicJwk?: LegacyPublicJWK
  privateKey?: CryptoKey
  signingKeyId?: string
  signingFingerprint?: string
  signingPublicJwk?: OKPPublicJWK
  signingPrivateKey?: CryptoKey
  exchangeKeyId?: string
  exchangeFingerprint?: string
  exchangePublicJwk?: OKPPublicJWK
  exchangePrivateKey?: CryptoKey
}

interface ModernDeviceKeys {
  signingKeyId: string
  signingPrivateKey: CryptoKey
  exchangeKeyId: string
  exchangePrivateKey: CryptoKey
}

const databaseName = 'chinese-can-fly-crypto'
const storeName = 'device-keys'
const encryptedSuite = 'X25519-HKDF-SHA256-AES-256-GCM+Ed25519' as const
const publicSuite = 'Ed25519' as const
const keyWrapInfo = new TextEncoder().encode('ChineseCanFly share key wrap v1')
const deviceKeyPromises = new Map<string, Promise<ModernDeviceKeys>>()

export function legacyShareSigningInput(encrypted: boolean, payload: string, iv: string) {
  return `share-sign-v1\n${encrypted ? '1' : '0'}\n${payload}\n${iv}`
}

export function modernShareSigningInput(input: Pick<ShareCreateRequest,
  'encrypted' | 'payload' | 'iv' | 'cryptoSuite' | 'recipientUserId' | 'ephemeralPublicJwk' | 'keyEnvelopes'>) {
  const envelopes = [...input.keyEnvelopes].sort((left, right) => left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0)
  const fields = [
    input.cryptoSuite,
    String(input.encrypted),
    input.payload,
    input.iv,
    input.recipientUserId,
    input.ephemeralPublicJwk?.x ?? '',
    String(envelopes.length),
    ...envelopes.flatMap((envelope) => [envelope.keyId, envelope.salt, envelope.iv, envelope.wrappedKey]),
  ]
  return lengthPrefixedInput('share-sign-v2', fields)
}

export function exchangeKeyBindingInput(userId: string, signingKeyId: string, exchangePublicJwk: OKPPublicJWK) {
  return lengthPrefixedInput('exchange-key-binding-v1', [userId, signingKeyId, 'Ed25519', 'X25519', exchangePublicJwk.x])
}

export async function verifyExchangeKeyBindings(recipientUserId: string, keys: ExchangeKey[]) {
  const results = await Promise.all(keys.map((key) => verifyExchangeKeyBinding(recipientUserId, key)))
  if (results.some((valid) => !valid)) throw new Error('接收者 X25519 公钥的 Ed25519 绑定签名无效')
  return keys
}

export async function okpPublicKeyFingerprint(publicJwk: OKPPublicJWK) {
  const canonical = JSON.stringify({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return toBase64URL(new Uint8Array(digest))
}

export function ensureModernDeviceKeys(userId: string) {
  const existing = deviceKeyPromises.get(userId)
  if (existing) return existing
  const created = ensureModernDeviceKeysInner(userId).finally(() => deviceKeyPromises.delete(userId))
  deviceKeyPromises.set(userId, created)
  return created
}

export async function createSignedShare(
  userId: string,
  plaintext: string,
  options: { encrypted: false } | { encrypted: true; recipientUserId: string; recipientKeys: ExchangeKey[] },
): Promise<ShareCreateRequest> {
  const deviceKeys = await ensureModernDeviceKeys(userId)
  let unsigned: Omit<ShareCreateRequest, 'signature' | 'keyId'>

  if (options.encrypted) {
    const encrypted = await encryptForRecipients(plaintext, options.recipientUserId, options.recipientKeys)
    unsigned = {
      encrypted: true,
      payload: encrypted.payload,
      iv: encrypted.iv,
      signatureVersion: 2,
      cryptoSuite: encryptedSuite,
      recipientUserId: options.recipientUserId,
      ephemeralPublicJwk: encrypted.ephemeralPublicJwk,
      keyEnvelopes: encrypted.keyEnvelopes,
    }
  } else {
    unsigned = {
      encrypted: false,
      payload: plaintext,
      iv: '',
      signatureVersion: 2,
      cryptoSuite: publicSuite,
      recipientUserId: '',
      keyEnvelopes: [],
    }
  }

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    deviceKeys.signingPrivateKey,
    new TextEncoder().encode(modernShareSigningInput(unsigned)),
  )
  return {
    ...unsigned,
    keyId: deviceKeys.signingKeyId,
    signature: toBase64URL(new Uint8Array(signature)),
  }
}

export async function encryptForRecipients(plaintext: string, recipientUserId: string, recipientKeys: ExchangeKey[]) {
  if (!recipientKeys.length) throw new Error('接收者没有可用的 X25519 设备密钥')
  await verifyExchangeKeyBindings(recipientUserId, recipientKeys)
  const contentKeyBytes = crypto.getRandomValues(new Uint8Array(32))
  try {
    const contentIV = crypto.getRandomValues(new Uint8Array(12))
    const contentKey = await crypto.subtle.importKey('raw', contentKeyBytes, { name: 'AES-GCM' }, false, ['encrypt'])
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: contentIV }, contentKey, new TextEncoder().encode(plaintext))

    const ephemeral = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const ephemeralPublicJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey) as OKPPublicJWK
    const keyEnvelopes: KeyEnvelope[] = []
    for (const recipientKey of recipientKeys) {
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const wrapIV = crypto.getRandomValues(new Uint8Array(12))
      const wrappingKey = await deriveWrappingKey(ephemeral.privateKey, recipientKey.publicJwk, salt, ['encrypt'])
      const wrappedKey = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIV }, wrappingKey, contentKeyBytes)
      keyEnvelopes.push({
        keyId: recipientKey.keyId,
        salt: toBase64URL(salt),
        iv: toBase64URL(wrapIV),
        wrappedKey: toBase64URL(new Uint8Array(wrappedKey)),
      })
    }
    return {
      payload: toBase64URL(new Uint8Array(ciphertext)),
      iv: toBase64URL(contentIV),
      ephemeralPublicJwk,
      keyEnvelopes,
    }
  } finally {
    contentKeyBytes.fill(0)
  }
}

export async function verifyShare(share: ShareRecord) {
  if (share.signatureVersion >= 2) {
    if (share.signingAlgorithm !== 'Ed25519' || share.publicJwk.kty !== 'OKP' || share.publicJwk.crv !== 'Ed25519') return false
    const publicKey = await crypto.subtle.importKey('jwk', share.publicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      fromBase64URL(share.signature),
      new TextEncoder().encode(modernShareSigningInput({
        encrypted: share.encrypted,
        payload: share.payload,
        iv: share.iv,
        cryptoSuite: share.cryptoSuite as ShareCreateRequest['cryptoSuite'],
        recipientUserId: share.recipientUserId,
        ephemeralPublicJwk: share.ephemeralPublicJwk,
        keyEnvelopes: share.keyEnvelopes,
      })),
    )
  }
  if (share.publicJwk.kty !== 'EC') return false
  const publicKey = await crypto.subtle.importKey('jwk', share.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    fromBase64URL(share.signature),
    new TextEncoder().encode(legacyShareSigningInput(share.encrypted, share.payload, share.iv)),
  )
}

export async function decryptModernShare(userId: string, share: ShareRecord) {
  if (!share.encrypted || share.signatureVersion < 2 || !share.ephemeralPublicJwk) throw new Error('分享不包含新版端到端加密信封')
  const stored = await idbGet(userId)
  if (!stored?.exchangeKeyId || !stored.exchangePrivateKey) throw new Error('此设备没有接收该分享所需的 X25519 私钥')
  return decryptWithExchangePrivateKey(stored.exchangePrivateKey, stored.exchangeKeyId, share)
}

export async function decryptWithExchangePrivateKey(
  privateKey: CryptoKey,
  exchangeKeyId: string,
  share: Pick<ShareRecord, 'encrypted' | 'signatureVersion' | 'ephemeralPublicJwk' | 'keyEnvelopes' | 'iv' | 'payload'>,
) {
  if (!share.encrypted || share.signatureVersion < 2 || !share.ephemeralPublicJwk) throw new Error('分享不包含新版端到端加密信封')
  const envelope = share.keyEnvelopes.find((candidate) => candidate.keyId === exchangeKeyId)
  if (!envelope) throw new Error('该分享创建时未包含此设备的密钥信封')

  const wrappingKey = await deriveWrappingKey(
    privateKey,
    share.ephemeralPublicJwk,
    fromBase64URL(envelope.salt),
    ['decrypt'],
  )
  const rawContentKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64URL(envelope.iv) },
    wrappingKey,
    fromBase64URL(envelope.wrappedKey),
  )
  const rawContentKeyBytes = new Uint8Array(rawContentKey)
  try {
    const contentKey = await crypto.subtle.importKey('raw', rawContentKeyBytes, { name: 'AES-GCM' }, false, ['decrypt'])
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64URL(share.iv) },
      contentKey,
      fromBase64URL(share.payload),
    )
    return new TextDecoder().decode(plaintext)
  } finally {
    rawContentKeyBytes.fill(0)
  }
}

export async function decryptLegacyAESGCM(ciphertext: string, iv: string, key: string) {
  const aesKey = await crypto.subtle.importKey('raw', fromBase64URL(key), 'AES-GCM', false, ['decrypt'])
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64URL(iv) }, aesKey, fromBase64URL(ciphertext))
  return new TextDecoder().decode(plaintext)
}

async function deriveWrappingKey(
  privateKey: CryptoKey,
  peerPublicJwk: OKPPublicJWK,
  salt: Uint8Array,
  usages: KeyUsage[],
) {
  if (peerPublicJwk.kty !== 'OKP' || peerPublicJwk.crv !== 'X25519') throw new Error('接收者 X25519 公钥无效')
  const peerPublicKey = await crypto.subtle.importKey('jwk', peerPublicJwk, { name: 'X25519' }, false, [])
  const sharedSecret = await crypto.subtle.deriveBits({ name: 'X25519', public: peerPublicKey }, privateKey, 256)
  const sharedSecretBytes = new Uint8Array(sharedSecret)
  try {
    const material = await crypto.subtle.importKey('raw', sharedSecretBytes, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: keyWrapInfo },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      usages,
    )
  } finally {
    sharedSecretBytes.fill(0)
  }
}

async function ensureModernDeviceKeysInner(userId: string): Promise<ModernDeviceKeys> {
  const existing = await idbGet(userId) ?? { userId }
  let next = existing

  if (!next.signingPrivateKey || !next.signingPublicJwk) {
    const generated = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey) as OKPPublicJWK
    next = {
      ...next,
      signingKeyId: undefined,
      signingFingerprint: undefined,
      signingPublicJwk: publicJwk,
      signingPrivateKey: generated.privateKey,
    }
    await idbPut(next)
  }

  const signingRegistered = await api.registerKey(next.signingPublicJwk!)
  if (signingRegistered.fingerprint !== await okpPublicKeyFingerprint(next.signingPublicJwk!)) {
    throw new Error('服务器返回的 Ed25519 公钥指纹不一致')
  }
  next = {
    ...next,
    signingKeyId: signingRegistered.keyId,
    signingFingerprint: signingRegistered.fingerprint,
  }
  await idbPut(next)

  if (!next.exchangePrivateKey || !next.exchangePublicJwk) {
    const generated = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey) as OKPPublicJWK
    next = {
      ...next,
      exchangeKeyId: undefined,
      exchangeFingerprint: undefined,
      exchangePublicJwk: publicJwk,
      exchangePrivateKey: generated.privateKey,
    }
    await idbPut(next)
  }

  const bindingSignature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    next.signingPrivateKey!,
    new TextEncoder().encode(exchangeKeyBindingInput(userId, next.signingKeyId!, next.exchangePublicJwk!)),
  )
  const registered = await api.registerExchangeKey(
    next.exchangePublicJwk!,
    next.signingKeyId!,
    toBase64URL(new Uint8Array(bindingSignature)),
  )
  if (registered.fingerprint !== await okpPublicKeyFingerprint(next.exchangePublicJwk!)) {
    throw new Error('服务器返回的 X25519 公钥指纹不一致')
  }
  next = {
    ...next,
    exchangeKeyId: registered.keyId,
    exchangeFingerprint: registered.fingerprint,
  }
  await idbPut(next)

  return {
    signingKeyId: next.signingKeyId!,
    signingPrivateKey: next.signingPrivateKey!,
    exchangeKeyId: next.exchangeKeyId!,
    exchangePrivateKey: next.exchangePrivateKey!,
  }
}

async function verifyExchangeKeyBinding(recipientUserId: string, key: ExchangeKey) {
  try {
    if (key.bindingVersion !== 1 || key.publicJwk.kty !== 'OKP' || key.publicJwk.crv !== 'X25519') return false
    if (key.signingPublicJwk.kty !== 'OKP' || key.signingPublicJwk.crv !== 'Ed25519') return false
    const [exchangeFingerprint, signingFingerprint] = await Promise.all([
      okpPublicKeyFingerprint(key.publicJwk),
      okpPublicKeyFingerprint(key.signingPublicJwk),
    ])
    if (exchangeFingerprint !== key.fingerprint || signingFingerprint !== key.signingFingerprint) return false
    const signingPublicKey = await crypto.subtle.importKey('jwk', key.signingPublicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' },
      signingPublicKey,
      fromBase64URL(key.bindingSignature),
      new TextEncoder().encode(exchangeKeyBindingInput(recipientUserId, key.signingKeyId, key.publicJwk)),
    )
  } catch {
    return false
  }
}

function lengthPrefixedInput(header: string, fields: string[]) {
  const encoder = new TextEncoder()
  return `${header}\n${fields.map((field) => `${encoder.encode(field).byteLength}:${field}\n`).join('')}`
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1)
    request.onupgradeneeded = () => request.result.createObjectStore(storeName, { keyPath: 'userId' })
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function idbGet(userId: string): Promise<StoredDeviceKey | undefined> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly')
    const request = transaction.objectStore(storeName).get(userId)
    request.onsuccess = () => resolve(request.result as StoredDeviceKey | undefined)
    request.onerror = () => reject(request.error)
    transaction.oncomplete = () => database.close()
  })
}

async function idbPut(record: StoredDeviceKey): Promise<void> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite')
    transaction.objectStore(storeName).put(record)
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

function toBase64URL(bytes: Uint8Array) {
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function fromBase64URL(value: string) {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)
  const binary = atob(base64)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}
