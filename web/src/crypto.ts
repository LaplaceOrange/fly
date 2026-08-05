import { api } from './api'
import { APIError, type ExchangeKey, type KeyEnvelope, type LegacyPublicJWK, type OKPPublicJWK, type OneTimePrekey, type RecipientTrustInspection, type ShareCreateRequest, type SharePayload, type ShareRecord } from './types'

interface StoredPrekey {
  keyId?: string
  fingerprint: string
  publicJwk: OKPPublicJWK
  privateKey: CryptoKey
  createdAt: string
}

interface StoredDeviceKey {
  userId: string
  // Legacy fields remain so v1/v2 links created before the protocol upgrade stay readable.
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
  prekeys?: StoredPrekey[]
  cacheEncryptionKey?: CryptoKey
}

interface CachedDecryptedShare {
  id: string
  userId: string
  shareId: string
  ciphertext: string
  iv: string
  expiresAt: string
}

interface RecipientTrustRecord {
  userId: string
  signingFingerprints: string[]
  safetyNumber: string
  trustedAt: string
}

interface ModernDeviceKeys {
  signingKeyId: string
  signingPrivateKey: CryptoKey
  exchangeKeyId: string
  exchangePrivateKey: CryptoKey
}

const databaseName = 'chinese-can-fly-crypto'
const deviceStoreName = 'device-keys'
const trustStoreName = 'recipient-trust'
const cacheStoreName = 'decrypted-share-cache'
const encryptedSuite = 'X25519-OTPK-HKDF-SHA256-AES-256-GCM+Ed25519' as const
const legacyV2EncryptedSuite = 'X25519-HKDF-SHA256-AES-256-GCM+Ed25519'
const publicSuite = 'Ed25519' as const
const keyWrapInfoV1 = new TextEncoder().encode('ChineseCanFly share key wrap v1')
const keyWrapInfoV2 = new TextEncoder().encode('ChineseCanFly one-time prekey share wrap v2')
const prekeyTarget = 8
const deviceKeyPromises = new Map<string, Promise<ModernDeviceKeys>>()

export function legacyShareSigningInput(encrypted: boolean, payload: string, iv: string) {
  return `share-sign-v1\n${encrypted ? '1' : '0'}\n${payload}\n${iv}`
}

export function modernShareSigningInput(input: Pick<ShareCreateRequest,
  'signatureVersion' | 'senderUserId' | 'encrypted' | 'payload' | 'iv' | 'cryptoSuite' | 'recipientUserId' | 'ephemeralPublicJwk' | 'keyEnvelopes' | 'expiresAt'>) {
  const envelopes = sortedEnvelopes(input.keyEnvelopes)
  const fields = [
    String(input.signatureVersion),
    input.senderUserId,
    input.cryptoSuite,
    String(input.encrypted),
    input.payload,
    input.iv,
    input.recipientUserId,
    input.ephemeralPublicJwk?.x ?? '',
    input.expiresAt,
    String(envelopes.length),
    ...envelopes.flatMap((envelope) => [envelope.keyId, envelope.salt, envelope.iv, envelope.wrappedKey]),
  ]
  return lengthPrefixedInput('share-sign-v3', fields)
}

function modernShareSigningInputV2(input: Pick<ShareRecord,
  'encrypted' | 'payload' | 'iv' | 'cryptoSuite' | 'recipientUserId' | 'ephemeralPublicJwk' | 'keyEnvelopes'>) {
  const envelopes = sortedEnvelopes(input.keyEnvelopes)
  return lengthPrefixedInput('share-sign-v2', [
    input.cryptoSuite,
    String(input.encrypted),
    input.payload,
    input.iv,
    input.recipientUserId,
    input.ephemeralPublicJwk?.x ?? '',
    String(envelopes.length),
    ...envelopes.flatMap((envelope) => [envelope.keyId, envelope.salt, envelope.iv, envelope.wrappedKey]),
  ])
}

export function exchangeKeyBindingInput(userId: string, signingKeyId: string, exchangePublicJwk: OKPPublicJWK) {
  return lengthPrefixedInput('exchange-key-binding-v1', [userId, signingKeyId, 'Ed25519', 'X25519', exchangePublicJwk.x])
}

export function prekeyBindingInput(userId: string, signingKeyId: string, exchangeKeyId: string, prekeyPublicJwk: OKPPublicJWK) {
  return lengthPrefixedInput('prekey-binding-v1', [userId, signingKeyId, exchangeKeyId, 'Ed25519', 'X25519', prekeyPublicJwk.x])
}

export async function verifyExchangeKeyBindings(recipientUserId: string, keys: ExchangeKey[]) {
  const results = await Promise.all(keys.map((key) => verifyExchangeKeyBinding(recipientUserId, key)))
  if (results.some((valid) => !valid)) throw new Error('接收者 X25519 公钥的 Ed25519 绑定签名无效')
  return keys
}

export async function inspectRecipientPrekeys(recipientUserId: string, keys: OneTimePrekey[]): Promise<RecipientTrustInspection> {
  await verifyRecipientPrekeys(recipientUserId, keys)
  const signingFingerprints = [...new Set(keys.map((key) => key.signingFingerprint))].sort()
  const safetyNumber = await recipientSafetyNumber(recipientUserId, signingFingerprints)
  const trusted = await idbGetTrust(`recipient-directory:${recipientUserId}`)
  const unchanged = trusted && arraysEqual(trusted.signingFingerprints, signingFingerprints)
  return {
    status: unchanged ? 'trusted' : trusted ? 'changed' : 'first-use',
    safetyNumber,
    signingFingerprints,
  }
}

export async function verifyRecipientPrekeys(recipientUserId: string, keys: OneTimePrekey[]) {
  if (!keys.length) throw new Error('接收者没有可用的一次性 X25519 预密钥')
  const results = await Promise.all(keys.map((key) => verifyPrekeyBinding(recipientUserId, key)))
  if (results.some((valid) => !valid)) throw new Error('接收者一次性 X25519 预密钥的 Ed25519 绑定签名无效')
  if (new Set(keys.map((key) => key.keyId)).size !== keys.length) throw new Error('接收者一次性预密钥目录包含重复项')
  return keys
}

export async function trustRecipientIdentity(recipientUserId: string, inspection: RecipientTrustInspection) {
  await idbPutTrust({
    userId: `recipient-directory:${recipientUserId}`,
    signingFingerprints: [...inspection.signingFingerprints].sort(),
    safetyNumber: inspection.safetyNumber,
    trustedAt: new Date().toISOString(),
  })
}

export async function inspectShareSigner(userId: string, publicJwk: OKPPublicJWK, fingerprint: string): Promise<RecipientTrustInspection> {
  if (publicJwk.kty !== 'OKP' || publicJwk.crv !== 'Ed25519' || await okpPublicKeyFingerprint(publicJwk) !== fingerprint) {
    throw new Error('分享者 Ed25519 公钥指纹无效')
  }
  const recordKey = `share-signer:${userId}`
  const trusted = await idbGetTrust(recordKey)
  const safetyNumber = await recipientSafetyNumber(userId, [fingerprint])
  return {
    status: trusted?.signingFingerprints.includes(fingerprint) ? 'trusted' : trusted ? 'changed' : 'first-use',
    safetyNumber,
    signingFingerprints: [fingerprint],
  }
}

export async function trustShareSignerIdentity(userId: string, inspection: RecipientTrustInspection) {
  const recordKey = `share-signer:${userId}`
  await idbPutTrust({
    userId: recordKey,
    signingFingerprints: [...inspection.signingFingerprints].sort(),
    safetyNumber: inspection.safetyNumber,
    trustedAt: new Date().toISOString(),
  })
}

export async function assertRecipientIdentityTrusted(recipientUserId: string, keys: OneTimePrekey[]) {
  const inspection = await inspectRecipientPrekeys(recipientUserId, keys)
  if (inspection.status !== 'trusted') {
    throw new Error(inspection.status === 'changed'
      ? '接收者设备签名密钥发生变化，请重新核对安全码并明确确认'
      : '请先核对并信任接收者安全码')
  }
  return inspection
}

export async function okpPublicKeyFingerprint(publicJwk: OKPPublicJWK) {
  const canonical = JSON.stringify({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return toBase64URL(new Uint8Array(digest))
}

export function ensureModernDeviceKeys(userId: string) {
  const existing = deviceKeyPromises.get(userId)
  if (existing) return existing
  const created = withDeviceLock(userId, () => ensureModernDeviceKeysInner(userId)).finally(() => deviceKeyPromises.delete(userId))
  deviceKeyPromises.set(userId, created)
  return created
}

export async function currentDeviceExchangeKeyID(userId: string) {
  return (await idbGetDevice(userId))?.exchangeKeyId
}

export async function forgetLocalDeviceKeys(userId: string) {
  await idbDeleteDevice(userId)
  await idbDeleteUserCaches(userId)
  deviceKeyPromises.delete(userId)
}

export async function createSignedShare(
  userId: string,
  plaintext: string,
  expiresAt: string,
  options: { encrypted: false } | { encrypted: true; recipientUserId: string; recipientKeys: OneTimePrekey[]; claimToken: string },
): Promise<ShareCreateRequest> {
  const deviceKeys = await ensureModernDeviceKeys(userId)
  let unsigned: Omit<ShareCreateRequest, 'signature' | 'keyId'>

  if (options.encrypted) {
    await assertRecipientIdentityTrusted(options.recipientUserId, options.recipientKeys)
    const encrypted = await encryptForPrekeys(plaintext, options.recipientUserId, options.recipientKeys)
    unsigned = {
      encrypted: true,
      payload: encrypted.payload,
      iv: encrypted.iv,
      senderUserId: userId,
      signatureVersion: 3,
      cryptoSuite: encryptedSuite,
      recipientUserId: options.recipientUserId,
      ephemeralPublicJwk: encrypted.ephemeralPublicJwk,
      keyEnvelopes: encrypted.keyEnvelopes,
      expiresAt,
      prekeyClaimToken: options.claimToken,
    }
  } else {
    unsigned = {
      encrypted: false,
      payload: plaintext,
      iv: '',
      senderUserId: userId,
      signatureVersion: 3,
      cryptoSuite: publicSuite,
      recipientUserId: '',
      keyEnvelopes: [],
      expiresAt,
      prekeyClaimToken: '',
    }
  }

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    deviceKeys.signingPrivateKey,
    new TextEncoder().encode(modernShareSigningInput(unsigned)),
  )
  return { ...unsigned, keyId: deviceKeys.signingKeyId, signature: toBase64URL(new Uint8Array(signature)) }
}

export async function encryptForPrekeys(plaintext: string, recipientUserId: string, recipientKeys: OneTimePrekey[]) {
  await verifyRecipientPrekeys(recipientUserId, recipientKeys)
  return encryptAndWrap(plaintext, recipientKeys.map((key) => ({ keyId: key.keyId, publicJwk: key.publicJwk })), keyWrapInfoV2)
}

// Retained for v2 compatibility tests and old locally stored shares. New shares use one-time prekeys.
export async function encryptForRecipients(plaintext: string, recipientUserId: string, recipientKeys: ExchangeKey[]) {
  if (!recipientKeys.length) throw new Error('接收者没有可用的 X25519 设备密钥')
  await verifyExchangeKeyBindings(recipientUserId, recipientKeys)
  return encryptAndWrap(plaintext, recipientKeys.map((key) => ({ keyId: key.keyId, publicJwk: key.publicJwk })), keyWrapInfoV1)
}

async function encryptAndWrap(plaintext: string, recipientKeys: Array<{ keyId: string; publicJwk: OKPPublicJWK }>, info: Uint8Array) {
  if (!recipientKeys.length) throw new Error('接收者没有可用的加密设备密钥')
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
      const wrappingKey = await deriveWrappingKey(ephemeral.privateKey, recipientKey.publicJwk, salt, ['encrypt'], info)
      const wrappedKey = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIV }, wrappingKey, contentKeyBytes)
      keyEnvelopes.push({
        keyId: recipientKey.keyId,
        salt: toBase64URL(salt),
        iv: toBase64URL(wrapIV),
        wrappedKey: toBase64URL(new Uint8Array(wrappedKey)),
      })
    }
    return { payload: toBase64URL(new Uint8Array(ciphertext)), iv: toBase64URL(contentIV), ephemeralPublicJwk, keyEnvelopes }
  } finally {
    contentKeyBytes.fill(0)
  }
}

export async function verifyShare(share: ShareRecord) {
  if (share.signatureVersion === 3) {
    if (share.signingAlgorithm !== 'Ed25519' || share.publicJwk.kty !== 'OKP' || share.publicJwk.crv !== 'Ed25519') return false
    if (share.encrypted ? share.cryptoSuite !== encryptedSuite : share.cryptoSuite !== publicSuite) return false
    if (await okpPublicKeyFingerprint(share.publicJwk) !== share.fingerprint) return false
    const publicKey = await crypto.subtle.importKey('jwk', share.publicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' }, publicKey, fromBase64URL(share.signature),
      new TextEncoder().encode(modernShareSigningInput({
        signatureVersion: 3,
        senderUserId: share.signer.id,
        encrypted: share.encrypted,
        payload: share.payload,
        iv: share.iv,
        cryptoSuite: share.cryptoSuite as ShareCreateRequest['cryptoSuite'],
        recipientUserId: share.recipientUserId,
        ephemeralPublicJwk: share.ephemeralPublicJwk,
        keyEnvelopes: share.keyEnvelopes,
        expiresAt: share.expiresAt,
      })),
    )
  }
  if (share.signatureVersion === 2) {
    if (share.signingAlgorithm !== 'Ed25519' || share.publicJwk.kty !== 'OKP' || share.publicJwk.crv !== 'Ed25519') return false
    if (share.encrypted && share.cryptoSuite !== legacyV2EncryptedSuite) return false
    if (await okpPublicKeyFingerprint(share.publicJwk) !== share.fingerprint) return false
    const publicKey = await crypto.subtle.importKey('jwk', share.publicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' }, publicKey, fromBase64URL(share.signature),
      new TextEncoder().encode(modernShareSigningInputV2(share)),
    )
  }
  if (share.signatureVersion !== 1 || share.publicJwk.kty !== 'EC') return false
  const publicKey = await crypto.subtle.importKey('jwk', share.publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, publicKey, fromBase64URL(share.signature),
    new TextEncoder().encode(legacyShareSigningInput(share.encrypted, share.payload, share.iv)),
  )
}

export async function decryptModernShare(userId: string, share: ShareRecord) {
  if (!share.encrypted || !share.ephemeralPublicJwk) throw new Error('分享不包含端到端加密信封')
  if (share.signatureVersion === 3) {
    await ensureModernDeviceKeys(userId)
    const stored = await idbGetDevice(userId)
    const cached = await idbGetCache(userId, share.id)
    if (cached && cached.expiresAt === share.expiresAt && stored?.cacheEncryptionKey) {
      return decryptCachedShare(stored.cacheEncryptionKey, cached)
    }
    if (cached) await idbDeleteCache(cached.id)
    const prekey = stored?.prekeys?.find((candidate) => share.keyEnvelopes.some((envelope) => envelope.keyId === candidate.keyId))
    if (!prekey?.keyId) throw new Error('此设备没有接收该分享所需的一次性 X25519 私钥')
    const plaintext = await decryptWithPrivateKey(prekey.privateKey, prekey.keyId, share, keyWrapInfoV2)
    await cacheShareAndConsumePrekey(stored!, prekey, share, plaintext)
    return plaintext
  }
  if (share.signatureVersion === 2) {
    const stored = await idbGetDevice(userId)
    if (!stored?.exchangeKeyId || !stored.exchangePrivateKey) throw new Error('此设备没有接收该分享所需的 X25519 私钥')
    return decryptWithExchangePrivateKey(stored.exchangePrivateKey, stored.exchangeKeyId, share)
  }
  throw new Error('分享不包含受支持的端到端加密信封')
}

export async function decryptWithExchangePrivateKey(
  privateKey: CryptoKey,
  exchangeKeyId: string,
  share: Pick<ShareRecord, 'encrypted' | 'signatureVersion' | 'ephemeralPublicJwk' | 'keyEnvelopes' | 'iv' | 'payload'>,
) {
  if (!share.encrypted || share.signatureVersion !== 2 || !share.ephemeralPublicJwk) throw new Error('分享不包含 v2 端到端加密信封')
  return decryptWithPrivateKey(privateKey, exchangeKeyId, share, keyWrapInfoV1)
}

export async function decryptWithPrekeyPrivateKey(
  privateKey: CryptoKey,
  prekeyId: string,
  share: Pick<ShareRecord, 'encrypted' | 'signatureVersion' | 'ephemeralPublicJwk' | 'keyEnvelopes' | 'iv' | 'payload'>,
) {
  if (!share.encrypted || share.signatureVersion !== 3 || !share.ephemeralPublicJwk) throw new Error('分享不包含 v3 一次性预密钥信封')
  return decryptWithPrivateKey(privateKey, prekeyId, share, keyWrapInfoV2)
}

async function decryptWithPrivateKey(
  privateKey: CryptoKey,
  keyId: string,
  share: Pick<ShareRecord, 'ephemeralPublicJwk' | 'keyEnvelopes' | 'iv' | 'payload'>,
  info: Uint8Array,
) {
  if (!share.ephemeralPublicJwk) throw new Error('分享缺少临时 X25519 公钥')
  const envelope = share.keyEnvelopes.find((candidate) => candidate.keyId === keyId)
  if (!envelope) throw new Error('该分享创建时未包含此设备的密钥信封')
  const wrappingKey = await deriveWrappingKey(privateKey, share.ephemeralPublicJwk, fromBase64URL(envelope.salt), ['decrypt'], info)
  const rawContentKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64URL(envelope.iv) }, wrappingKey, fromBase64URL(envelope.wrappedKey),
  )
  const rawContentKeyBytes = new Uint8Array(rawContentKey)
  try {
    const contentKey = await crypto.subtle.importKey('raw', rawContentKeyBytes, { name: 'AES-GCM' }, false, ['decrypt'])
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64URL(share.iv) }, contentKey, fromBase64URL(share.payload),
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

export function parseSharePayload(raw: string, expectedSignerId: string): SharePayload {
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw new Error('分享载荷不是有效 JSON')
  }
  if (!isRecord(value) || !hasOnlyKeys(value, ['version', 'sharedAt', 'message', 'user', 'snapshot']) || value.version !== 1) {
    throw new Error('分享载荷版本或字段无效')
  }
  if (!isISODate(value.sharedAt) || typeof value.message !== 'string' || !value.message.trim() || [...value.message].length > 280) {
    throw new Error('分享时间或寄语无效')
  }
  const user = value.user
  if (!isRecord(user) || !hasOnlyKeys(user, ['id', 'username', 'displayName', 'avatarUrl', 'totalFlights', 'lastFlightAt']) ||
      user.id !== expectedSignerId || !isBoundedString(user.username, 200) || !isBoundedString(user.displayName, 200) ||
      typeof user.avatarUrl !== 'string' || user.avatarUrl.length > 2048 || !isCount(user.totalFlights) ||
      !(user.lastFlightAt === null || isISODate(user.lastFlightAt))) {
    throw new Error('分享者身份或统计字段无效')
  }
  const snapshot = value.snapshot
  if (!isRecord(snapshot) || !hasOnlyKeys(snapshot, ['totalFlights', 'totalUsers', 'rangeFlights', 'range']) ||
      !isCount(snapshot.totalFlights) || !isCount(snapshot.totalUsers) || !isCount(snapshot.rangeFlights) ||
      !['24h', '7d', '1month', 'all'].includes(String(snapshot.range))) {
    throw new Error('分享快照字段无效')
  }
  return value as unknown as SharePayload
}

async function deriveWrappingKey(privateKey: CryptoKey, peerPublicJwk: OKPPublicJWK, salt: Uint8Array, usages: KeyUsage[], info: Uint8Array) {
  if (peerPublicJwk.kty !== 'OKP' || peerPublicJwk.crv !== 'X25519') throw new Error('接收者 X25519 公钥无效')
  const peerPublicKey = await crypto.subtle.importKey('jwk', peerPublicJwk, { name: 'X25519' }, false, [])
  const sharedSecret = await crypto.subtle.deriveBits({ name: 'X25519', public: peerPublicKey }, privateKey, 256)
  const sharedSecretBytes = new Uint8Array(sharedSecret)
  try {
    const material = await crypto.subtle.importKey('raw', sharedSecretBytes, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
      material, { name: 'AES-GCM', length: 256 }, false, usages,
    )
  } finally {
    sharedSecretBytes.fill(0)
  }
}

async function ensureModernDeviceKeysInner(userId: string): Promise<ModernDeviceKeys> {
  const existing = await idbGetDevice(userId) ?? { userId }
  let next = existing
  const deviceLabel = browserDeviceLabel()

  if (!next.cacheEncryptionKey) {
    next = { ...next, cacheEncryptionKey: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) }
    await idbPutDevice(next)
  }
  await idbDeleteExpiredCaches(userId)

  if (!next.signingPrivateKey || !next.signingPublicJwk) {
    const generated = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey) as OKPPublicJWK
    next = { ...next, signingKeyId: undefined, signingFingerprint: undefined, signingPublicJwk: publicJwk, signingPrivateKey: generated.privateKey }
    await idbPutDevice(next)
  }

  let signingRegistered
  try {
    signingRegistered = await api.registerKey(next.signingPublicJwk!, deviceLabel)
  } catch (caught) {
    if (caught instanceof APIError && caught.code === 'key_revoked') {
      await idbDeleteDevice(userId)
      return ensureModernDeviceKeysInner(userId)
    }
    throw caught
  }
  if (signingRegistered.fingerprint !== await okpPublicKeyFingerprint(next.signingPublicJwk!)) throw new Error('服务器返回的 Ed25519 公钥指纹不一致')
  next = { ...next, signingKeyId: signingRegistered.keyId, signingFingerprint: signingRegistered.fingerprint }
  await idbPutDevice(next)

  if (!next.exchangePrivateKey || !next.exchangePublicJwk) {
    const generated = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey) as OKPPublicJWK
    next = { ...next, exchangeKeyId: undefined, exchangeFingerprint: undefined, exchangePublicJwk: publicJwk, exchangePrivateKey: generated.privateKey, prekeys: [] }
    await idbPutDevice(next)
  }

  const bindingSignature = await crypto.subtle.sign(
    { name: 'Ed25519' }, next.signingPrivateKey!,
    new TextEncoder().encode(exchangeKeyBindingInput(userId, next.signingKeyId!, next.exchangePublicJwk!)),
  )
  let registered
  try {
    registered = await api.registerExchangeKey(next.exchangePublicJwk!, next.signingKeyId!, toBase64URL(new Uint8Array(bindingSignature)), deviceLabel)
  } catch (caught) {
    if (caught instanceof APIError && caught.code === 'key_revoked') {
      await idbDeleteDevice(userId)
      return ensureModernDeviceKeysInner(userId)
    }
    throw caught
  }
  if (registered.fingerprint !== await okpPublicKeyFingerprint(next.exchangePublicJwk!)) throw new Error('服务器返回的 X25519 公钥指纹不一致')
  next = { ...next, exchangeKeyId: registered.keyId, exchangeFingerprint: registered.fingerprint }
  await idbPutDevice(next)
  next = await replenishPrekeys(next)

  return {
    signingKeyId: next.signingKeyId!, signingPrivateKey: next.signingPrivateKey!,
    exchangeKeyId: next.exchangeKeyId!, exchangePrivateKey: next.exchangePrivateKey!,
  }
}

async function replenishPrekeys(record: StoredDeviceKey) {
  let next = { ...record, prekeys: [...(record.prekeys ?? [])] }
  const pending = next.prekeys.filter((key) => !key.keyId)
  if (pending.length) next = await registerLocalPrekeys(next, pending.slice(0, 16))
  const status = await api.prekeyStatus(next.exchangeKeyId!)
  const retained = new Set([...status.availableFingerprints, ...status.retainedFingerprints])
  next = {
    ...next,
    prekeys: next.prekeys.filter((key) => !key.keyId || retained.has(key.fingerprint)),
  }
  await idbPutDevice(next)
  const needed = Math.max(0, prekeyTarget - status.availableFingerprints.length)
  if (!needed) return next
  const generated: StoredPrekey[] = []
  for (let index = 0; index < needed; index += 1) {
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey) as OKPPublicJWK
    generated.push({ publicJwk, privateKey: pair.privateKey, fingerprint: await okpPublicKeyFingerprint(publicJwk), createdAt: new Date().toISOString() })
  }
  next = { ...next, prekeys: [...next.prekeys, ...generated] }
  await idbPutDevice(next)
  return registerLocalPrekeys(next, generated)
}

async function registerLocalPrekeys(record: StoredDeviceKey, keys: StoredPrekey[]) {
  const wire = []
  for (const key of keys) {
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' }, record.signingPrivateKey!,
      new TextEncoder().encode(prekeyBindingInput(record.userId, record.signingKeyId!, record.exchangeKeyId!, key.publicJwk)),
    )
    wire.push({
      publicJwk: key.publicJwk, exchangeKeyId: record.exchangeKeyId!, signingKeyId: record.signingKeyId!,
      bindingSignature: toBase64URL(new Uint8Array(signature)),
    })
  }
  const response = await api.registerPrekeys(wire)
  const ids = new Map(response.prekeys.map((item) => [item.fingerprint, item.keyId]))
  const next = {
    ...record,
    prekeys: (record.prekeys ?? []).map((key) => ids.has(key.fingerprint) ? { ...key, keyId: ids.get(key.fingerprint) } : key),
  }
  await idbPutDevice(next)
  return next
}

async function verifyExchangeKeyBinding(recipientUserId: string, key: ExchangeKey | OneTimePrekey) {
  try {
    const exchangeJwk = 'exchangePublicJwk' in key ? key.exchangePublicJwk : key.publicJwk
    const exchangeFingerprintValue = 'exchangeFingerprint' in key ? key.exchangeFingerprint : key.fingerprint
    const exchangeSignature = 'exchangeBindingSignature' in key ? key.exchangeBindingSignature : key.bindingSignature
    if (key.bindingVersion !== 1 || exchangeJwk.kty !== 'OKP' || exchangeJwk.crv !== 'X25519') return false
    if (key.signingPublicJwk.kty !== 'OKP' || key.signingPublicJwk.crv !== 'Ed25519') return false
    const [exchangeFingerprint, signingFingerprint] = await Promise.all([
      okpPublicKeyFingerprint(exchangeJwk), okpPublicKeyFingerprint(key.signingPublicJwk),
    ])
    if (exchangeFingerprint !== exchangeFingerprintValue || signingFingerprint !== key.signingFingerprint) return false
    const signingPublicKey = await crypto.subtle.importKey('jwk', key.signingPublicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' }, signingPublicKey, fromBase64URL(exchangeSignature),
      new TextEncoder().encode(exchangeKeyBindingInput(recipientUserId, key.signingKeyId, exchangeJwk)),
    )
  } catch {
    return false
  }
}

async function verifyPrekeyBinding(recipientUserId: string, key: OneTimePrekey) {
  try {
    if (!await verifyExchangeKeyBinding(recipientUserId, key)) return false
    if (key.publicJwk.kty !== 'OKP' || key.publicJwk.crv !== 'X25519' || key.bindingVersion !== 1) return false
    if (await okpPublicKeyFingerprint(key.publicJwk) !== key.fingerprint) return false
    const signingPublicKey = await crypto.subtle.importKey('jwk', key.signingPublicJwk, { name: 'Ed25519' }, false, ['verify'])
    return crypto.subtle.verify(
      { name: 'Ed25519' }, signingPublicKey, fromBase64URL(key.bindingSignature),
      new TextEncoder().encode(prekeyBindingInput(recipientUserId, key.signingKeyId, key.exchangeKeyId, key.publicJwk)),
    )
  } catch {
    return false
  }
}

async function recipientSafetyNumber(recipientUserId: string, fingerprints: string[]) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(
    lengthPrefixedInput('recipient-safety-number-v1', [recipientUserId, ...fingerprints]),
  )))
  const view = new DataView(digest.buffer)
  const groups: string[] = []
  for (let offset = 0; offset < 32; offset += 4) groups.push(String(view.getUint32(offset) % 100000).padStart(5, '0'))
  return groups.join(' ')
}

async function withDeviceLock<T>(userId: string, task: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: { request<TValue>(name: string, callback: () => Promise<TValue>): Promise<TValue> } }).locks
  if (locks) return locks.request(`chinese-can-fly-device-${userId}`, task)
  try {
    return await withLocalStorageLease(userId, task)
  } catch (caught) {
    if (caught instanceof DOMException) return task()
    throw caught
  }
}

async function withLocalStorageLease<T>(userId: string, task: () => Promise<T>) {
  const leaseKey = `chinese-can-fly-device-lock:${userId}`
  const owner = crypto.randomUUID()
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    const current = parseLease(localStorage.getItem(leaseKey))
    if (!current || current.expiresAt <= Date.now()) {
      localStorage.setItem(leaseKey, JSON.stringify({ owner, expiresAt: Date.now() + 2 * 60_000 }))
      if (parseLease(localStorage.getItem(leaseKey))?.owner === owner) {
        const heartbeat = window.setInterval(() => {
          if (parseLease(localStorage.getItem(leaseKey))?.owner === owner) {
            localStorage.setItem(leaseKey, JSON.stringify({ owner, expiresAt: Date.now() + 2 * 60_000 }))
          }
        }, 20_000)
        try {
          return await task()
        } finally {
          window.clearInterval(heartbeat)
          if (parseLease(localStorage.getItem(leaseKey))?.owner === owner) localStorage.removeItem(leaseKey)
        }
      }
    }
    await new Promise((resolve) => window.setTimeout(resolve, 75 + Math.random() * 100))
  }
  throw new Error('等待其他页面完成设备密钥初始化超时')
}

function parseLease(value: string | null): { owner: string; expiresAt: number } | undefined {
  if (!value) return undefined
  try {
    const parsed = JSON.parse(value) as { owner?: unknown; expiresAt?: unknown }
    if (typeof parsed.owner === 'string' && typeof parsed.expiresAt === 'number') return parsed as { owner: string; expiresAt: number }
  } catch { /* Ignore malformed leases. */ }
  return undefined
}

function browserDeviceLabel() {
  const platform = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform || navigator.platform || '未知平台'
  return `${platform} · ${navigator.userAgent.includes('Firefox') ? 'Firefox' : navigator.userAgent.includes('Edg/') ? 'Edge' : navigator.userAgent.includes('Chrome/') ? 'Chrome' : navigator.userAgent.includes('Safari/') ? 'Safari' : '浏览器'}`
}

function lengthPrefixedInput(header: string, fields: string[]) {
  const encoder = new TextEncoder()
  return `${header}\n${fields.map((field) => `${encoder.encode(field).byteLength}:${field}\n`).join('')}`
}

function sortedEnvelopes(envelopes: KeyEnvelope[]) {
  return [...envelopes].sort((left, right) => left.keyId < right.keyId ? -1 : left.keyId > right.keyId ? 1 : 0)
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 3)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(deviceStoreName)) request.result.createObjectStore(deviceStoreName, { keyPath: 'userId' })
      if (!request.result.objectStoreNames.contains(trustStoreName)) request.result.createObjectStore(trustStoreName, { keyPath: 'userId' })
      if (!request.result.objectStoreNames.contains(cacheStoreName)) {
        const cache = request.result.createObjectStore(cacheStoreName, { keyPath: 'id' })
        cache.createIndex('userId', 'userId')
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function idbGetDevice(userId: string): Promise<StoredDeviceKey | undefined> {
  return idbGet<StoredDeviceKey>(deviceStoreName, userId)
}

async function idbPutDevice(record: StoredDeviceKey): Promise<void> {
  return idbPut(deviceStoreName, record)
}

async function idbDeleteDevice(userId: string): Promise<void> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(deviceStoreName, 'readwrite')
    transaction.objectStore(deviceStoreName).delete(userId)
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

async function idbGetCache(userId: string, shareId: string): Promise<CachedDecryptedShare | undefined> {
  return idbGet<CachedDecryptedShare>(cacheStoreName, `${userId}:${shareId}`)
}

async function idbDeleteCache(id: string): Promise<void> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(cacheStoreName, 'readwrite')
    transaction.objectStore(cacheStoreName).delete(id)
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

async function idbDeleteExpiredCaches(userId: string) {
  const database = await openDatabase()
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(cacheStoreName, 'readwrite')
    const request = transaction.objectStore(cacheStoreName).index('userId').openCursor(IDBKeyRange.only(userId))
    request.onsuccess = () => {
      const cursor = request.result
      if (!cursor) return
      const cached = cursor.value as CachedDecryptedShare
      if (Date.parse(cached.expiresAt) <= Date.now() - 7 * 24 * 60 * 60 * 1000) cursor.delete()
      cursor.continue()
    }
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

async function idbDeleteUserCaches(userId: string) {
  const database = await openDatabase()
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(cacheStoreName, 'readwrite')
    const request = transaction.objectStore(cacheStoreName).index('userId').openCursor(IDBKeyRange.only(userId))
    request.onsuccess = () => {
      const cursor = request.result
      if (!cursor) return
      cursor.delete()
      cursor.continue()
    }
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

async function cacheShareAndConsumePrekey(stored: StoredDeviceKey, prekey: StoredPrekey, share: ShareRecord, plaintext: string) {
  if (!stored.cacheEncryptionKey) throw new Error('本机分享缓存密钥不可用')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const additionalData = cacheAdditionalData(stored.userId, share.id, share.expiresAt)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData }, stored.cacheEncryptionKey, new TextEncoder().encode(plaintext),
  )
  const cached: CachedDecryptedShare = {
    id: `${stored.userId}:${share.id}`, userId: stored.userId, shareId: share.id,
    ciphertext: toBase64URL(new Uint8Array(ciphertext)), iv: toBase64URL(iv), expiresAt: share.expiresAt,
  }
  const next = { ...stored, prekeys: (stored.prekeys ?? []).filter((candidate) => candidate !== prekey) }
  const database = await openDatabase()
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction([deviceStoreName, cacheStoreName], 'readwrite')
    transaction.objectStore(cacheStoreName).put(cached)
    transaction.objectStore(deviceStoreName).put(next)
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

async function decryptCachedShare(key: CryptoKey, cached: CachedDecryptedShare) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64URL(cached.iv), additionalData: cacheAdditionalData(cached.userId, cached.shareId, cached.expiresAt) },
      key, fromBase64URL(cached.ciphertext),
    )
    return new TextDecoder().decode(plaintext)
  } catch {
    await idbDeleteCache(cached.id)
    throw new Error('本机分享缓存校验失败')
  }
}

function cacheAdditionalData(userId: string, shareId: string, expiresAt: string) {
  return new TextEncoder().encode(lengthPrefixedInput('decrypted-share-cache-v1', [userId, shareId, expiresAt]))
}

async function idbGetTrust(userId: string): Promise<RecipientTrustRecord | undefined> {
  return idbGet<RecipientTrustRecord>(trustStoreName, userId)
}

async function idbPutTrust(record: RecipientTrustRecord): Promise<void> {
  return idbPut(trustStoreName, record)
}

async function idbGet<T>(storeName: string, key: string): Promise<T | undefined> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readonly')
    const request = transaction.objectStore(storeName).get(key)
    request.onsuccess = () => resolve(request.result as T | undefined)
    request.onerror = () => reject(request.error)
    transaction.oncomplete = () => database.close()
  })
}

async function idbPut(storeName: string, record: object): Promise<void> {
  const database = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, 'readwrite')
    transaction.objectStore(storeName).put(record)
    transaction.oncomplete = () => { database.close(); resolve() }
    transaction.onerror = () => { database.close(); reject(transaction.error) }
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, expected: string[]) {
  const keys = Object.keys(value).sort()
  return arraysEqual(keys, [...expected].sort())
}

function arraysEqual(left: string[], right: string[]) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function isBoundedString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isISODate(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value))
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
