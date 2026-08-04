import { api } from './api'
import type { PublicJWK } from './types'

interface StoredDeviceKey {
  userId: string
  keyId: string
  fingerprint: string
  publicJwk: PublicJWK
  privateKey: CryptoKey
}

const databaseName = 'chinese-can-fly-crypto'
const storeName = 'device-keys'

export function shareSigningInput(encrypted: boolean, payload: string, iv: string) {
  return `share-sign-v1\n${encrypted ? '1' : '0'}\n${payload}\n${iv}`
}

export async function createSignedShare(userId: string, plaintext: string, encrypted: boolean) {
  const deviceKey = await ensureDeviceKey(userId)
  let payload = plaintext
  let iv = ''
  let fragmentKey = ''
  if (encrypted) {
    const encryptedResult = await encryptAESGCM(plaintext)
    payload = encryptedResult.ciphertext
    iv = encryptedResult.iv
    fragmentKey = encryptedResult.key
  }
  const data = new TextEncoder().encode(shareSigningInput(encrypted, payload, iv))
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, deviceKey.privateKey, data)
  return {
    encrypted, payload, iv, keyId: deviceKey.keyId,
    signature: toBase64URL(new Uint8Array(signature)), fragmentKey,
  }
}

export async function verifyShare(publicJwk: PublicJWK, encrypted: boolean, payload: string, iv: string, signature: string) {
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, publicKey, fromBase64URL(signature),
    new TextEncoder().encode(shareSigningInput(encrypted, payload, iv)),
  )
}

export async function decryptAESGCM(ciphertext: string, iv: string, key: string) {
  const aesKey = await crypto.subtle.importKey('raw', fromBase64URL(key), 'AES-GCM', false, ['decrypt'])
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64URL(iv) }, aesKey, fromBase64URL(ciphertext))
  return new TextDecoder().decode(plaintext)
}

async function encryptAESGCM(plaintext: string) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt'])
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext))
  return { ciphertext: toBase64URL(new Uint8Array(ciphertext)), iv: toBase64URL(iv), key: toBase64URL(rawKey) }
}

async function ensureDeviceKey(userId: string): Promise<StoredDeviceKey> {
  const existing = await idbGet(userId)
  if (existing) return existing
  const generated = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey) as PublicJWK
  const privateJwk = await crypto.subtle.exportKey('jwk', generated.privateKey)
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const registered = await api.registerKey(publicJwk)
  const record: StoredDeviceKey = {
    userId, keyId: registered.keyId, fingerprint: registered.fingerprint, publicJwk, privateKey,
  }
  await idbPut(record)
  return record
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
