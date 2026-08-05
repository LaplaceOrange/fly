import { useEffect, useState } from 'react'
import { createSignedShare, inspectRecipientPrekeys, trustRecipientIdentity } from '../crypto'
import { api } from '../api'
import { APIError, type Dashboard, type OneTimePrekey, type RangeName, type RecipientTrustInspection, type SharePayload, type ShareRecipient, type User } from '../types'

export function ShareModal({ user, dashboard, range, ttlHours, onClose }: {
  user: User
  dashboard: Dashboard
  range: RangeName
  ttlHours: number
  onClose: () => void
}) {
  const [message, setMessage] = useState('我刚刚确认：中国人真的能飞。')
  const [encrypted, setEncrypted] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [shareURL, setShareURL] = useState('')
  const [copied, setCopied] = useState(false)
  const [recipients, setRecipients] = useState<ShareRecipient[]>([])
  const [recipientUserId, setRecipientUserId] = useState('')
  const [recipientsLoading, setRecipientsLoading] = useState(true)
  const [recipientKeys, setRecipientKeys] = useState<OneTimePrekey[]>([])
  const [prekeyClaimToken, setPrekeyClaimToken] = useState('')
  const [trustInspection, setTrustInspection] = useState<RecipientTrustInspection>()
  const [recipientKeysLoading, setRecipientKeysLoading] = useState(false)
  const [claimRevision, setClaimRevision] = useState(0)

  useEffect(() => {
    let active = true
    api.shareRecipients().then(({ recipients: nextRecipients }) => {
      if (!active) return
      setRecipients(nextRecipients)
      setRecipientUserId((current) => current || nextRecipients[0]?.id || '')
    }).catch((caught) => active && setError(caught instanceof Error ? caught.message : '无法加载加密分享接收者'))
      .finally(() => active && setRecipientsLoading(false))
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (!encrypted || !recipientUserId) {
      setRecipientKeys([])
      setPrekeyClaimToken('')
      setTrustInspection(undefined)
      setRecipientKeysLoading(false)
      return
    }
    let active = true
    setError('')
    setRecipientKeys([])
    setPrekeyClaimToken('')
    setTrustInspection(undefined)
    setRecipientKeysLoading(true)
    api.claimRecipientPrekeys(recipientUserId)
      .then(async ({ keys, claimToken }) => ({ keys, claimToken, inspection: await inspectRecipientPrekeys(recipientUserId, keys) }))
      .then(({ keys, claimToken, inspection }) => {
        if (!active) return
        setRecipientKeys(keys)
        setPrekeyClaimToken(claimToken)
        setTrustInspection(inspection)
      })
      .catch((caught) => active && setError(caught instanceof Error ? caught.message : '无法读取接收者设备公钥'))
      .finally(() => active && setRecipientKeysLoading(false))
    return () => { active = false }
  }, [encrypted, recipientUserId, claimRevision])

  const trustRecipient = async () => {
    if (!trustInspection || !recipientUserId) return
    await trustRecipientIdentity(recipientUserId, trustInspection)
    setTrustInspection({ ...trustInspection, status: 'trusted' })
  }

  const createShare = async () => {
    setBusy(true)
    setError('')
    try {
      if (!window.isSecureContext || !window.crypto?.subtle) throw new Error('加密分享需要 HTTPS 或 localhost 安全环境')
      const snapshot: SharePayload = {
        version: 1,
        sharedAt: new Date().toISOString(),
        message: message.trim(),
        user: {
          id: user.id, username: user.username, displayName: user.displayName, avatarUrl: user.avatarUrl,
          totalFlights: user.totalFlights, lastFlightAt: user.lastFlightAt,
        },
        snapshot: {
          totalFlights: dashboard.summary.totalFlights,
          totalUsers: dashboard.summary.totalUsers,
          rangeFlights: dashboard.summary.rangeFlights,
          range,
        },
      }
      if (encrypted && !recipientUserId) throw new Error('请选择一名已注册 X25519 设备密钥的接收者')
      if (encrypted && !recipientKeys.length) throw new Error('接收者当前没有可用于密钥交换的设备公钥')
      const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString()
      if (encrypted && trustInspection?.status !== 'trusted') throw new Error('请先核对并确认接收者安全码')
      const signed = encrypted
        ? await createSignedShare(user.id, JSON.stringify(snapshot), expiresAt, {
            encrypted: true, recipientUserId, recipientKeys, claimToken: prekeyClaimToken,
          })
        : await createSignedShare(user.id, JSON.stringify(snapshot), expiresAt, { encrypted: false })
      const created = await api.createShare(signed)
      setShareURL(created.url)
    } catch (caught) {
      if (caught instanceof APIError && caught.code === 'prekey_claim_expired') {
        setClaimRevision((current) => current + 1)
        setError('一次性预密钥已刷新，请再次生成分享')
        return
      }
      setError(caught instanceof Error ? caught.message : '创建分享失败')
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    await navigator.clipboard.writeText(shareURL)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1800)
  }

  const nativeShare = async () => {
    if (!navigator.share) return copy()
    await navigator.share({ title: '中国人能飞', text: message, url: shareURL })
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !busy && onClose()}>
      <section className="modal share-modal" role="dialog" aria-modal="true" aria-labelledby="share-title">
        <button className="modal-close" aria-label="关闭" onClick={onClose} disabled={busy}>×</button>
        <span className="modal-icon modal-icon--share">⌁</span>
        <h2 id="share-title">分享起飞状态</h2>
        {!shareURL ? <>
          <p>生成由 Ed25519 签名的分享卡片。加密开启后，将通过接收者的一次性 X25519 预密钥完成密钥交换。</p>
          <label className="message-field">
            <span>分享寄语</span>
            <textarea value={message} maxLength={280} rows={4} onChange={(event) => setMessage(event.target.value)} />
            <small>{message.length}/280</small>
          </label>
          <label className="encryption-toggle">
            <span><strong>指定接收者端到端加密</strong><small>一次性 X25519 · HKDF-SHA-256 · AES-256-GCM</small></span>
            <input type="checkbox" checked={encrypted} onChange={(event) => setEncrypted(event.target.checked)} />
          </label>
          {encrypted && <div className="recipient-field">
            <span>接收者</span>
            <select value={recipientUserId} disabled={recipientsLoading || !recipients.length} onChange={(event) => setRecipientUserId(event.target.value)}>
              {recipientsLoading && <option value="">正在加载可用接收者…</option>}
              {!recipientsLoading && !recipients.length && <option value="">暂无已注册加密设备的其他用户</option>}
              {recipients.map((recipient) => <option key={recipient.id} value={recipient.id}>{recipient.displayName} (@{recipient.username}) · {recipient.deviceCount} 台设备</option>)}
            </select>
            <span className="key-fingerprints">
              <strong>已验证 Ed25519 绑定的设备公钥</strong>
              {recipientKeysLoading && <small>正在领取并验证一次性 X25519 预密钥…</small>}
              {!recipientKeysLoading && recipientKeys.map((key, index) => <small key={key.keyId} title={`一次性 X25519 ${key.fingerprint}\nEd25519 ${key.signingFingerprint}`}>{key.deviceLabel || `设备 ${index + 1}`} · OTPK {key.fingerprint.slice(0, 12)}… · Ed {key.signingFingerprint.slice(0, 12)}…</small>)}
            </span>
            {trustInspection && <span className={`trust-check trust-check--${trustInspection.status}`}>
              <strong>{trustInspection.status === 'trusted' ? '✓ 接收者身份密钥与已信任记录一致' : trustInspection.status === 'changed' ? '⚠ 接收者设备签名密钥发生变化' : '首次向该接收者加密'}</strong>
              <small>安全码：<code>{trustInspection.safetyNumber}</code></small>
              {trustInspection.status !== 'trusted' && <button type="button" onClick={trustRecipient}>我已通过独立渠道核对，信任此安全码</button>}
            </span>}
          </div>}
          <div className="crypto-note"><span>✓</span> 每份分享由本设备 Ed25519 私钥签名；AES 内容密钥仅由经核对的一次性设备预密钥包装。</div>
          <button className="primary-modal-button" onClick={createShare} disabled={busy || recipientKeysLoading || !message.trim() || (encrypted && (!recipientUserId || !recipientKeys.length || !prekeyClaimToken || trustInspection?.status !== 'trusted'))}>{busy ? '正在交换一次性密钥、加密和签名…' : '生成分享链接'}</button>
          <small className="expiry-note">链接将在 {Math.round(ttlHours / 24)} 天后过期</small>
        </> : <>
          <p>分享链接已经生成。{encrypted ? '只有指定接收者持有对应一次性 X25519 私钥的设备可以解密；成功解密后该私钥会从本机删除。' : '这是一条公开的 Ed25519 签名分享。'}</p>
          <div className="share-link"><input readOnly value={shareURL} /><button onClick={copy}>{copied ? '已复制' : '复制'}</button></div>
          <button className="primary-modal-button" onClick={nativeShare}>分享给朋友</button>
          <div className="signature-valid">✓ 已验证 Ed25519 设备签名</div>
        </>}
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  )
}
