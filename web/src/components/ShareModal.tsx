import { useState } from 'react'
import { createSignedShare } from '../crypto'
import { api } from '../api'
import type { Dashboard, RangeName, SharePayload, User } from '../types'

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
      const signed = await createSignedShare(user.id, JSON.stringify(snapshot), encrypted)
      const created = await api.createShare(signed)
      const url = `${created.url}${signed.encrypted ? `#key=${signed.fragmentKey}` : ''}`
      setShareURL(url)
    } catch (caught) {
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
          <p>生成带数字签名的分享卡片。加密开启后，服务器只会看到 AES-GCM 密文。</p>
          <label className="message-field">
            <span>分享寄语</span>
            <textarea value={message} maxLength={280} rows={4} onChange={(event) => setMessage(event.target.value)} />
            <small>{message.length}/280</small>
          </label>
          <label className="encryption-toggle">
            <span><strong>AES-GCM 端到端加密</strong><small>密钥只存在于分享链接的 #fragment 中</small></span>
            <input type="checkbox" checked={encrypted} onChange={(event) => setEncrypted(event.target.checked)} />
          </label>
          <div className="crypto-note"><span>✓</span> 每份分享都由本设备 ECDSA P-256 密钥签名，接收方会自动验证。</div>
          <button className="primary-modal-button" onClick={createShare} disabled={busy || !message.trim()}>{busy ? '正在加密和签名…' : '生成分享链接'}</button>
          <small className="expiry-note">链接将在 {Math.round(ttlHours / 24)} 天后过期</small>
        </> : <>
          <p>分享链接已经生成。{encrypted ? '请完整复制，# 后面的密钥不会发送给服务器。' : '这是一条公开的签名分享。'}</p>
          <div className="share-link"><input readOnly value={shareURL} /><button onClick={copy}>{copied ? '已复制' : '复制'}</button></div>
          <button className="primary-modal-button" onClick={nativeShare}>分享给朋友</button>
          <div className="signature-valid">✓ 已在服务器端验证设备签名</div>
        </>}
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  )
}

