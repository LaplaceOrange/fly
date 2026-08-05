import { useEffect, useState } from 'react'
import { api } from '../api'
import { decryptLegacyAESGCM, decryptModernShare, verifyShare } from '../crypto'
import { APIError, type SharePayload, type ShareRecord } from '../types'
import { Avatar } from './Avatar'

export function SharePage({ id }: { id: string }) {
  const [record, setRecord] = useState<ShareRecord>()
  const [payload, setPayload] = useState<SharePayload>()
  const [signatureValid, setSignatureValid] = useState<boolean>()
  const [legacyKey, setLegacyKey] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get('key') ?? '')
  const [authRequired, setAuthRequired] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api.share(id).then(async (share) => {
      if (!active) return
      setRecord(share)
      const valid = await verifyShare(share)
      if (!active) return
      setSignatureValid(valid)
      if (!valid) throw new Error('分享签名无效，内容可能已被篡改')
      if (!share.encrypted) {
        setPayload(JSON.parse(share.payload) as SharePayload)
      } else if (share.signatureVersion >= 2) {
        const me = await api.me()
        if (!me.authenticated) throw new Error('请登录接收者账号后解密此分享')
        setPayload(JSON.parse(await decryptModernShare(me.user.id, share)) as SharePayload)
      } else if (legacyKey) {
        setPayload(JSON.parse(await decryptLegacyAESGCM(share.payload, share.iv, legacyKey)) as SharePayload)
      }
    }).catch((caught) => {
      if (!active) return
      if (caught instanceof APIError && caught.status === 401) {
        setAuthRequired(true)
        return
      }
      setError(caught instanceof Error ? caught.message : '无法打开分享')
    }).finally(() => active && setLoading(false))
    return () => { active = false }
  }, [id])

  const decryptLegacy = async () => {
    if (!record || !legacyKey) return
    setError('')
    try {
      const plaintext = await decryptLegacyAESGCM(record.payload, record.iv, legacyKey.trim())
      setPayload(JSON.parse(plaintext) as SharePayload)
      window.history.replaceState({}, '', `${window.location.pathname}#key=${legacyKey.trim()}`)
    } catch {
      setError('解密失败：密钥不正确或密文已损坏')
    }
  }

  const login = () => {
    window.location.href = `/api/auth/login?return_to=${encodeURIComponent(window.location.pathname)}`
  }

  if (loading) return <div className="loading-screen"><span className="brand-mark">飞</span><p>正在验证分享签名并协商密钥…</p></div>

  return (
    <div className="share-page">
      <header className="share-page-header"><a className="brand" href="/"><span className="brand-mark">飞</span><span><strong>中国人能飞</strong><small>VERIFIED SHARE</small></span></a></header>
      <main className="share-stage">
        <section className="share-card-public">
          <div className="share-card-top">
            <span className="eyebrow">SIGNED FLIGHT SHARE</span>
            {signatureValid === true && <span className="verified-pill">✓ 签名有效</span>}
            {signatureValid === false && <span className="invalid-pill">签名无效</span>}
          </div>
          {record && <div className="share-signer"><Avatar user={record.signer} size={50} /><div><small>分享者</small><strong>{record.signer.displayName}</strong><span>@{record.signer.username}</span></div></div>}
          {authRequired ? (
            <div className="decrypt-panel">
              <span className="lock-icon">◇</span>
              <h1>请验证接收者身份</h1>
              <p>这是指定接收者的端到端加密分享。登录对应的 CPOAuth 账号后，浏览器会使用本设备 X25519 私钥自动解密。</p>
              <button className="primary-modal-button" onClick={login}>登录并解密</button>
            </div>
          ) : record?.encrypted && !payload ? (
            record.signatureVersion >= 2 ? (
              <div className="decrypt-panel">
                <span className="lock-icon">◇</span>
                <h1>端到端加密分享</h1>
                <p>系统已验证接收者身份，但此设备需要拥有分享创建时对应的 X25519 私钥。设备私钥不会上传服务器。</p>
              </div>
            ) : (
              <div className="decrypt-panel">
                <span className="lock-icon">◇</span>
                <h1>旧版加密分享</h1>
                <p>这是兼容保留的 URL 密钥分享。请使用完整链接，或粘贴 #key= 后的密钥。</p>
                <div className="share-link"><input value={legacyKey} onChange={(event) => setLegacyKey(event.target.value)} placeholder="粘贴旧版解密密钥" /><button onClick={decryptLegacy}>解密</button></div>
              </div>
            )
          ) : payload ? (
            <div className="shared-content">
              <blockquote>“{payload.message}”</blockquote>
              <div className="shared-stats">
                <div><small>我的累计起飞</small><strong>{payload.user.totalFlights}</strong><span>次</span></div>
                <div><small>全站累计起飞</small><strong>{payload.snapshot.totalFlights}</strong><span>次</span></div>
                <div><small>全站飞行员</small><strong>{payload.snapshot.totalUsers}</strong><span>人</span></div>
              </div>
              <p className="share-time">分享于 {formatDate(payload.sharedAt)}</p>
            </div>
          ) : null}
          {record && <div className="crypto-proof">
            <span>{record.encrypted ? (record.signatureVersion >= 2 ? 'X25519 + AES-256-GCM' : '旧版 AES-256-GCM') : '公开内容'}</span>
            <span>{record.signingAlgorithm === 'Ed25519' ? 'Ed25519' : '旧版 ECDSA P-256'}</span>
            <span title={record.fingerprint}>密钥指纹 {record.fingerprint.slice(0, 12)}…</span>
          </div>}
          {error && <p className="form-error" role="alert">{error}</p>}
        </section>
        <a className="back-link" href="/">返回实时起飞仪表盘 →</a>
      </main>
    </div>
  )
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'long', timeStyle: 'short' }).format(new Date(value))
}
