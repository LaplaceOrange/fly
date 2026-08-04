import { useEffect, useState } from 'react'
import { api } from '../api'
import { decryptAESGCM, verifyShare } from '../crypto'
import type { SharePayload, ShareRecord } from '../types'
import { Avatar } from './Avatar'

export function SharePage({ id }: { id: string }) {
  const [record, setRecord] = useState<ShareRecord>()
  const [payload, setPayload] = useState<SharePayload>()
  const [signatureValid, setSignatureValid] = useState<boolean>()
  const [decryptionKey, setDecryptionKey] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get('key') ?? '')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    api.share(id).then(async (share) => {
      if (!active) return
      setRecord(share)
      const valid = await verifyShare(share.publicJwk, share.encrypted, share.payload, share.iv, share.signature)
      if (!active) return
      setSignatureValid(valid)
      if (!valid) throw new Error('分享签名无效，内容可能已被篡改')
      if (!share.encrypted) setPayload(JSON.parse(share.payload) as SharePayload)
      else if (decryptionKey) setPayload(JSON.parse(await decryptAESGCM(share.payload, share.iv, decryptionKey)) as SharePayload)
    }).catch((caught) => active && setError(caught instanceof Error ? caught.message : '无法打开分享')).finally(() => active && setLoading(false))
    return () => { active = false }
  }, [id])

  const decrypt = async () => {
    if (!record || !decryptionKey) return
    setError('')
    try {
      const plaintext = await decryptAESGCM(record.payload, record.iv, decryptionKey.trim())
      setPayload(JSON.parse(plaintext) as SharePayload)
      window.history.replaceState({}, '', `${window.location.pathname}#key=${decryptionKey.trim()}`)
    } catch {
      setError('解密失败：密钥不正确或密文已损坏')
    }
  }

  if (loading) return <div className="loading-screen"><span className="brand-mark">飞</span><p>正在验证分享签名…</p></div>

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
          {record?.encrypted && !payload ? (
            <div className="decrypt-panel">
              <span className="lock-icon">◇</span>
              <h1>这是一份端到端加密分享</h1>
              <p>AES-GCM 密钥不会保存在服务器。请使用完整分享链接，或在下面粘贴 #key= 后的密钥。</p>
              <div className="share-link"><input value={decryptionKey} onChange={(event) => setDecryptionKey(event.target.value)} placeholder="粘贴解密密钥" /><button onClick={decrypt}>解密</button></div>
            </div>
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
          {record && <div className="crypto-proof"><span>{record.encrypted ? 'AES-256-GCM' : '公开内容'}</span><span>ECDSA P-256</span><span title={record.fingerprint}>密钥指纹 {record.fingerprint.slice(0, 12)}…</span></div>}
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
