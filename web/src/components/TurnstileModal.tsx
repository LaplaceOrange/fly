import { useCallback, useEffect, useRef, useState } from 'react'

interface TurnstileFrameMessage {
  source: 'chinese-can-fly-turnstile'
  nonce: string
  type: 'ready' | 'token' | 'error' | 'expired'
  token?: string
}

export function TurnstileModal({ siteKey, onClose, onVerify }: {
  siteKey: string
  onClose: () => void
  onVerify: (token: string) => Promise<void>
}) {
  const frame = useRef<HTMLIFrameElement>(null)
  const nonce = useRef(crypto.randomUUID())
  const submittingRef = useRef(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const initializeFrame = useCallback(() => {
    frame.current?.contentWindow?.postMessage({
      source: 'chinese-can-fly-parent', type: 'init', nonce: nonce.current,
      siteKey, action: 'turnstile-spin-v2',
    }, '*')
  }, [siteKey])

  useEffect(() => {
    let active = true
    const receive = async (event: MessageEvent<TurnstileFrameMessage>) => {
      if (!active || event.source !== frame.current?.contentWindow) return
      const message = event.data
      if (!message || message.source !== 'chinese-can-fly-turnstile' || message.nonce !== nonce.current) return
      if (message.type === 'ready') {
        initializeFrame()
        return
      }
      if (message.type === 'error') {
        setError('人机验证失败，请重试')
        return
      }
      if (message.type === 'expired') {
        setError('验证已过期，请重新完成验证')
        return
      }
      if (message.type !== 'token' || !message.token || submittingRef.current) return
      submittingRef.current = true
      setSubmitting(true)
      setError('')
      try {
        await onVerify(message.token)
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : '起飞失败，请重试')
        frame.current?.contentWindow?.postMessage({ source: 'chinese-can-fly-parent', type: 'reset', nonce: nonce.current }, '*')
      } finally {
        submittingRef.current = false
        if (active) setSubmitting(false)
      }
    }
    window.addEventListener('message', receive)
    return () => {
      active = false
      window.removeEventListener('message', receive)
    }
  }, [initializeFrame, onVerify])

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !submitting && onClose()}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="turnstile-title">
        <button className="modal-close" aria-label="关闭" onClick={onClose} disabled={submitting}>×</button>
        <span className="modal-icon">✈</span>
        <h2 id="turnstile-title">准备起飞</h2>
        <p>完成 Cloudflare 人机验证后，这次起飞会立即展示给所有人。</p>
        <iframe
          ref={frame}
          className="turnstile-frame"
          title="Cloudflare 人机验证"
          src="/turnstile-frame.html"
          sandbox="allow-scripts allow-same-origin allow-forms"
          referrerPolicy="no-referrer"
          onLoad={initializeFrame}
        />
        {submitting && <p className="modal-status">正在记录你的起飞…</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  )
}
