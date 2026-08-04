import { useEffect, useRef, useState } from 'react'

interface TurnstileOptions {
  sitekey: string
  action: string
  theme: 'auto'
  callback: (token: string) => void
  'error-callback': () => void
  'expired-callback': () => void
}

interface TurnstileAPI {
  render: (container: HTMLElement, options: TurnstileOptions) => string
  reset: (widgetId: string) => void
  remove: (widgetId: string) => void
}

declare global {
  interface Window { turnstile?: TurnstileAPI }
}

let scriptPromise: Promise<void> | undefined

function loadTurnstile() {
  if (window.turnstile) return Promise.resolve()
  if (scriptPromise) return scriptPromise
  scriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    script.async = true
    script.defer = true
    script.onload = () => resolve()
    script.onerror = () => reject(new Error('人机验证组件加载失败'))
    document.head.appendChild(script)
  })
  return scriptPromise
}

export function TurnstileModal({ siteKey, onClose, onVerify }: {
  siteKey: string
  onClose: () => void
  onVerify: (token: string) => Promise<void>
}) {
  const container = useRef<HTMLDivElement>(null)
  const widgetId = useRef<string | undefined>(undefined)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let active = true
    loadTurnstile().then(() => {
      if (!active || !container.current || !window.turnstile) return
      widgetId.current = window.turnstile.render(container.current, {
        sitekey: siteKey,
        action: 'turnstile-spin-v2',
        theme: 'auto',
        callback: async (token) => {
          setSubmitting(true)
          setError('')
          try {
            await onVerify(token)
          } catch (caught) {
            setError(caught instanceof Error ? caught.message : '起飞失败，请重试')
            if (widgetId.current) window.turnstile?.reset(widgetId.current)
          } finally {
            setSubmitting(false)
          }
        },
        'error-callback': () => setError('人机验证失败，请重试'),
        'expired-callback': () => setError('验证已过期，请重新完成验证'),
      })
    }).catch((caught) => setError(caught instanceof Error ? caught.message : '人机验证组件加载失败'))
    return () => {
      active = false
      if (widgetId.current) window.turnstile?.remove(widgetId.current)
    }
  }, [onVerify, siteKey])

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !submitting && onClose()}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="turnstile-title">
        <button className="modal-close" aria-label="关闭" onClick={onClose} disabled={submitting}>×</button>
        <span className="modal-icon">↗</span>
        <h2 id="turnstile-title">准备起飞</h2>
        <p>完成 Cloudflare 人机验证后，这次起飞会立即展示给所有人。</p>
        <div className="turnstile-box" ref={container} />
        {submitting && <p className="modal-status">正在记录你的起飞…</p>}
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  )
}
