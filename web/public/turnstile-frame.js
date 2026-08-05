(() => {
  'use strict'
  let nonce = ''
  let widgetId
  let scriptPromise

  const send = (type, extra = {}) => window.parent.postMessage({
    source: 'chinese-can-fly-turnstile', nonce, type, ...extra,
  }, '*')

  const loadTurnstile = () => {
    if (window.turnstile) return Promise.resolve()
    if (scriptPromise) return scriptPromise
    scriptPromise = new Promise((resolve, reject) => {
      const script = document.createElement('script')
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
      script.async = true
      script.defer = true
      script.onload = resolve
      script.onerror = reject
      document.head.appendChild(script)
    })
    return scriptPromise
  }

  window.addEventListener('message', async (event) => {
    const message = event.data
    if (event.source !== window.parent || !message || message.source !== 'chinese-can-fly-parent') return
    if (message.type === 'reset' && message.nonce === nonce && widgetId && window.turnstile) {
      window.turnstile.reset(widgetId)
      return
    }
    if (message.type !== 'init' || typeof message.nonce !== 'string' || typeof message.siteKey !== 'string') return
    nonce = message.nonce
    try {
      await loadTurnstile()
      if (widgetId) window.turnstile.remove(widgetId)
      widgetId = window.turnstile.render('#widget', {
        sitekey: message.siteKey,
        action: message.action,
        theme: 'auto',
        callback: (token) => send('token', { token }),
        'error-callback': () => send('error'),
        'expired-callback': () => send('expired'),
      })
    } catch {
      send('error')
    }
  })

  send('ready')
})()
