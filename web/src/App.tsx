import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { ActivityFeed } from './components/ActivityFeed'
import { Avatar } from './components/Avatar'
import { Heatmap } from './components/Heatmap'
import { Leaderboard } from './components/Leaderboard'
import { ShareModal } from './components/ShareModal'
import { SharePage } from './components/SharePage'
import { TakeoffSuccessModal } from './components/TakeoffSuccessModal'
import { TrendChart } from './components/TrendChart'
import { TurnstileModal } from './components/TurnstileModal'
import { UserTable } from './components/UserTable'
import { APIError, type Dashboard, type Me, type PublicConfig, type RangeName, type RealtimeEvent, type UserStatus } from './types'

const ranges: Array<{ value: RangeName; label: string }> = [
  { value: '24h', label: '24 小时' },
  { value: '7d', label: '7 天' },
  { value: '1month', label: '1 个月' },
  { value: 'all', label: '全部' },
]

export default function App() {
  const shareMatch = window.location.pathname.match(/^\/share\/([A-Za-z0-9_-]+)$/)
  return shareMatch ? <SharePage id={shareMatch[1]} /> : <DashboardApp />
}

function DashboardApp() {
  const [config, setConfig] = useState<PublicConfig>()
  const [me, setMe] = useState<Me>({ authenticated: false })
  const [range, setRange] = useState<RangeName>('24h')
  const [dashboard, setDashboard] = useState<Dashboard>()
  const [users, setUsers] = useState<UserStatus[]>([])
  const [userCursor, setUserCursor] = useState('')
  const [userSort, setUserSort] = useState('last_flight')
  const [loading, setLoading] = useState(true)
  const [loadingUsers, setLoadingUsers] = useState(false)
  const [error, setError] = useState('')
  const [realtime, setRealtime] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [turnstileOpen, setTurnstileOpen] = useState(false)
  const [shareOpen, setShareOpen] = useState(false)
  const [takeoffSuccessOpen, setTakeoffSuccessOpen] = useState(false)
  const [now, setNow] = useState(Date.now())
  const refreshTimer = useRef<number | undefined>(undefined)

  const refreshUsers = useCallback(async (sort = userSort) => {
    const page = await api.users(sort)
    setUsers(page.users)
    setUserCursor(page.nextCursor ?? '')
  }, [userSort])

  const refresh = useCallback(async () => {
    const [nextDashboard, nextMe, nextUsers] = await Promise.all([
      api.dashboard(range), api.me(), api.users(userSort),
    ])
    setDashboard(nextDashboard)
    setMe(nextMe)
    setUsers(nextUsers.users)
    setUserCursor(nextUsers.nextCursor ?? '')
  }, [range, userSort])

  useEffect(() => {
    let active = true
    setLoading(true)
    Promise.all([api.config(), api.me(), api.dashboard(range), api.users(userSort)])
      .then(([nextConfig, nextMe, nextDashboard, nextUsers]) => {
        if (!active) return
        setConfig(nextConfig)
        setMe(nextMe)
        setDashboard(nextDashboard)
        setUsers(nextUsers.users)
        setUserCursor(nextUsers.nextCursor ?? '')
      })
      .catch((caught) => active && setError(errorMessage(caught)))
      .finally(() => active && setLoading(false))
    const authError = new URLSearchParams(window.location.search).get('auth_error')
    if (authError) {
      setError('CPOAuth 登录没有完成，请重试。')
      window.history.replaceState({}, '', window.location.pathname)
    }
    return () => { active = false }
    // Initial load only; range and sort changes have dedicated effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (loading) return
    api.dashboard(range).then(setDashboard).catch((caught) => setError(errorMessage(caught)))
  }, [range, loading])

  useEffect(() => {
    if (loading) return
    setLoadingUsers(true)
    refreshUsers(userSort).catch((caught) => setError(errorMessage(caught))).finally(() => setLoadingUsers(false))
  }, [userSort, loading, refreshUsers])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    let socket: WebSocket | undefined
    let retryTimer: number | undefined
    let stopped = false
    let attempts = 0
    const connect = () => {
      setRealtime(attempts ? 'disconnected' : 'connecting')
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/api/realtime`)
      socket.onopen = () => { attempts = 0; setRealtime('connected') }
      socket.onmessage = (message) => {
        const event = JSON.parse(message.data) as RealtimeEvent
        if (event.type === 'flight.created' && event.flight) {
          setDashboard((current) => current ? {
            ...current,
            revision: event.revision,
            recentFlights: [event.flight!, ...current.recentFlights.filter((flight) => flight.id !== event.flight?.id)].slice(0, 20),
          } : current)
          if (refreshTimer.current) window.clearTimeout(refreshTimer.current)
          refreshTimer.current = window.setTimeout(() => refresh().catch(() => undefined), 300)
        }
      }
      socket.onclose = () => {
        if (stopped) return
        setRealtime('disconnected')
        attempts += 1
        retryTimer = window.setTimeout(connect, Math.min(15_000, 750 * 2 ** attempts))
      }
      socket.onerror = () => socket?.close()
    }
    connect()
    return () => {
      stopped = true
      if (retryTimer) window.clearTimeout(retryTimer)
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current)
      socket?.close()
    }
  }, [refresh])

  const cooldownSeconds = useMemo(() => {
    if (!me.authenticated || !me.nextAllowedAt) return 0
    return Math.max(0, Math.ceil((new Date(me.nextAllowedAt).getTime() - now) / 1000))
  }, [me, now])

  const handleTakeoff = () => {
    if (!me.authenticated) {
      window.location.href = `/api/auth/login?return_to=${encodeURIComponent(window.location.pathname + window.location.search)}`
      return
    }
    if (!me.canTakeoff && cooldownSeconds > 0) return
    setTurnstileOpen(true)
  }

  const handleShare = () => {
    if (!me.authenticated) {
      window.location.href = `/api/auth/login?return_to=${encodeURIComponent(window.location.pathname)}`
      return
    }
    setShareOpen(true)
  }

  const verifyTakeoff = useCallback(async (token: string) => {
    try {
      const result = await api.takeoff(token)
      setTurnstileOpen(false)
      setTakeoffSuccessOpen(true)
      setMe((current) => current.authenticated ? { ...current, canTakeoff: false, nextAllowedAt: result.nextAllowedAt } : current)
      await refresh()
    } catch (caught) {
      if (caught instanceof APIError && caught.status === 429) {
        setMe((current) => current.authenticated ? { ...current, canTakeoff: false, nextAllowedAt: caught.nextAllowedAt ?? current.nextAllowedAt } : current)
      }
      throw new Error(errorMessage(caught))
    }
  }, [refresh])

  const logout = async () => {
    await api.logout()
    setMe({ authenticated: false })
  }

  const loadMoreUsers = async () => {
    if (!userCursor) return
    setLoadingUsers(true)
    try {
      const page = await api.users(userSort, userCursor)
      setUsers((current) => [...current, ...page.users])
      setUserCursor(page.nextCursor ?? '')
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoadingUsers(false)
    }
  }

  if (loading) return <LoadingScreen />

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="/" aria-label="回到首页">
          <span className="brand-mark">飞</span>
          <span><strong>{config?.siteName ?? '中国人能飞'}</strong><small>FLIGHT STATUS</small></span>
        </a>
        <div className="header-actions">
          <span className={`live-state live-state--${realtime}`}><i />{realtime === 'connected' ? '实时在线' : realtime === 'connecting' ? '正在连接' : '重新连接中'}</span>
          {me.authenticated ? (
            <div className="account">
              <Avatar user={me.user} size={34} />
              <span><strong>{me.user.displayName}</strong><button onClick={logout}>退出登录</button></span>
            </div>
          ) : <button className="text-button" onClick={() => window.location.href = '/api/auth/login'}>CPOAuth 登录</button>}
        </div>
      </header>

      <main>
        {error && <div className="error-banner" role="alert"><span>{error}</span><button onClick={() => setError('')}>×</button></div>}
        <section className="hero">
          <div className="hero-copy">
            <span className="eyebrow">LIVE TAKEOFF NETWORK · 实时起飞网络</span>
            <h1>此刻，<em>中国人能飞。</em></h1>
            <p>记录每一次起飞，让全站共同见证。数据持续更新，排行榜绝不落地。</p>
            <div className="hero-actions">
              <button className="takeoff-button" onClick={handleTakeoff} disabled={me.authenticated && !me.canTakeoff && cooldownSeconds > 0}>
                <span>立即起飞！</span><i>↗</i>
              </button>
              <button className="share-button" onClick={handleShare}>分享状态 <span>⌁</span></button>
              {me.authenticated && cooldownSeconds > 0
                ? <span className="cooldown">距离下次起飞还有 {formatDuration(cooldownSeconds)}</span>
                : <span className="hero-note">通过 CPOAuth 验证身份 · Cloudflare 人机验证</span>}
            </div>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <div className="orbit orbit--one" /><div className="orbit orbit--two" />
            <span className="plane">↗</span>
            <div className="altitude"><small>当前总起飞</small><strong>{dashboard?.summary.totalFlights.toLocaleString() ?? 0}</strong><span>次</span></div>
          </div>
        </section>

        <nav className="range-tabs" aria-label="统计时间范围">
          {ranges.map((item) => <button key={item.value} className={range === item.value ? 'active' : ''} onClick={() => setRange(item.value)}>{item.label}</button>)}
        </nav>

        <section className="stats-grid">
          <StatCard label="全站累计起飞" value={dashboard?.summary.totalFlights ?? 0} detail="历史总次数" symbol="∑" />
          <StatCard label="当前范围起飞" value={dashboard?.summary.rangeFlights ?? 0} detail={ranges.find((item) => item.value === range)?.label ?? ''} symbol="↗" accent />
          <StatCard label="本站用户" value={dashboard?.summary.totalUsers ?? 0} detail="通过 CPOAuth 登录" symbol="人" />
          <StatCard label="活跃飞行员" value={dashboard?.summary.activeUsers ?? 0} detail="当前范围内起飞" symbol="◎" />
          <StatCard label="最近一次起飞" value={dashboard?.summary.lastFlightAt ? relativeShort(dashboard.summary.lastFlightAt) : '暂无'} detail={dashboard?.summary.lastFlightAt ? formatDate(dashboard.summary.lastFlightAt) : '等待首飞'} symbol="◷" compact />
        </section>

        <section className="dashboard-grid">
          <Card title="起飞趋势" subtitle="按当前时间范围聚合" className="card--wide">
            <TrendChart points={dashboard?.trend ?? []} />
          </Card>
          <Card title="实时动态" subtitle="所有在线页面同步更新" badge={<span className="live-badge"><i /> LIVE</span>}>
            <ActivityFeed flights={dashboard?.recentFlights ?? []} />
          </Card>
          <Card title="起飞排行榜" subtitle="前十名飞行员" className="card--wide">
            <Leaderboard entries={dashboard?.leaderboard ?? []} />
          </Card>
          <Card title="起飞时间热力" subtitle="最近 30 天 · 星期 × 小时">
            <Heatmap cells={dashboard?.heatmap ?? []} />
          </Card>
        </section>

        <section className="card users-card">
          <div className="card-header"><div><h2>所有飞行员</h2><p>本站登录用户的实时起飞状态</p></div><span className="section-index">ALL USERS</span></div>
          <UserTable users={users} sort={userSort} hasMore={Boolean(userCursor)} loadingMore={loadingUsers} onSort={setUserSort} onLoadMore={loadMoreUsers} />
        </section>
      </main>

      <footer>
        <span>中国人能飞 · 所有时间均按 {config?.timezone ?? 'Asia/Shanghai'} 展示</span>
        <span className="footer-links">
          <span>作者：FSY / LaplaceOrange</span>
          <a href="https://github.com/LaplaceOrange/fly" target="_blank" rel="noreferrer">GitHub 仓库</a>
          <a href="https://www.cpoauth.com/about" target="_blank" rel="noreferrer">身份认证由 CPOAuth 提供</a>
        </span>
      </footer>
      {turnstileOpen && config && <TurnstileModal siteKey={config.turnstileSiteKey} onClose={() => setTurnstileOpen(false)} onVerify={verifyTakeoff} />}
      {shareOpen && config && dashboard && me.authenticated && <ShareModal user={me.user} dashboard={dashboard} range={range} ttlHours={config.shareTTLHours} onClose={() => setShareOpen(false)} />}
      {takeoffSuccessOpen && <TakeoffSuccessModal onClose={() => setTakeoffSuccessOpen(false)} />}
    </div>
  )
}

function Card({ title, subtitle, badge, className = '', children }: { title: string; subtitle: string; badge?: React.ReactNode; className?: string; children: React.ReactNode }) {
  return <section className={`card ${className}`}><div className="card-header"><div><h2>{title}</h2><p>{subtitle}</p></div>{badge}</div>{children}</section>
}

function StatCard({ label, value, detail, symbol, accent, compact }: { label: string; value: number | string; detail: string; symbol: string; accent?: boolean; compact?: boolean }) {
  return <article className={`stat-card ${accent ? 'stat-card--accent' : ''}`}><div className="stat-label"><span>{label}</span><i>{symbol}</i></div><strong className={compact ? 'stat-value stat-value--compact' : 'stat-value'}>{typeof value === 'number' ? value.toLocaleString() : value}</strong><small>{detail}</small></article>
}

function LoadingScreen() {
  return <div className="loading-screen"><span className="brand-mark">飞</span><div className="loading-line"><i /></div><p>正在连接实时起飞网络…</p></div>
}

function errorMessage(caught: unknown) {
  if (caught instanceof APIError || caught instanceof Error) return caught.message
  return '请求失败，请稍后重试'
}

function formatDuration(seconds: number) {
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return minutes ? `${minutes}分${rest.toString().padStart(2, '0')}秒` : `${rest}秒`
}

function relativeShort(value: string) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 60) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时前`
  return `${Math.floor(seconds / 86400)}天前`
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}
