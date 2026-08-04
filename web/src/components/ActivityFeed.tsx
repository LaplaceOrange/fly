import type { Flight } from '../types'
import { Avatar } from './Avatar'

export function ActivityFeed({ flights }: { flights: Flight[] }) {
  if (!flights.length) return <div className="empty-state">等待第一位用户起飞</div>
  return (
    <div className="activity-list">
      {flights.map((flight, index) => (
        <article className={`activity-item ${index === 0 ? 'activity-item--latest' : ''}`} key={flight.id}>
          <Avatar user={flight.user} size={38} />
          <div>
            <strong>{flight.user.displayName}</strong>
            <p>刚刚完成了一次起飞</p>
          </div>
          <time dateTime={flight.createdAt}>{formatRelative(flight.createdAt)}</time>
        </article>
      ))}
    </div>
  )
}

function formatRelative(value: string) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000))
  if (seconds < 10) return '刚刚'
  if (seconds < 60) return `${seconds} 秒前`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  return new Intl.DateTimeFormat('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

