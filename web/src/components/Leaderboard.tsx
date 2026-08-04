import type { Dashboard } from '../types'
import { Avatar } from './Avatar'

export function Leaderboard({ entries }: { entries: Dashboard['leaderboard'] }) {
  const top = entries.slice(0, 10)
  const maximum = Math.max(1, ...top.map((entry) => entry.flightCount))
  if (!top.length) return <div className="empty-state">这个时间段还没有人起飞</div>
  return (
    <div className="leaderboard-bars">
      {top.map((entry) => (
        <div className="leaderboard-row" key={entry.user.id}>
          <span className={`rank rank--${entry.rank}`}>{entry.rank}</span>
          <Avatar user={entry.user} size={34} />
          <div className="leaderboard-person">
            <strong>{entry.user.displayName}</strong>
            <span>@{entry.user.username}</span>
          </div>
          <div className="bar-track" aria-label={`${entry.flightCount} 次`}>
            <span style={{ width: `${Math.max(5, (entry.flightCount / maximum) * 100)}%` }} />
          </div>
          <strong className="bar-value">{entry.flightCount}</strong>
        </div>
      ))}
    </div>
  )
}

