import type { UserStatus } from '../types'
import { Avatar } from './Avatar'

interface Props {
  users: UserStatus[]
  sort: string
  hasMore: boolean
  loadingMore: boolean
  onSort: (sort: string) => void
  onLoadMore: () => void
}

export function UserTable({ users, sort, hasMore, loadingMore, onSort, onLoadMore }: Props) {
  return (
    <div>
      <div className="table-toolbar">
        <p>共展示 {users.length} 位用户</p>
        <label>
          排序
          <select value={sort} onChange={(event) => onSort(event.target.value)}>
            <option value="last_flight">最近起飞</option>
            <option value="total">累计次数</option>
          </select>
        </label>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>用户</th><th>累计起飞</th><th>最近起飞</th><th>状态</th></tr></thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td><div className="user-cell"><Avatar user={user} size={36} /><span><strong>{user.displayName}</strong><small>@{user.username}</small></span></div></td>
                <td><strong className="number-cell">{user.totalFlights}</strong></td>
                <td>{user.lastFlightAt ? formatDate(user.lastFlightAt) : '还未起飞'}</td>
                <td><span className={`status-pill ${user.canTakeoff ? 'status-pill--ready' : ''}`}>{user.canTakeoff ? '可以起飞' : '冷却中'}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!users.length && <div className="empty-state">还没有用户登录本站</div>}
      {hasMore && <button className="load-more" onClick={onLoadMore} disabled={loadingMore}>{loadingMore ? '加载中…' : '加载更多用户'}</button>}
    </div>
  )
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

