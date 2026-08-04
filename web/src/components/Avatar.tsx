import type { User } from '../types'

export function Avatar({ user, size = 40 }: { user: Pick<User, 'avatarUrl' | 'displayName' | 'username'>; size?: number }) {
  const label = user.displayName || user.username
  if (user.avatarUrl) {
    return <img className="avatar" src={user.avatarUrl} alt="" loading="lazy" width={size} height={size} />
  }
  return (
    <span className="avatar avatar--fallback" style={{ width: size, height: size }} aria-hidden="true">
      {label.slice(0, 1).toUpperCase()}
    </span>
  )
}

