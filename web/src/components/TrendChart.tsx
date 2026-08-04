import { useId } from 'react'
import type { Dashboard } from '../types'

export function TrendChart({ points }: { points: Dashboard['trend'] }) {
  const gradientId = useId().replaceAll(':', '')
  const width = 760
  const height = 250
  const padding = { top: 20, right: 18, bottom: 38, left: 42 }
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom
  const maximum = Math.max(1, ...points.map((point) => point.count))
  const coordinates = points.map((point, index) => ({
    x: padding.left + (index / Math.max(1, points.length - 1)) * chartWidth,
    y: padding.top + chartHeight - (point.count / maximum) * chartHeight,
    point,
  }))
  const linePath = coordinates.map(({ x, y }, index) => `${index ? 'L' : 'M'} ${x.toFixed(2)} ${y.toFixed(2)}`).join(' ')
  const areaPath = coordinates.length
    ? `${linePath} L ${coordinates.at(-1)?.x} ${padding.top + chartHeight} L ${coordinates[0].x} ${padding.top + chartHeight} Z`
    : ''
  const ticks = Array.from({ length: 4 }, (_, index) => Math.round((maximum / 3) * index)).reverse()
  const labelIndexes = [...new Set([0, Math.floor((points.length - 1) / 3), Math.floor(((points.length - 1) * 2) / 3), points.length - 1])]

  if (!points.length) return <div className="empty-chart">还没有起飞数据</div>

  return (
    <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="起飞趋势图">
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.34" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {ticks.map((tick, index) => {
        const y = padding.top + (index / 3) * chartHeight
        return (
          <g key={`${tick}-${index}`}>
            <line x1={padding.left} x2={width - padding.right} y1={y} y2={y} className="chart-grid" />
            <text x={padding.left - 10} y={y + 4} textAnchor="end" className="chart-axis-label">{tick}</text>
          </g>
        )
      })}
      <path d={areaPath} fill={`url(#${gradientId})`} />
      <path d={linePath} className="chart-line" />
      {coordinates.map(({ x, y, point }) => (
        <circle key={point.bucketStart} cx={x} cy={y} r="7" className="chart-hit">
          <title>{`${formatBucket(point.bucketStart)}：${point.count} 次`}</title>
        </circle>
      ))}
      {labelIndexes.filter((index) => index >= 0).map((index) => (
        <text key={index} x={coordinates[index]?.x} y={height - 10} textAnchor={index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle'} className="chart-axis-label">
          {formatBucket(points[index].bucketStart)}
        </text>
      ))}
    </svg>
  )
}

function formatBucket(value: string) {
  return new Intl.DateTimeFormat('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value))
}

