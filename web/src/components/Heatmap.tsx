import type { Dashboard } from '../types'

const weekdays = [
  { value: 1, label: '一' }, { value: 2, label: '二' }, { value: 3, label: '三' },
  { value: 4, label: '四' }, { value: 5, label: '五' }, { value: 6, label: '六' }, { value: 0, label: '日' },
]

export function Heatmap({ cells }: { cells: Dashboard['heatmap'] }) {
  const values = new Map(cells.map((cell) => [`${cell.weekday}:${cell.hour}`, cell.count]))
  const maximum = Math.max(1, ...cells.map((cell) => cell.count))
  return (
    <div className="heatmap-wrap">
      <div className="heatmap-hours" aria-hidden="true">
        <span />
        {Array.from({ length: 24 }, (_, hour) => <span key={hour}>{hour % 3 === 0 ? hour : ''}</span>)}
      </div>
      <div className="heatmap" role="img" aria-label="最近三十天按星期和小时统计的起飞热力图">
        {weekdays.flatMap(({ value, label }) => [
          <span className="heatmap-day" key={`label-${value}`}>{label}</span>,
          ...Array.from({ length: 24 }, (_, hour) => {
            const count = values.get(`${value}:${hour}`) ?? 0
            const intensity = count ? 0.16 + (count / maximum) * 0.84 : 0.06
            return (
              <span key={`${value}-${hour}`} className="heatmap-cell" style={{ '--intensity': intensity } as React.CSSProperties}>
                <span className="sr-only">星期{label} {hour}:00，共 {count} 次</span>
                <span className="tooltip">星期{label} {hour}:00 · {count} 次</span>
              </span>
            )
          }),
        ])}
      </div>
      <div className="heatmap-legend"><span>少</span><i /><i /><i /><i /><span>多</span></div>
    </div>
  )
}

