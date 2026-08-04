import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Heatmap } from './Heatmap'
import { Leaderboard } from './Leaderboard'
import { TrendChart } from './TrendChart'

describe('dashboard visualizations', () => {
  it('renders a zero-filled trend without crashing', () => {
    render(<TrendChart points={[
      { bucketStart: '2026-08-04T00:00:00Z', count: 0 },
      { bucketStart: '2026-08-04T01:00:00Z', count: 3 },
    ]} />)
    expect(screen.getByRole('img', { name: '起飞趋势图' })).toBeInTheDocument()
  })

  it('renders all heatmap hours with accessible labels', () => {
    render(<Heatmap cells={[{ weekday: 1, hour: 8, count: 5 }]} />)
    expect(screen.getByText('星期一 8:00，共 5 次')).toBeInTheDocument()
  })

  it('renders ranking identities and counts', () => {
    render(<Leaderboard entries={[{
      rank: 1,
      user: { id: 'u1', username: 'pilot', displayName: '飞行员', avatarUrl: '', totalFlights: 8, lastFlightAt: null },
      flightCount: 8,
      lastFlightAt: null,
    }]} />)
    expect(screen.getByText('飞行员')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })
})

