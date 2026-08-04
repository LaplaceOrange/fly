import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TakeoffSuccessModal } from './TakeoffSuccessModal'

class AudioMock {
  static latest: AudioMock
  src: string
  preload = ''
  currentTime = 0
  play = vi.fn(() => Promise.resolve())
  pause = vi.fn()
  private listeners = new Map<string, Set<() => void>>()

  constructor(src: string) {
    this.src = src
    AudioMock.latest = this
  }

  addEventListener(type: string, listener: () => void) {
    const listeners = this.listeners.get(type) ?? new Set()
    listeners.add(listener)
    this.listeners.set(type, listeners)
  }

  removeEventListener(type: string, listener: () => void) {
    this.listeners.get(type)?.delete(listener)
  }

  emit(type: string) {
    this.listeners.get(type)?.forEach((listener) => listener())
  }
}

describe('takeoff success modal', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('tries the configured audio and stops it when manually closed', async () => {
    vi.stubGlobal('Audio', AudioMock as unknown as typeof Audio)
    const onClose = vi.fn()
    render(<TakeoffSuccessModal onClose={onClose} />)

    await waitFor(() => expect(AudioMock.latest.play).toHaveBeenCalled())
    expect(AudioMock.latest.src).toBe('./ChineseCanFly.mp3')
    fireEvent.click(screen.getByRole('button', { name: '关闭并停止音频' }))

    expect(AudioMock.latest.pause).toHaveBeenCalled()
    expect(AudioMock.latest.currentTime).toBe(0)
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('closes automatically when playback ends', async () => {
    vi.stubGlobal('Audio', AudioMock as unknown as typeof Audio)
    const onClose = vi.fn()
    render(<TakeoffSuccessModal onClose={onClose} />)

    await waitFor(() => expect(AudioMock.latest.play).toHaveBeenCalled())
    act(() => AudioMock.latest.emit('ended'))
    expect(onClose).toHaveBeenCalledOnce()
  })
})
