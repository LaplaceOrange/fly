import { useEffect, useRef, useState } from 'react'

export function TakeoffSuccessModal({ onClose }: { onClose: () => void }) {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const closeRef = useRef(onClose)
  const [audioState, setAudioState] = useState<'loading' | 'playing' | 'unavailable'>('loading')
  closeRef.current = onClose

  const stopAudio = () => {
    const audio = audioRef.current
    if (!audio) return
    audio.pause()
    audio.currentTime = 0
  }

  const close = () => {
    stopAudio()
    onClose()
  }

  useEffect(() => {
    let active = true
    const audio = new Audio('./ChineseCanFly.mp3')
    audio.preload = 'auto'
    audioRef.current = audio

    const handleEnded = () => closeRef.current()
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        stopAudio()
        closeRef.current()
      }
    }
    audio.addEventListener('ended', handleEnded)
    document.addEventListener('keydown', handleEscape)
    void audio.play().then(() => {
      if (active) setAudioState('playing')
    }).catch(() => {
      if (active) setAudioState('unavailable')
    })

    return () => {
      active = false
      audio.removeEventListener('ended', handleEnded)
      document.removeEventListener('keydown', handleEscape)
      audio.pause()
      audio.currentTime = 0
      audioRef.current = null
    }
  }, [])

  return (
    <div className="modal-backdrop takeoff-success-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
      <section className="modal takeoff-success-modal" role="dialog" aria-modal="true" aria-labelledby="takeoff-success-title">
        <button className="modal-close" aria-label="关闭弹窗并停止音频" onClick={close}>×</button>
        <div className="takeoff-success-orbit" aria-hidden="true"><span>✈</span></div>
        <span className="eyebrow">FLIGHT CONFIRMED</span>
        <h2 id="takeoff-success-title">起飞成功！</h2>
        <p>这次起飞已经记录，并实时同步给所有在线用户。</p>
        <div className={`takeoff-audio-state takeoff-audio-state--${audioState}`}>
          <i />
          {audioState === 'playing' && '正在播放 ChineseCanFly.mp3'}
          {audioState === 'loading' && '正在尝试播放 ChineseCanFly.mp3'}
          {audioState === 'unavailable' && '音频未能自动播放，你仍可手动关闭弹窗'}
        </div>
        <button className="primary-modal-button" onClick={close}>关闭并停止音频</button>
      </section>
    </div>
  )
}
