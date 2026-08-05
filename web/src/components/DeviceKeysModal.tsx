import { useEffect, useState } from 'react'
import { api } from '../api'
import { currentDeviceExchangeKeyID, forgetLocalDeviceKeys } from '../crypto'
import type { DeviceKeyInfo } from '../types'

export function DeviceKeysModal({ userId, onClose }: { userId: string; onClose: () => void }) {
  const [devices, setDevices] = useState<DeviceKeyInfo[]>([])
  const [currentKeyId, setCurrentKeyId] = useState('')
  const [confirming, setConfirming] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([api.devices(), currentDeviceExchangeKeyID(userId)])
      .then(([result, current]) => {
        if (!active) return
        setDevices(result.devices)
        setCurrentKeyId(current ?? '')
      })
      .catch((caught) => active && setError(caught instanceof Error ? caught.message : '无法读取设备密钥'))
    return () => { active = false }
  }, [userId])

  const revoke = async (device: DeviceKeyInfo) => {
    if (confirming !== device.exchangeKeyId) {
      setConfirming(device.exchangeKeyId)
      return
    }
    setBusy(device.exchangeKeyId)
    setError('')
    try {
      await api.revokeDevice(device.exchangeKeyId)
      if (device.exchangeKeyId === currentKeyId) {
        await forgetLocalDeviceKeys(userId)
        window.location.reload()
        return
      }
      const result = await api.devices()
      setDevices(result.devices)
      setConfirming('')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '撤销设备失败')
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !busy && onClose()}>
      <section className="modal device-modal" role="dialog" aria-modal="true" aria-labelledby="device-title">
        <button className="modal-close" aria-label="关闭" onClick={onClose} disabled={Boolean(busy)}>×</button>
        <span className="modal-icon">⌘</span>
        <h2 id="device-title">设备密钥</h2>
        <p>撤销丢失或不再使用的设备。撤销后该设备不能创建新分享，也不会再收到新的一次性预密钥信封。</p>
        <div className="device-list">
          {devices.map((device) => <article key={device.exchangeKeyId} className={device.revokedAt ? 'device-item device-item--revoked' : 'device-item'}>
            <div>
              <strong>{device.deviceLabel || '浏览器设备'} {device.exchangeKeyId === currentKeyId && <small>当前设备</small>}</strong>
              <span>Ed25519 {device.signingFingerprint.slice(0, 16)}…</span>
              <span>X25519 {device.exchangeFingerprint.slice(0, 16)}…</span>
              <time>最近使用：{formatDate(device.lastSeenAt)}</time>
            </div>
            {device.revokedAt
              ? <span className="revoked-pill">已撤销</span>
              : <button className={confirming === device.exchangeKeyId ? 'danger-button danger-button--confirm' : 'danger-button'} disabled={Boolean(busy)} onClick={() => revoke(device)}>
                  {busy === device.exchangeKeyId ? '正在撤销…' : confirming === device.exchangeKeyId ? '再次点击确认撤销' : '撤销'}
                </button>}
          </article>)}
          {!devices.length && !error && <p className="empty-state">暂无已注册设备</p>}
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
      </section>
    </div>
  )
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
