import { describe, expect, it } from 'vitest'
import { shareSigningInput } from './crypto'

describe('share signing input', () => {
  it('binds encryption mode, ciphertext and IV into the signature', () => {
    expect(shareSigningInput(true, 'ciphertext', 'iv')).toBe('share-sign-v1\n1\nciphertext\niv')
    expect(shareSigningInput(false, '{}', '')).toBe('share-sign-v1\n0\n{}\n')
  })
})
