import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const webDirectory = resolve(scriptDirectory, '..')
const source = resolve(webDirectory, '..', 'ChineseCanFly.mp3')
const destination = resolve(webDirectory, 'public', 'ChineseCanFly.mp3')

if (existsSync(source)) {
  mkdirSync(dirname(destination), { recursive: true })
  copyFileSync(source, destination)
  console.log('Copied ChineseCanFly.mp3 into the frontend build.')
} else {
  console.log('ChineseCanFly.mp3 was not found at the repository root; the site will still attempt playback.')
}
