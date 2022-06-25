import crypto from 'crypto'
import type { Response } from 'node-fetch'

export const randStr = (length: number, randChar: () => string) => {
  let r = ''
  for (let i = 0; i < length; i += 1) r += randChar()
  return r
}

export const randDigit = (base = 10) =>
  ((Math.random() * base) << 0).toString(base)

export const randHex = (length: number) => randStr(length, () => randDigit(16))

export const rand = <T>(dict: ArrayLike<T>) =>
  dict[(dict.length * Math.random()) << 0]

const base62Dict =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

export const randBase62 = (length: number) =>
  randStr(length, () => rand(base62Dict))

export const createHash = (algorithm: string) => (data: crypto.BinaryLike) =>
  crypto.createHash(algorithm).update(data).digest()

export const md5 = createHash('md5')
export const sha1 = createHash('sha1')

export const parseResponseCookies = (res: Response) => {
  const cookie = {} as Record<string, string>
  const rawHeaders = res.headers.raw()
  for (const line of rawHeaders['set-cookie'] || []) {
    const parts = line.split(';').shift()?.split('=')
    if (!parts) continue
    cookie[parts[0]] = parts[1]
  }
  return cookie
}
