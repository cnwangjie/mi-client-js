import fetch from 'node-fetch'
import qs from 'querystring'
import { defaultLogger, Logger } from './logger'
import { md5, parseResponseCookies, randBase62, randHex, sha1 } from './util'
import path from 'path'
import os from 'os'
import fs from 'fs/promises'
import assert from 'assert'
import crypto from 'crypto'
import { createArc4 } from './arc4'
import ProxyAgent from 'proxy-agent'
import pako from 'pako'

const MiLoginUrl = 'https://account.xiaomi.com/pass/serviceLoginAuth2'

interface MiClientOpt {
  username: string
  password: string
  logger?: Logger
  stateStorePath?: string
}

interface State {
  agentId: string
  deviceId: string

  location?: string
  userId?: string
  cUserId?: string
  ssecurity?: string
  passToken?: string

  serviceToken?: string
}

export const getNonce = () => {
  const part0 = crypto.randomBytes(8)
  const time = (Date.now() / 60000) << 0
  const byteLen = ((time.toString(2).length + 7) / 8) << 0
  const part1 = Buffer.alloc(8)
  part1.writeInt32BE(time)
  const buf = Buffer.concat([part0, part1.slice(0, byteLen)])
  return buf.toString('base64')
}

export const getSignedNonce = (ssecurity: string, nonce: string) => {
  const hash = crypto.createHash('sha256')
  hash.update(Buffer.from(ssecurity, 'base64'))
  hash.update(Buffer.from(nonce, 'base64'))
  return hash.digest().toString('base64')
}

export const getEncSignature = (
  url: string,
  method: string,
  signedNonce: string,
  data: Record<string, string>,
) => {
  const parts = [method.toString(), url.split('com')[1].replace('/app/', '/')]

  for (const [k, v] of Object.entries(data)) {
    parts.push(`${k}=${v}`)
  }

  parts.push(signedNonce)
  return sha1(parts.join('&')).toString('base64')
}

export const getEncParams = (
  url: string,
  method: string,
  signedNonce: string,
  nonce: string,
  data: Record<string, string>,
  ssecurity: string,
) => {
  const params: Record<string, string> = { data: JSON.stringify(data) }
  params.rc4_hash__ = getEncSignature(url, method, signedNonce, params)
  for (const [k, v] of Object.entries(params)) {
    params[k] = encryptRc4(signedNonce, v)
  }

  params.signature = getEncSignature(url, method, signedNonce, params)
  params.ssecurity = ssecurity
  params._nonce = nonce
  return params
}

export const parseEncParams = (
  params: Record<string, string>,
  signedNonce: string,
) => {
  return decryptRc4(signedNonce, params.data)
}

export const parseResponse = (
  rawText: string,
  signedNonce: string,
  gzip?: boolean,
) => {
  const result = decryptRc4(signedNonce, rawText)
  if (gzip) return Buffer.from(pako.inflate(result))
  return result
}

export const encryptRc4 = (key: string, str: string) => {
  const arc4 = createArc4(Buffer.from(key, 'base64'))
  arc4.encrypt(Buffer.alloc(1024))
  return arc4.encrypt(Buffer.from(str)).toString('base64')
}

export const decryptRc4 = (key: string, str: string) => {
  const arc4 = createArc4(Buffer.from(key, 'base64'))
  arc4.encrypt(Buffer.alloc(1024))
  return arc4.encrypt(Buffer.from(str, 'base64'))
}

export class MiClient {
  public state: State = {
    agentId: randHex(32).toUpperCase(),
    deviceId: randBase62(16),
  }

  get agentId() {
    return this.state.agentId
  }

  get deviceId() {
    return this.state.deviceId
  }

  constructor(public opt: MiClientOpt) {}

  async init() {
    await this.loadState()
    await this.saveState()
  }

  protected getStateStorePath() {
    const stateStoreDir = this.opt.stateStorePath
      ? path.resolve(process.cwd(), this.opt.stateStorePath)
      : os.tmpdir()

    return path.resolve(stateStoreDir, 'mi-client-state.json')
  }

  async loadState() {
    const exist = await fs
      .stat(this.getStateStorePath())
      .then(i => i.isFile())
      .catch(() => false)

    if (!exist) return
    const raw = await fs.readFile(this.getStateStorePath())
    const data = JSON.parse(raw.toString()) as State
    this.state = data
  }

  async saveState() {
    const data = JSON.stringify(this.state, null, 2)
    await fs.writeFile(this.getStateStorePath(), data)
  }

  get logger() {
    return this.opt.logger || defaultLogger
  }

  getUA() {
    return `Android-10-7.5.702-SMARTISAN-DT1901A-1-CN-${this.agentId} APP/xiaomi.smarthome`
  }

  stringifyCookie(data: Record<string, any>) {
    return qs.stringify({ ...data }, '; ', '=', {
      encodeURIComponent: i => i,
    })
  }

  getCookie(data?: Record<string, string>) {
    return qs.stringify(
      {
        sdkVersion: 'accountsdk-2020.01.09',
        deviceId: this.deviceId,
        ...data,
      },
      '; ',
      '=',
    )
  }

  async getSign() {
    const query = {
      sid: 'xiaomiio',
      _json: true,
    }

    const req = {
      method: 'GET',
      headers: {
        'User-Agent': this.getUA(),
        Cookie: this.getCookie({
          userId: this.opt.username,
        }),
      },
    }

    this.logger.debug(`get sign. req=${JSON.stringify(req, null, 2)}`)
    const res = await fetch(
      `https://account.xiaomi.com/pass/serviceLogin?${qs.stringify(query)}`,
      req,
    )

    const resBody = await res.text()
    this.logger.debug(`get sign res. res=${resBody}`)

    const data = JSON.parse(resBody.replace('&&&START&&&', ''))
    return data._sign
  }

  async getServiceToken() {
    const location = this.state.location
    assert(location, 'No service token location. Must be login firstly.')
    this.logger.debug(`get service token`)
    const res = await fetch(location, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': this.getUA(),
        Cookie: this.getCookie(),
      },
    })
    const cookie = parseResponseCookies(res)
    this.logger.debug(`get service token res. cookie=${JSON.stringify(cookie)}`)
    const serviceToken = cookie.serviceToken
    return serviceToken
  }

  async login() {
    const query = {
      sid: 'xiaomiio',
      _json: true,
    }

    const body = {
      ...query,
      user: this.opt.username,
      hash: md5(this.opt.password).toString('hex').toUpperCase(),
      callback: 'https://sts.api.io.mi.com/sts',
      qs: '?' + qs.stringify(query),
      _sign: await this.getSign(),
    }

    this.logger.debug(`start login. body=${JSON.stringify(body, null, 2)}`)
    const res = await fetch(MiLoginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': this.getUA(),
        Cookie: this.getCookie(),
      },
      body: qs.stringify(body),
    })

    const resBody = await res.text()
    this.logger.debug(`get sign res. res=${resBody}`)

    const data = JSON.parse(resBody.replace('&&&START&&&', ''))

    this.state.userId = data.userId
    this.state.cUserId = data.cUserId
    this.state.ssecurity = data.ssecurity
    this.state.passToken = data.passToken
    this.state.location = data.location

    const serviceToken = await this.getServiceToken()
    this.state.serviceToken = serviceToken

    await this.saveState()
  }

  getLocale() {
    return Intl.DateTimeFormat().resolvedOptions().locale
  }

  getTimezone() {
    const offset = new Date().getTimezoneOffset()
    const sign = offset < 0 ? '+' : '-'
    const value = Math.abs(offset)
    return (
      'GMT' +
      sign +
      ((value / 60) | 0).toString().padStart(2, '0') +
      ':' +
      (value % 60).toString().padStart(2, '0')
    )
  }

  getDaylight() {
    const jan = new Date(new Date().getFullYear(), 0, 1)
    const jul = new Date(new Date().getFullYear(), 6, 1)
    const stdTimezoneOffset = Math.max(
      jan.getTimezoneOffset(),
      jul.getTimezoneOffset(),
    )

    const isDstObserved = new Date().getTimezoneOffset() < stdTimezoneOffset

    return isDstObserved ? 1 : 0
  }

  async request(url: string, data: any) {
    const cookies = {
      userId: this.state.userId,
      yetAnotherServiceToken: this.state.serviceToken,
      serviceToken: this.state.serviceToken,
      locale: this.getLocale(),
      timezone: this.getTimezone(),
      is_daylight: this.getDaylight(),
      dst_offset: this.getDaylight() * 60 * 60 * 1000,
      channel: 'GooglePlay',
    }

    const headers = {
      'User-Agent': this.getUA(),
      'Accept-Encoding': 'identity',
      'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
      'content-type': 'application/x-www-form-urlencoded',
      'miot-encrypt-algorithm': 'ENCRYPT-RC4',
      'miot-accept-encoding': 'GZIP',
      Cookie: this.stringifyCookie(cookies),
    }

    const { ssecurity } = this.state
    assert(ssecurity, 'No ssecurity. Must login first.')

    const nonce = getNonce()
    const signedNonce = getSignedNonce(ssecurity, nonce)
    const params = getEncParams(
      url,
      'POST',
      signedNonce,
      nonce,
      data,
      ssecurity,
    )

    const req = {
      method: 'POST',
      headers,
      body: qs.stringify(params),
      agent: new ProxyAgent(),
    }
    this.logger.debug(`req ${url}. req=${JSON.stringify(req, null, 2)}`)
    const res = await fetch(url, {
      ...req,
    })

    const rawData = await res.text()
    const gzip = res.headers.get('miot-content-encoding') === 'GZIP'
    this.logger.debug(`req ${url}. status=${res.status} resBody=${rawData}`)
    const resData = parseResponse(rawData, signedNonce, gzip)
    return JSON.parse(resData.toString())
  }
}
