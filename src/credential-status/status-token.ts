import { cborDecode, cborEncode } from '../cbor'
import { Tag } from '../cbor/cbor-x'
import type { CoseKey } from '../cose'
import { CoseStructureType, CoseTypeToTag, Mac0, Sign1 } from '../cose'
import { CWT, CwtProtectedHeaders } from '../cwt'
import type { StatusArray } from './status-array'
import { StatusList } from './status-list'

export interface CwtStatusTokenOptions {
  statusListUri: string
  claimsSet: {
    statusArray: StatusArray
    aggregationUri?: string
    expirationTime?: number
    timeToLive?: number
  }
  type: CoseStructureType
  key: CoseKey
}

export interface CwtStatusTokenVerifyOptions {
  token: Uint8Array
  key?: CoseKey
}

export interface CwtStatusVerifyOptions extends CwtStatusTokenVerifyOptions {
  index: number
  expectedStatus: number
}

enum CwtStatusListClaims {
  StatusListUri = 2,
  ExpirationTime = 4,
  IssuedAt = 6,
  StatusList = 65533,
  TimeToLive = 65534,
}

const CWT_STATUS_LIST_HEADER_TYPE = 'application/statuslist+cwt'

export class CwtStatusToken {
  static async sign(options: CwtStatusTokenOptions): Promise<Uint8Array> {
    const cwt = new CWT()
    cwt.setHeaders({
      protected: {
        [CwtProtectedHeaders.Typ]: CWT_STATUS_LIST_HEADER_TYPE,
      },
    })

    const claims: { [key: number]: string | number | Uint8Array } = {
      [CwtStatusListClaims.StatusListUri]: options.statusListUri,
      [CwtStatusListClaims.IssuedAt]: Math.floor(Date.now() / 1000),
      [CwtStatusListClaims.StatusList]: StatusList.buildCborStatusList({
        statusArray: options.claimsSet.statusArray,
        aggregationUri: options.claimsSet.aggregationUri,
      }),
    }
    if (options.claimsSet.expirationTime) {
      claims[CwtStatusListClaims.ExpirationTime] = options.claimsSet.expirationTime
    }
    if (options.claimsSet.timeToLive) {
      claims[CwtStatusListClaims.TimeToLive] = options.claimsSet.timeToLive
    }

    cwt.setClaims(claims)
    return cborEncode(new Tag(await cwt.create({ type: options.type, key: options.key }), CoseTypeToTag[options.type]))
  }

  static async verifyStatusToken(options: CwtStatusTokenVerifyOptions): Promise<Sign1 | Mac0> {
    const cwt = cborDecode(options.token) as Sign1 | Mac0

    const type = cwt.protectedHeaders.headers?.get(String(CwtProtectedHeaders.Typ))
    if (!type || type !== CWT_STATUS_LIST_HEADER_TYPE) {
      throw new Error('CWT status token does not have the correct type in protected headers')
    }

    if (!cwt.payload) {
      throw new Error('CWT status token does not contain claims')
    }
    const claims = cborDecode(cwt.payload) as Map<string, string | number | Uint8Array>
    // Check if is the same as the one used to fetch the token
    if (!claims.has(String(CwtStatusListClaims.StatusListUri))) {
      throw new Error('CWT status token does not contain status list URI')
    }
    if (!claims.has(String(CwtStatusListClaims.IssuedAt))) {
      throw new Error('CWT status token does not contain issued at claim')
    }
    if (!claims.has(String(CwtStatusListClaims.StatusList))) {
      throw new Error('CWT status token does not contain status list')
    }

    const expirationTime = claims.get(String(CwtStatusListClaims.ExpirationTime))
    if (expirationTime && typeof expirationTime === 'number' && expirationTime < Math.floor(Date.now() / 1000)) {
      throw new Error('CWT status token has expired')
    }

    let coseType: CoseStructureType
    if (cwt instanceof Sign1) {
      coseType = CoseStructureType.Sign1
    } else if (cwt instanceof Mac0) {
      coseType = CoseStructureType.Mac0
    } else {
      throw new Error('Unsupported CWT structure type. Supported values are sign1 and mac0')
    }
    const validSignature = await CWT.verify({ type: coseType, token: options.token, key: options.key })
    if (!validSignature) {
      throw new Error('Invalid signature for CWT status token')
    }

    return cwt
  }

  static async verifyStatus(options: CwtStatusVerifyOptions): Promise<boolean> {
    const cwt = await CwtStatusToken.verifyStatusToken(options)
    if (!cwt.payload) {
      throw new Error('CWT status token does not contain claims')
    }

    const claims = cborDecode(cwt.payload) as Map<string, string | number | Uint8Array>
    const statusList = claims.get(String(CwtStatusListClaims.StatusList))
    return StatusList.verifyStatus(statusList as Uint8Array, options.index, options.expectedStatus)
  }

  static async fetchStatusListUri(statusListUri: string, timeoutMs = 5000): Promise<Uint8Array> {
    if (!statusListUri.startsWith('https://')) {
      throw new Error(`Status list URI must be HTTPS: ${statusListUri}`)
    }

    const abortController = new AbortController()
    const timeout = setTimeout(() => {
      abortController.abort()
    }, timeoutMs)
    try {
      const response = await fetch(statusListUri, {
        signal: abortController.signal as NonNullable<RequestInit['signal']>,
        headers: {
          Accept: CWT_STATUS_LIST_HEADER_TYPE,
        },
      })
      const buffer = await response.arrayBuffer()
      clearTimeout(timeout)
      return new Uint8Array(buffer)
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Fetch operation timed out for status list URI: ${statusListUri}`)
      }
      throw new Error(
        `Error fetching status list from ${statusListUri}: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
}
