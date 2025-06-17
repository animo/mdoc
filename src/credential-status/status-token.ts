import { cborDecode, cborEncode } from '../cbor'
import { Tag } from '../cbor/cbor-x'
import type { MdocContext } from '../context'
import type { CoseKey } from '../cose'
import { CoseStructureType, CoseTypeToTag, Mac0, Sign1 } from '../cose'
import { CWT, CwtProtectedHeaders } from '../cwt'
import { dateToSeconds } from '../utils'
import type { StatusArray } from './status-array'
import { StatusList } from './status-list'

export interface CwtStatusTokenOptions {
  mdocContext: Pick<MdocContext, 'cose' | 'x509'>
  statusListUri: string
  claimsSet: {
    statusArray: StatusArray
    aggregationUri?: string
    expirationTime?: number
    timeToLive?: number
  }
  type: CoseStructureType.Sign1 | CoseStructureType.Mac0
  key: CoseKey
}

export interface CwtStatusTokenVerifyOptions {
  mdocContext: Pick<MdocContext, 'cose' | 'x509'>
  token: Uint8Array
  key?: CoseKey
}

export interface CwtStatusVerifyOptions extends CwtStatusTokenVerifyOptions {
  index: number
  expectedStatus: number
}

enum CwtStatusListClaims {
  Sub = 2,
  Exp = 4,
  Iat = 6,
  Sli = 65533, // Status List
  Ttl = 65534,
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
      [CwtStatusListClaims.Sub]: options.statusListUri,
      [CwtStatusListClaims.Iat]: dateToSeconds(),
      [CwtStatusListClaims.Sli]: StatusList.buildCborStatusList({
        statusArray: options.claimsSet.statusArray,
        aggregationUri: options.claimsSet.aggregationUri,
      }),
    }
    if (options.claimsSet.expirationTime) {
      claims[CwtStatusListClaims.Exp] = options.claimsSet.expirationTime
    }
    if (options.claimsSet.timeToLive) {
      claims[CwtStatusListClaims.Ttl] = options.claimsSet.timeToLive
    }

    cwt.setClaims(claims)
    return cborEncode(
      new Tag(
        await cwt.create({ type: options.type, key: options.key, mdocContext: options.mdocContext }),
        CoseTypeToTag[options.type]
      )
    )
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
    // Todo: Check if is the same as the one used to fetch the token
    if (!claims.has(String(CwtStatusListClaims.Sub))) {
      throw new Error('CWT status token does not contain status list URI')
    }
    if (!claims.has(String(CwtStatusListClaims.Iat))) {
      throw new Error('CWT status token does not contain issued at claim')
    }
    if (!claims.has(String(CwtStatusListClaims.Sli))) {
      throw new Error('CWT status token does not contain status list')
    }

    const expirationTime = claims.get(String(CwtStatusListClaims.Exp))
    if (expirationTime && typeof expirationTime === 'number' && expirationTime < dateToSeconds()) {
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
    const validSignature = await CWT.verify({
      type: coseType,
      token: options.token,
      key: options.key,
      mdocContext: options.mdocContext,
    })
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
    const statusList = claims.get(String(CwtStatusListClaims.Sli))
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
