import { cborDecode, cborEncode } from '../cbor'
import { Tag } from '../cbor/cbor-x'
import type { CoseKey } from '../cose'
import { CoseType, CoseTypeToTag, Mac0, Sign1 } from '../cose'
import { CWT } from '../cwt'
import type { StatusArray } from './status-array'
import { StatusList } from './status-list'

interface CWTStatusTokenOptions {
  claimsSet: {
    statusArray: StatusArray
    aggregationUri?: string
    expirationTime?: number
    timeToLive?: number
  }
  type: CoseType
  key: CoseKey
}

interface CWTStatusTokenVerifyOptions {
  token: Uint8Array
  key?: CoseKey
}

interface CWTStatusVerifyOptions extends CWTStatusTokenVerifyOptions {
  index: number
  expectedStatus: number
}

enum CwtProtectedHeaders {
  TYPE = 16,
}

enum CwtStatusListClaims {
  StatusListUri = 2,
  ExpirationTime = 4,
  IssuedAt = 6,
  StatusList = 65533,
  TimeToLive = 65534,
}

export class CWTStatusToken {
  static async build(options: CWTStatusTokenOptions): Promise<Uint8Array> {
    const cwt = new CWT()
    cwt.setHeaders({
      protected: {
        [CwtProtectedHeaders.TYPE]: 'application/statuslist+cwt',
      },
    })

    const claims: { [key: number]: string | number | Uint8Array } = {
      [CwtStatusListClaims.StatusListUri]: 'https://example.com/statuslist', // Where the status list is going to be hosted
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

  static async verifyStatusToken(options: CWTStatusTokenVerifyOptions): Promise<boolean> {
    const cwt = cborDecode(options.token) as Sign1 | Mac0

    const type = cwt.protectedHeaders.headers?.get(String(CwtProtectedHeaders.TYPE))
    if (!type || type !== 'application/statuslist+cwt') {
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

    let coseType: CoseType
    if (cwt instanceof Sign1) {
      coseType = CoseType.Sign1
    } else if (cwt instanceof Mac0) {
      coseType = CoseType.Mac0
    } else {
      throw new Error(`Unimplemented/Unsupported CWT type`)
    }
    const validSignature = await CWT.verify({ type: coseType, token: options.token, key: options.key })
    if (!validSignature) {
      throw new Error('Invalid signature for CWT status token')
    }

    return true
  }

  static async verifyStatus(options: CWTStatusVerifyOptions): Promise<boolean> {
    const validStatusToken = await CWTStatusToken.verifyStatusToken(options)
    if (validStatusToken) {
      const cwt = cborDecode(options.token) as Sign1 | Mac0
      if (!cwt.payload) {
        throw new Error('CWT status token does not contain claims')
      }

      const claims = cborDecode(cwt.payload) as Map<string, string | number | Uint8Array>
      const statusList = claims.get(String(CwtStatusListClaims.StatusList))
      return StatusList.verifyStatus(statusList as Uint8Array, options.index, options.expectedStatus)
    }

    return false
  }
}
