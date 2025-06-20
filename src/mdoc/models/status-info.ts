import { cborDecode, cborEncode } from '../../cbor'
import { Tag } from '../../cbor/cbor-x'
import type { MdocContext } from '../../context'
import { type CoseKey, CoseStructureType, CoseTypeToTag, Mac0, Sign1 } from '../../cose'
import { CWT } from '../../cwt'

export type StatusInfoStructure = {
  idx: number
  uri: string
}
export type StatusInfoOptions = {
  statusList: StatusInfoStructure
  key?: CoseKey
  mdocContext?: Pick<MdocContext, 'cose' | 'x509'>
}

export enum StatusInfoClaim {
  StatusList = 65535,
}

export class StatusInfo {
  public statusList: StatusInfoStructure
  public mdocContext?: Pick<MdocContext, 'cose' | 'x509'>
  public key?: CoseKey

  public constructor(statusInfo: StatusInfoOptions) {
    this.statusList = {
      idx: statusInfo.statusList.idx,
      uri: statusInfo.statusList.uri,
    }
    this.mdocContext = statusInfo.mdocContext
    this.key = statusInfo.key
  }

  public setKey(key: CoseKey): void {
    this.key = key
  }
  public setMdocContext(mdocContext: Pick<MdocContext, 'cose' | 'x509'>): void {
    this.mdocContext = mdocContext
  }

  public async encodedStructure(): Promise<Uint8Array> {
    const cwt = new CWT()
    cwt.setClaims({
      [StatusInfoClaim.StatusList]: {
        status_list: cborEncode(this.statusList),
      },
    })
    if (!this.key) {
      throw new Error('Signing key is required to encode StatusInfo')
    }
    if (!this.mdocContext) {
      throw new Error('MdocContext is required to encode StatusInfo')
    }
    // Todo: Add support for Mac0?
    const type = CoseStructureType.Sign1
    return cborEncode(
      new Tag(await cwt.create({ type, key: this.key, mdocContext: this.mdocContext }), CoseTypeToTag[type])
    )
  }

  public static fromEncodedStructure(encodedStructure: Uint8Array): StatusInfo {
    const decoded = cborDecode(encodedStructure) as Sign1 | Mac0
    if (!(decoded instanceof Sign1 || decoded instanceof Mac0)) {
      throw new Error('Unsupported CWT type')
    }
    if (!decoded.payload) {
      throw new Error('CWT payload is missing')
    }
    const payload = cborDecode(decoded.payload) as {
      [StatusInfoClaim.StatusList]: { status_list: StatusInfoStructure }
    }
    if (!payload || typeof payload !== 'object' || !(StatusInfoClaim.StatusList in payload)) {
      throw new Error('Invalid status list structure')
    }
    const statusList = payload[StatusInfoClaim.StatusList].status_list
    if (!statusList || typeof statusList !== 'object' || !('idx' in statusList) || !('uri' in statusList)) {
      throw new Error('Invalid status list structure')
    }
    return new StatusInfo({
      statusList: {
        idx: statusList.idx,
        uri: statusList.uri,
      },
    })
  }
}
