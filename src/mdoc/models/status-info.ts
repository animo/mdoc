import { cborDecode, cborEncode } from '../../cbor'

export type StatusInfoStructure = {
  [StatusInfoClaim.StatusList]: {
    status_list: Uint8Array
  }
}

export type StatusInfoOptions = {
  idx: number
  uri: string
}

export enum StatusInfoClaim {
  StatusList = 65535,
}

export class StatusInfo {
  public statusList: StatusInfoOptions

  public constructor(statusInfo: StatusInfoOptions) {
    this.statusList = {
      idx: statusInfo.idx,
      uri: statusInfo.uri,
    }
  }

  public encodedStructure(): StatusInfoStructure {
    return {
      [StatusInfoClaim.StatusList]: {
        status_list: cborEncode(this.statusList),
      },
    }
  }

  public static fromEncodedStructure(encodedStructure: StatusInfoStructure): StatusInfo {
    let structure = encodedStructure as StatusInfoStructure
    if (structure instanceof Map) {
      structure = Object.fromEntries(structure.entries()) as StatusInfoStructure
    }
    if (!(StatusInfoClaim.StatusList in structure)) {
      throw new Error('Invalid status list structure')
    }
    if (structure[StatusInfoClaim.StatusList] instanceof Map) {
      structure[StatusInfoClaim.StatusList] = Object.fromEntries(structure[StatusInfoClaim.StatusList].entries())
    }

    let statusList = cborDecode(structure[StatusInfoClaim.StatusList].status_list) as StatusInfoOptions
    if (statusList instanceof Map) {
      statusList = Object.fromEntries(statusList.entries()) as StatusInfoOptions
    }
    if (!('idx' in statusList) || !('uri' in statusList)) {
      throw new Error('Invalid status list structure')
    }

    return new StatusInfo({
      idx: statusList.idx,
      uri: statusList.uri,
    })
  }
}
