export type StatusInfoStructure = {
  status_list: StatusInfoOptions
}

export type StatusInfoOptions = {
  idx: number
  uri: string
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
      status_list: this.statusList,
    }
  }

  public static fromEncodedStructure(encodedStructure: StatusInfoStructure): StatusInfo {
    let structure = encodedStructure as StatusInfoStructure
    if (structure instanceof Map) {
      structure = Object.fromEntries(structure.entries()) as StatusInfoStructure
    }

    let statusList = structure.status_list as StatusInfoOptions
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
