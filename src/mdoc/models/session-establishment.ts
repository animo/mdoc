import { type CborDecodeOptions, CborStructure, DataItem, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import type { CoseKey } from '../../cose'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import type { SessionTranscript } from './session-transcript'

export type SessionEstablishmentStructure = {
  eReaderKey: DataItem<EReaderKeyStructure>
  data: Uint8Array
}

export type SessionEstablishmentOptions = {
  eReaderKey: EReaderKey
  data: Uint8Array
}

export class SessionEstablishment extends CborStructure {
  public eReaderKey: EReaderKey
  public data: Uint8Array

  public constructor(options: SessionEstablishmentOptions) {
    super()
    this.eReaderKey = options.eReaderKey
    this.data = options.data
  }

  public async decryptedData(
    options: {
      eDeviceKeyPrivate: CoseKey
      eReaderKeyPublic: CoseKey
      sessionTranscript: SessionTranscript
    },
    ctx: { crypto: MdocContext['crypto'] }
  ) {
    const key = await ctx.crypto.calculateEphemeralMacKeyJwk({
      privateKey: options.eDeviceKeyPrivate.privateKey,
      publicKey: options.eReaderKeyPublic.publicKey,
      sessionTranscriptBytes: options.sessionTranscript.encode({ asDataItem: true }),
      info: 'SKReader',
    })

    // TODO: we need to add a ctx.crypto.decrypt method
    throw new Error('unimplemented: ctx.crypto.decrypt must be added')
  }

  public encodedStructure(): SessionEstablishmentStructure {
    return {
      eReaderKey: DataItem.fromData(this.eReaderKey.encodedStructure()),
      data: this.data,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: SessionEstablishmentStructure | Map<unknown, unknown>
  ): SessionEstablishment {
    let structure = encodedStructure as SessionEstablishmentStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as SessionEstablishmentStructure
    }

    return new SessionEstablishment({
      eReaderKey: EReaderKey.fromEncodedStructure(structure.eReaderKey.data),
      data: structure.data,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): SessionEstablishment {
    const structure = cborDecode<SessionEstablishmentStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return SessionEstablishment.fromEncodedStructure(structure)
  }
}
