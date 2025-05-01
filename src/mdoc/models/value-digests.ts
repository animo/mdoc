import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'
import type { Digest } from './digest'
import type { DigestId } from './digest-id'
import type { Namespace } from './namespace'

export type ValueDigestsStructure = Map<Namespace, Map<DigestId, Digest>>

export type ValueDigestOptions = {
  valueDigests: Map<Namespace, Map<DigestId, Digest>>
}

export class ValueDigests extends CborStructure {
  public valueDigests: Map<Namespace, Map<DigestId, Digest>>

  public constructor(options: ValueDigestOptions) {
    super()
    this.valueDigests = options.valueDigests
  }

  public encodedStructure(): ValueDigestsStructure {
    return this.valueDigests
  }

  public static override fromEncodedStructure(encodedStructure: ValueDigestsStructure): ValueDigests {
    return new ValueDigests({ valueDigests: encodedStructure })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ValueDigests {
    const structure = cborDecode<ValueDigestsStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })
    return new ValueDigests({ valueDigests: structure })
  }
}
