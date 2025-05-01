import { CborStructure } from '../../cbor'
import { CborEncodeError } from '../../cbor/error'

export type ProtocolInfoStructure = never

export class ProtocolInfo extends CborStructure {
  public encodedStructure(): ProtocolInfoStructure {
    throw new CborEncodeError('protocolInfo is RFU (reserved for future use)')
  }

  public static fromEncodedStructure(_encodedStructure: unknown): ProtocolInfo {
    throw new CborEncodeError('protocolInfo is RFU (reserved for future use)')
  }
}
