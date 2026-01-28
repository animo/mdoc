import z from 'zod'
import { CborStructure } from '../../cbor'

const protocolInfoSchema = z.unknown()
export type ProtocolInfoStructure = z.infer<typeof protocolInfoSchema>

export class ProtocolInfo extends CborStructure<ProtocolInfoStructure> {
  public static override get encodingSchema() {
    return protocolInfoSchema
  }
}
