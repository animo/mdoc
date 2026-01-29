import z from 'zod'
import { Handover } from './handover'

const qrHandoverSchema = z.null()
export type QrHandoverStructure = z.infer<typeof qrHandoverSchema>

export class QrHandover extends Handover<QrHandoverStructure> {
  public static override get encodingSchema() {
    return qrHandoverSchema
  }

  public override get requiresReaderKey() {
    return true
  }

  public override get requiresDeviceEngagement() {
    return true
  }

  public static create() {
    return this.fromDecodedStructure(null)
  }
}
