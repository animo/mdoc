import type { MdocContext } from '../../context'
import { Sign1, type Sign1DecodedStructure, type Sign1EncodedStructure, type Sign1Options } from '../../cose/sign1'

export type DeviceSignatureEncodedStructure = Sign1EncodedStructure
export type DeviceSignatureDecodedStructure = Sign1DecodedStructure
export type DeviceSignatureOptions = Sign1Options

export class DeviceSignature extends Sign1 {
  // TODO: super should be generic, so we don't need this
  public static create(options: DeviceSignatureOptions, ctx: Pick<MdocContext, 'cose'>) {
    return super.create(options, ctx) as Promise<DeviceSignature>
  }
}
