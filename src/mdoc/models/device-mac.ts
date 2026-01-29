import type { MdocContext } from '../../context'
import type { CoseKey, Mac0Options } from '../../cose'
import { Mac0, type Mac0DecodedStructure, type Mac0EncodedStructure } from '../../cose/mac0'
import { SessionTranscript } from './session-transcript'

export type DeviceMacEncodedStructure = Mac0EncodedStructure
export type DeviceMacDecodedStructure = Mac0DecodedStructure
export type DeviceMacOptions = Mac0Options

export class DeviceMac extends Mac0 {
  public async verify(
    options: {
      publicKey: CoseKey
      privateKey: CoseKey
      info?: 'EMacKey' | 'SKReader' | 'SKDevice'
      sessionTranscript: SessionTranscript | Uint8Array
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const key = await ctx.crypto.calculateEphemeralMacKey({
      privateKey: options.privateKey.privateKey,
      publicKey: options.publicKey.publicKey,
      sessionTranscriptBytes:
        options.sessionTranscript instanceof SessionTranscript
          ? options.sessionTranscript.encode({ asDataItem: true })
          : options.sessionTranscript,
      info: options.info ?? 'EMacKey',
    })

    return ctx.cose.mac0.verify({
      mac0: this,
      key,
    })
  }

  public static async create(options: DeviceMacOptions, ctx: Pick<MdocContext, 'cose' | 'crypto'>) {
    return super.create(options, ctx) as Promise<DeviceMac>
  }
}
