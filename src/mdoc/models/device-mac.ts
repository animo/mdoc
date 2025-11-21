import { type CborDecodeOptions, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import type { CoseKey } from '../../cose'
import { Mac0, type Mac0Structure } from '../../cose/mac0'
import { SessionTranscript } from './session-transcript'

export type DeviceMacStructure = Mac0Structure

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

  public static override fromEncodedStructure(encodedStructure: DeviceMacStructure): DeviceMac {
    return new DeviceMac({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      tag: encodedStructure[3],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceMac {
    const data = cborDecode<DeviceMacStructure>(bytes, options)
    return DeviceMac.fromEncodedStructure(data)
  }
}
