import { type CborDecodeOptions, cborDecode } from '../../cbor'
import type { MdocContext } from '../../context'
import { Sign1, type Sign1Structure } from '../../cose/sign1'
import { type VerificationCallback, defaultVerificationCallback, onCategoryCheck } from '../check-callback'
import { ReaderAuthentication, type ReaderAuthenticationOptions } from './reader-authentication'

export type ReaderAuthStructure = Sign1Structure

export class ReaderAuth extends Sign1 {
  public static override fromEncodedStructure(encodedStructure: ReaderAuthStructure): ReaderAuth {
    return new ReaderAuth({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ReaderAuth {
    const data = cborDecode<ReaderAuthStructure>(bytes, options)
    return ReaderAuth.fromEncodedStructure(data)
  }

  public async verify(
    options: {
      readerAuthentication: ReaderAuthentication | ReaderAuthenticationOptions
      verificationCallback?: VerificationCallback
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const readerAuthentication =
      options.readerAuthentication instanceof ReaderAuthentication
        ? options.readerAuthentication
        : new ReaderAuthentication(options.readerAuthentication)

    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'READER_AUTH')

    this.detachedContent = readerAuthentication.encode({ asDataItem: true })

    const isValid = await this.verifySignature({}, ctx)

    onCheck({
      status: isValid ? 'PASSED' : 'FAILED',
      check: 'Signature is invalid on the reader auth',
      reason: 'Signature is invalid on the reader auth',
    })
  }
}
