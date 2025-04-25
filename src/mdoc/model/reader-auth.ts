import { type CborDecodeOptions, cborDecode } from '../../cbor'
import { Sign1, type Sign1Structure } from '../../cose/sign1'

export type ReaderAuthStructure = Sign1Structure

export class ReaderAuth extends Sign1 {
  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): ReaderAuth {
    const data = cborDecode<ReaderAuthStructure>(bytes, options)

    return ReaderAuth.fromEncodedStructure(data)
  }

  public static override fromEncodedStructure(encodedStructure: ReaderAuthStructure): Sign1 {
    return new ReaderAuth({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }
}
