import type { MdocContext } from '../../c-mdoc'
import { DataItem, cborDecode, cborEncode } from '../../cbor'
import type { Sign1 } from '../../cose/sign1'
import type { ItemsRequest } from '../items-request'
import type { SessionTranscript } from './session-transcript'

export type ReaderAuthenticationOptions = {
  sessionTranscript: SessionTranscript
  itemRequest: ItemsRequest
  readerAuth: Uint8Array
}

export class ReaderAuthentication {
  private identifier = 'ReaderAuthentication'
  public sessionTranscript: SessionTranscript
  public itemsRequest: ItemsRequest
  private readerAuth: Sign1

  public constructor(options: ReaderAuthenticationOptions) {
    this.sessionTranscript = options.sessionTranscript
    this.itemsRequest = options.itemRequest

    this.readerAuth = cborDecode<Sign1>(options.readerAuth)
    this.readerAuth.assertEmptyPayload()
  }

  public async verify(ctx: { cose: MdocContext['cose'] }) {
    this.readerAuth.getRawVerificationData({ detachedPayload: this.encode() })
    ctx.cose.sign1.verify({})
  }

  public encode() {
    return cborEncode(DataItem.fromData([this.identifier, this.sessionTranscript, this.itemsRequest]))
  }
}
