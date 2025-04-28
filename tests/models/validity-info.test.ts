import { describe, expect, test } from 'vitest'
import { ValidityInfo } from '../../src/mdoc/model/validity-info'
import { hex } from '../../src/utils'

const cbor =
  'b90003667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a30325a'

describe('validity info', () => {
  test('parse', () => {
    const validityInfo = ValidityInfo.decode(hex.decode(cbor))

    expect(validityInfo.signed).toBeInstanceOf(Date)
    expect(validityInfo.validUntil).toBeInstanceOf(Date)
    expect(validityInfo.validFrom).toBeInstanceOf(Date)
    expect(validityInfo.expectedUpdate).toBeUndefined()

    expect(hex.encode(validityInfo.encode())).toStrictEqual(cbor)
  })
})
