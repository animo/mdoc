import { describe, expect, test } from 'vitest'
import { Mac0 } from '../../src/cose/mac0'
import { hex } from '../../src/utils'

const cbor =
  'd18441a0a1010554546869732069732074686520636f6e74656e742e5820176dce14c1e57430c13658233f41dc89aa4fa0ff9b8783f23b0ef51ca6b026bc'

describe('mac0', () => {
  test('parse', () => {
    const mac0 = Mac0.decode(hex.decode(cbor))

    expect(mac0.unprotectedHeaders.headers).toBeDefined()
    expect(mac0.payload).toBeDefined()
    expect(mac0.tag).toBeDefined()

    // @todo the tag is not included, but everything else is the same
    // const encodedSign1 = mac0.encode()
    // const encodedSign1InHex = uint8ArrayToHex(encodedSign1)
    // expect(encodedSign1InHex).toStrictEqual(cbor)
  })
})
