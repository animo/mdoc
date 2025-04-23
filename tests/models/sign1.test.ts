import { describe, expect, test } from 'vitest'
import { hexToUint8Array } from '../../src'
import { Sign1 } from '../../src/cose/sign1'

const cbor =
  'd28441a0a201260442313154546869732069732074686520636f6e74656e742e584087db0d2e5571843b78ac33ecb2830df7b6e0a4d5b7376de336b23c591c90c425317e56127fbe04370097ce347087b233bf722b64072beb4486bda4031d27244f'

describe('sign1', () => {
  test('parse', () => {
    const sign1 = Sign1.decode(hexToUint8Array(cbor))

    expect(sign1.unprotectedHeaders.headers).toBeDefined()
    expect(sign1.payload).toBeDefined()
    expect(sign1.signature).toBeDefined()

    // @todo the tag is not included, but everything else is the same
    // const encodedSign1 = sign1.encode()
    // const encodedSign1InHex = uint8ArrayToHex(encodedSign1)
    // expect(encodedSign1InHex).toStrictEqual(cbor)
  })
})
