import { describe, expect, test } from 'vitest'
import { Header } from '../../src/cose/headers/defaults'
import { Sign1 } from '../../src/cose/sign1'
import { hex } from '../../src/utils'

const cbor =
  'd28441a0a201260442313154546869732069732074686520636f6e74656e742e584087db0d2e5571843b78ac33ecb2830df7b6e0a4d5b7376de336b23c591c90c425317e56127fbe04370097ce347087b233bf722b64072beb4486bda4031d27244f'

describe('sign1', () => {
  test('parse', () => {
    const sign1 = Sign1.decode(hex.decode(cbor))

    expect(sign1.unprotectedHeaders.headers?.has(Header.Algorithm)).toBeTruthy()
    expect(sign1.unprotectedHeaders.headers?.has(Header.KeyID)).toBeTruthy()
    expect(sign1.payload).toBeDefined()
    expect(sign1.signature).toBeDefined()
  })
})
