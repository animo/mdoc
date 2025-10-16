import { describe, expect, test } from 'vitest'
import { CoseKey, cborDecode } from '../../src'
import { Header } from '../../src/cose/headers/defaults'
import { Sign1 } from '../../src/cose/sign1'
import { hex } from '../../src/utils'
import { mdocContext } from '../context'
import { sign1TestVector01, sign1TestVector02 } from './vectors'

const cbor = hex.decode(
  'd28441a0a201260442313154546869732069732074686520636f6e74656e742e584087db0d2e5571843b78ac33ecb2830df7b6e0a4d5b7376de336b23c591c90c425317e56127fbe04370097ce347087b233bf722b64072beb4486bda4031d27244f'
)

describe('sign1', () => {
  test('parse', async () => {
    const sign1 = Sign1.decode(cbor)

    expect(sign1.unprotectedHeaders.headers?.has(Header.Algorithm)).toBeTruthy()
    expect(sign1.unprotectedHeaders.headers?.has(Header.KeyId)).toBeTruthy()
    expect(sign1.payload).toBeDefined()
    expect(sign1.signature).toBeDefined()
  })
  ;[sign1TestVector01, sign1TestVector02].map(async (testVector) => {
    test(`${testVector.title} :: ${testVector.description}`, async () => {
      const key = CoseKey.fromJwk(testVector.key)

      const sign1 = new Sign1({
        protectedHeaders: hex.decode(testVector['sign1::sign'].protectedHeaders.cborHex),
        unprotectedHeaders: cborDecode(hex.decode(testVector['sign1::sign'].unprotectedHeaders.cborHex)),
        payload: hex.decode(testVector['sign1::sign'].payload),
        externalAad: hex.decode(testVector['sign1::sign'].external),
        signature: cborDecode<Sign1>(hex.decode(testVector['sign1::sign'].expectedOutput.cborHex)).signature,
      })

      const tbsHex = hex.encode(sign1.toBeSigned)

      expect(tbsHex).toStrictEqual(testVector['sign1::sign'].tbsHex.cborHex)

      const isValid = await sign1.verifySignature({ key }, mdocContext)
      expect(isValid).toBeTruthy()

      await sign1.addSignature({ signingKey: key }, mdocContext)

      const isValidAfterResign = await sign1.verifySignature({ key }, mdocContext)
      expect(isValidAfterResign).toBeTruthy()
    })
  })
})
