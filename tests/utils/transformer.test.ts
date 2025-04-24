import { describe, expect, test } from 'vitest'
import { base64, base64url, bytesToString, compareBytes, concatBytes, hex, stringToBytes } from '../../src/utils'

describe('transformer', () => {
  test('base64', () => {
    const s = 'Hello World!'
    const b = stringToBytes(s)
    const encoded = base64.encode(b)
    const decoded = base64.decode(encoded)
    const received = bytesToString(decoded)
    expect(received).toStrictEqual(s)
  })

  test('base64url', () => {
    const s = 'Hello World!'
    const b = stringToBytes(s)
    const encoded = base64url.encode(b)
    const decoded = base64url.decode(encoded)
    const received = bytesToString(decoded)
    expect(received).toStrictEqual(s)
  })

  test('hex', () => {
    const s = 'Hello World!'
    const b = stringToBytes(s)
    const encoded = hex.encode(b)
    const decoded = hex.decode(encoded)
    const received = bytesToString(decoded)
    expect(received).toStrictEqual(s)
  })

  test('contact bytes', () => {
    const b1 = Uint8Array.from([1, 2, 3])
    const b2 = Uint8Array.from([4, 5, 6])
    const b3 = concatBytes([b1, b2])

    expect(b3).toContain(1)
    expect(b3).toContain(2)
    expect(b3).toContain(3)
    expect(b3).toContain(4)
    expect(b3).toContain(5)
    expect(b3).toContain(6)
  })

  test('compare bytes', () => {
    const b1 = Uint8Array.from([1, 2, 3])
    const b2 = Uint8Array.from([4, 5, 6])
    const b3 = Uint8Array.from([4, 5, 6])
    const b4 = Uint8Array.from([4, 5, 6, 7])

    const compareSameInstance = compareBytes(b1, b1)
    const compareSameLength = compareBytes(b1, b2)
    const compareSameContent = compareBytes(b2, b3)
    const compareDifferentLength = compareBytes(b3, b4)

    expect(compareSameInstance).toStrictEqual(true)
    expect(compareSameLength).toStrictEqual(false)
    expect(compareSameContent).toStrictEqual(true)
    expect(compareDifferentLength).toStrictEqual(false)
  })
})
