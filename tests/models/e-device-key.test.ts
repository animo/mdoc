import { describe, expect, test } from 'vitest'
import { Curve, KeyType } from '../../src/cose/key/key'
import { EDeviceKey } from '../../src/mdoc/model/e-device-key'
import { hex } from '../../src/utils'

const cbor =
  'b90004613102622d3101622d3258205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe622d335820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67'

describe('e device key', () => {
  test('parse', () => {
    const eDeviceKey = EDeviceKey.decode(hex.decode(cbor))

    expect(eDeviceKey.keyType).toStrictEqual(KeyType.Ec)
    expect(eDeviceKey.curve).toStrictEqual(Curve['P-256'])
    expect(eDeviceKey.x).toBeDefined()
    expect(eDeviceKey.y).toBeDefined()
  })
})
