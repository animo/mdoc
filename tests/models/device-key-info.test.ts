import { describe, expect, test } from 'vitest'
import { DeviceKey } from '../../src/mdoc/model/device-key'
import { DeviceKeyInfo } from '../../src/mdoc/model/device-key-info'
import { hex } from '../../src/utils'

const cbor =
  'b90001696465766963654b6579b90004613102622d3101622d32582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a622d3358201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6'

describe('device key info', () => {
  test('parse', () => {
    const deviceKeyInfo = DeviceKeyInfo.decode(hex.decode(cbor))

    expect(deviceKeyInfo.keyInfo).toBeUndefined()
    expect(deviceKeyInfo.keyAuthorizations).toBeUndefined()
    expect(deviceKeyInfo.deviceKey).toBeInstanceOf(DeviceKey)
  })
})
