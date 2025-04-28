import { describe, expect, test } from 'vitest'
import { DeviceAuth } from '../../src/mdoc/model/device-auth'
import { DeviceMac } from '../../src/mdoc/model/device-mac'
import { hex } from '../../src/utils'

const cbor = 'a1696465766963654d61638443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d'

describe('device auth', () => {
  test('parse', () => {
    const deviceAuth = DeviceAuth.decode(hex.decode(cbor))

    expect(deviceAuth.deviceMac).toBeInstanceOf(DeviceMac)
    expect(deviceAuth.deviceSignature).toBeUndefined()
  })
})
