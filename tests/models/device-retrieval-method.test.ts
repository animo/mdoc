import { describe, expect, test } from 'vitest'
import { BleOptions } from '../../src/mdoc/model/ble-options'
import { DeviceRetrievalMethod, DeviceRetrievalMethodType } from '../../src/mdoc/model/device-retrieval-method'
import { hex } from '../../src/utils'

const cbor = '830201b900036130f46131f56231315045efef742b2c4837a9a3b0e1d05a6917'

describe('device retrieval method', () => {
  test('parse', () => {
    const deviceRetrievalMethod = DeviceRetrievalMethod.decode(hex.decode(cbor))

    expect(deviceRetrievalMethod.version).toStrictEqual(1)
    expect(deviceRetrievalMethod.type).toStrictEqual(DeviceRetrievalMethodType.Ble)
    expect(deviceRetrievalMethod.retrievalOptions).instanceof(BleOptions)

    const ro = deviceRetrievalMethod.retrievalOptions as BleOptions

    expect(ro.centralClientMode).toStrictEqual(true)
    expect(ro.centralClientModeUuid).toBeDefined()

    expect(ro.peripheralServerMode).toStrictEqual(false)
    expect(ro.peripheralServerModeUuid).toBeUndefined()
    expect(ro.peripheralServerModeDeviceAddress).toBeUndefined()
  })
})
