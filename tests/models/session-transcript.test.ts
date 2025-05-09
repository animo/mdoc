import { describe, expect, test } from 'vitest'
import { DeviceEngagement } from '../../src/mdoc/models/device-engagement'
import { EReaderKey } from '../../src/mdoc/models/e-reader-key'
import { NfcHandover } from '../../src/mdoc/models/nfc-handover'
import { SessionTranscript } from '../../src/mdoc/models/session-transcript'
import { hex } from '../../src/utils'

const cbor =
  'd81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414'

describe('session transcript', () => {
  test('parse', () => {
    const sessionTranscript = SessionTranscript.decode(hex.decode(cbor))

    expect(sessionTranscript.deviceEngagement).toBeInstanceOf(DeviceEngagement)
    expect(sessionTranscript.eReaderKey).toBeInstanceOf(EReaderKey)
    expect(sessionTranscript.handover).toBeInstanceOf(NfcHandover)

    const nh = sessionTranscript.handover as NfcHandover

    expect(nh.selectMessage).toBeDefined()
    expect(nh.requestMessage).toBeDefined()
  })
})
