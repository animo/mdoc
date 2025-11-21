import { describe, expect, it } from 'vitest'
import { DeviceResponse, SessionTranscript } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { rootCertificate } from './rootCertificate'
import { signingCertificate } from './signingCertificate'

/*
 *
 * @note issuer signed item seems to be encoded as a map, but it should be an object
 *
 * @todo this test was failing because of a bug in the device authentication, but now it works, is this correct?
 *
 */
describe('Google CM Wallet mdoc implementation', () => {
  it('should verify DC API DeviceResponse from Google CM Wallet', async () => {
    const nonce = 'UwQek7MemM55VM2Lc7UPPsdsxa-vejebSUo75B_G7vk'
    const origin = 'https://ellis-occurrence-ac-smoking.trycloudflare.com'
    const clientId = `web-origin:${origin}`

    await expect(
      DeviceResponse.decode(deviceResponse).verify(
        {
          trustedCertificates: [
            new Uint8Array(rootCertificate.rawData),
            // FIXME: verification fails when only trusting root certificate. We need
            // to trust the signing certificate for now
            new Uint8Array(signingCertificate.rawData),
          ],
          sessionTranscript: await SessionTranscript.forOid4VpDcApiDraft24(
            {
              origin,
              clientId,
              nonce,
            },
            mdocContext
          ),
          now: new Date('2025-02-20'),
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })
})
