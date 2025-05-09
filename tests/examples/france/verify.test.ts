import { describe, expect, it } from 'vitest'
import { DeviceResponse, SessionTranscript } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate } from './issuerCertificate'

/*
 *
 * @note issuer signed item seems to be encoded as a map, but it should be an object
 *
 */
describe('French playground mdoc implementation', () => {
  it('should verify DeviceResponse from French playground', async () => {
    const verifierGeneratedNonce = 'abcdefgh1234567890'
    const mdocGeneratedNonce = ''
    const clientId = 'example.com'
    const responseUri = 'https://example.com/12345/response'

    await expect(
      async () =>
        await DeviceResponse.decode(deviceResponse).validate(
          {
            trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
            sessionTranscript: await SessionTranscript.calculateSessionTranscriptBytesForOid4Vp(
              {
                clientId,
                responseUri,
                verifierGeneratedNonce,
                mdocGeneratedNonce,
              },
              mdocContext
            ),
            now: new Date('2021-09-25'),
          },
          mdocContext
        )
    ).rejects.toThrow()
  })
})
