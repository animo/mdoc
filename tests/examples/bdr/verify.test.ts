import { describe, it } from 'vitest'
import { IssuerSigned, Verifier } from '../../../src'
import { mdocContext } from '../../context'
import { issuerCertificate } from './issuerCertificate'
import { issuerSignedBytes } from './issuerSigned'

describe('BDR mDL implementation', () => {
  it('should verify mDL IssuerSigned from BDR', async () => {
    const issuerSigned = IssuerSigned.decode(issuerSignedBytes)

    const verifier = new Verifier()
    await verifier.verifyIssuerSignature(
      {
        trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
        disableCertificateChainValidation: false,
        issuerAuth: issuerSigned.issuerAuth,
      },
      mdocContext
    )
  })
})
