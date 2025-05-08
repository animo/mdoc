import type { MdocContext } from '../context.js'
import type { VerificationCallback } from './check-callback.js'
import { defaultVerificationCallback, onCategoryCheck } from './check-callback.js'
import type { Document } from './models/document.js'
import type { IssuerSignedItem } from './models/issuer-signed-item.js'

const MDL_NAMESPADCE = 'org.iso.18013.5.1'

const DIGEST_ALGS = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
} as Record<string, string>

export class Verifier {
  public async verifyData(
    options: {
      document: Document
      verificationCallback?: VerificationCallback
    },
    ctx: Pick<MdocContext, 'x509' | 'crypto'>
  ) {
    const { issuerAuth } = options.document.issuerSigned
    const { valueDigests, digestAlgorithm } = issuerAuth.mobileSecurityObject

    const onCheck = onCategoryCheck(options.verificationCallback ?? defaultVerificationCallback, 'DATA_INTEGRITY')

    onCheck({
      status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
      check: 'Issuer Auth must include a supported digestAlgorithm element',
    })

    const namespaces =
      options.document.issuerSigned.issuerNamespaces?.issuerNamespaces ?? new Map<string, IssuerSignedItem[]>()

    await Promise.all(
      Array.from(namespaces.entries()).map(async ([ns, nsItems]) => {
        onCheck({
          status: valueDigests?.valueDigests.has(ns) ? 'PASSED' : 'FAILED',
          check: `Issuer Auth must include digests for namespace: ${ns}`,
        })

        const verifications = await Promise.all(
          nsItems.map(async (ev) => {
            const isValid = await ev.isValid(ns, issuerAuth, ctx)
            return { ev, ns, isValid }
          })
        )

        verifications
          .filter((v) => v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'PASSED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        verifications
          .filter((v) => !v.isValid)
          .forEach((v) => {
            onCheck({
              status: 'FAILED',
              check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
            })
          })

        if (ns === MDL_NAMESPADCE) {
          const certificateData = await ctx.x509.getCertificateData({
            certificate: issuerAuth.certificate,
          })
          if (!certificateData.issuerName) {
            onCheck({
              status: 'FAILED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason:
                "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
            })
          } else {
            const invalidCountry = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
              .find((v) => !v.isValid || !v.ev.matchCertificate(issuerAuth, ctx))

            onCheck({
              status: invalidCountry ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
              reason: invalidCountry
                ? `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${issuerAuth.getIssuingCountry(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })

            const invalidJurisdiction = verifications
              .filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
              .find((v) => !v.isValid || !v.ev.matchCertificate(issuerAuth, ctx))

            onCheck({
              status: invalidJurisdiction ? 'FAILED' : 'PASSED',
              check:
                "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
              reason: invalidJurisdiction
                ? `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${issuerAuth.getIssuingStateOrProvince(ctx)}) in the subject field within the issuer certificate`
                : undefined,
            })
          }
        }
      })
    )
  }
}
