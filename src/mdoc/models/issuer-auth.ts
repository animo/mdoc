import { type CborDecodeOptions, DataItem, cborDecode } from '../../cbor/index.js'
import type { MdocContext } from '../../context.js'
import { CosePayloadInvalidStructureError, CosePayloadMustBeDefinedError } from '../../cose/error.js'
import { Sign1, type Sign1Options, type Sign1Structure } from '../../cose/sign1.js'
import { type VerificationCallback, defaultVerificationCallback, onCategoryCheck } from '../check-callback.js'
import { MobileSecurityObject, type MobileSecurityObjectStructure } from './mobile-security-object.js'

export type IssuerAuthStructure = Sign1Structure
export type IssuerAuthOptions = Sign1Options

export class IssuerAuth extends Sign1 {
  public get mobileSecurityObject(): MobileSecurityObject {
    if (!this.payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const dataItem = cborDecode<DataItem<MobileSecurityObjectStructure>>(this.payload, {
      unwrapTopLevelDataItem: false,
    })

    if (!(dataItem instanceof DataItem)) {
      throw new CosePayloadInvalidStructureError()
    }

    const mso = MobileSecurityObject.decode(dataItem.buffer)

    return mso
  }

  public async validate(
    options: {
      verificationCallback?: VerificationCallback
      now?: Date
      trustedCertificates?: Array<Uint8Array>
      disableCertificateChainValidation?: boolean
    },
    ctx: Pick<MdocContext, 'x509' | 'cose'>
  ) {
    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback
    const now = options.now ?? new Date()
    const disableCertificateChainValidation = options.disableCertificateChainValidation ?? false
    const trustedCertificates = options.trustedCertificates ?? []

    const onCheck = onCategoryCheck(verificationCallback, 'ISSUER_AUTH')

    onCheck({
      status: this.getIssuingCountry(ctx) ? 'PASSED' : 'FAILED',
      check: "Country name (C) must be present in the issuer certificate's subject distinguished name",
    })

    if (!disableCertificateChainValidation) {
      try {
        if (!trustedCertificates[0]) {
          throw new Error('No trusted certificates found. Cannot verify issuer signature.')
        }

        await ctx.x509.validateCertificateChain({
          trustedCertificates,
          x5chain: this.certificateChain,
        })

        onCheck({
          status: 'PASSED',
          check: 'Issuer certificate must be valid',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Issuer certificate must be valid',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }

    const isSignatureValid = await this.verify({}, ctx)

    onCheck({
      status: isSignatureValid ? 'PASSED' : 'FAILED',
      check: 'Issuer auth signature is invalid',
    })

    const { validityInfo } = this.mobileSecurityObject

    const { notAfter, notBefore } = await ctx.x509.getCertificateData({
      certificate: this.certificate,
    })

    onCheck({
      status: validityInfo.validateSigned(notBefore, notAfter) ? 'FAILED' : 'PASSED',
      check: 'The MSO signed date must be within the validity period of the certificate',
      reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${notBefore.toUTCString()} to ${notAfter.toUTCString()})`,
    })

    onCheck({
      status: now < validityInfo.validFrom || now > validityInfo.validUntil ? 'FAILED' : 'PASSED',
      check: 'The MSO must be valid at the time of verification',
      reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions) {
    const data = cborDecode<IssuerAuthStructure>(bytes, options)
    return IssuerAuth.fromEncodedStructure(data)
  }

  public static override fromEncodedStructure(encodedStructure: IssuerAuthStructure): IssuerAuth {
    return new IssuerAuth({
      protectedHeaders: encodedStructure[0],
      unprotectedHeaders: encodedStructure[1],
      payload: encodedStructure[2],
      signature: encodedStructure[3],
    })
  }
}
