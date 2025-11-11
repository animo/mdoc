import type { DocType } from '../mdoc/models/doctype'
import type { IssuerSigned } from '../mdoc/models/issuer-signed'

export const findIssuerSigned = (is: Array<IssuerSigned>, docType: DocType) => {
  const issuerSigned = is.filter((i) => i.issuerAuth.mobileSecurityObject.docType === docType)

  if (!issuerSigned || !issuerSigned[0]) {
    throw new Error(`Cannot limit the disclosure. No Issuer Signed Item matching docType '${docType}'`)
  }

  if (issuerSigned.length > 1) {
    throw new Error(`Cannot limit the disclosure. Multiple Issuer Signed Items matching docType '${docType}'`)
  }

  return issuerSigned[0]
}
