import type { DocRequest } from '../mdoc/models/doc-request'
import { IssuerNamespaces } from '../mdoc/models/issuer-namespaces'
import type { IssuerSigned } from '../mdoc/models/issuer-signed'
import type { IssuerSignedItem } from '../mdoc/models/issuer-signed-item'
import type { Namespace } from '../mdoc/models/namespace'
import { findAgeOverCandidate } from './ageOver'

export const limitDisclosureToDeviceRequestNameSpaces = (
  issuerSigned: IssuerSigned,
  docRequest: DocRequest
): IssuerNamespaces => {
  const issuerNamespaces = new Map<Namespace, Array<IssuerSignedItem>>()
  for (const [namespace, nameSpaceFields] of docRequest.itemsRequest.namespaces.entries()) {
    const nsAttrs = issuerSigned.issuerNamespaces?.issuerNamespaces.get(namespace) ?? []
    const issuerSignedItems = Array.from(nameSpaceFields.entries()).map(([elementIdentifier, _]) => {
      const issuerSignedItem = prepareIssuerSignedItem(elementIdentifier, nsAttrs)

      if (!issuerSignedItem) {
        throw new Error(`No matching field found for '${elementIdentifier}'`)
      }
      return issuerSignedItem
    })
    issuerNamespaces.set(namespace, issuerSignedItems)
  }

  return IssuerNamespaces.create({ issuerNamespaces })
}

const prepareIssuerSignedItem = (
  elementIdentifier: string,
  nsAttrs: Array<IssuerSignedItem>
): IssuerSignedItem | null => {
  // An age_over_NN request may be answered with a different age attestation (18013-5 7.2.5).
  const ageOverItem = findAgeOverCandidate(elementIdentifier, nsAttrs)
  if (ageOverItem) return ageOverItem

  const digest = nsAttrs.find((d) => d.elementIdentifier === elementIdentifier)
  return digest ?? null
}
