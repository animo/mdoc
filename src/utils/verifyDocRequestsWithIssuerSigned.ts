import type { IssuerSigned } from '../mdoc'
import type { DocRequest } from '../mdoc/models/doc-request'
import { findIssuerSigned } from './findIssuerSigned'

export const verifyDocRequestsWithIssuerSigned = (docRequests: Array<DocRequest>, is: Array<IssuerSigned>) => {
  for (const docRequest of docRequests) {
    const issuerSigned = findIssuerSigned(is, docRequest.itemsRequest.docType)
    for (const [namespace, values] of docRequest.itemsRequest.namespaces) {
      const issuerSignedItems = issuerSigned.getIssuerNamespace(namespace)
      if (!issuerSignedItems) {
        throw new Error(`Could not find issuer namespace for the requested namespace '${namespace}'`)
      }
      for (const identifier of values.keys()) {
        const issuerSignedItem = issuerSignedItems.find((isi) => isi.elementIdentifier === identifier)
        if (!issuerSignedItem) {
          throw new Error(
            `Found issuer namespace '${namespace}', but could not find the element for identifier '${identifier}'`
          )
        }
      }
    }
  }
}
