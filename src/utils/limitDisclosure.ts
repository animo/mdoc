import type { DocRequest } from '../mdoc/models/doc-request'
import { IssuerNamespaces } from '../mdoc/models/issuer-namespaces'
import type { IssuerSigned } from '../mdoc/models/issuer-signed'
import type { IssuerSignedItem } from '../mdoc/models/issuer-signed-item'
import type { Namespace } from '../mdoc/models/namespace'

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
  if (elementIdentifier.startsWith('age_over_')) {
    const digest = handleAgeOverNN(elementIdentifier, nsAttrs)
    return digest
  }

  const digest = nsAttrs.find((d) => d.elementIdentifier === elementIdentifier)
  return digest ?? null
}

const handleAgeOverNN = (request: string, attributes: IssuerSignedItem[]): IssuerSignedItem | null => {
  const ageOverList = attributes
    .map((a, i) => {
      const { elementIdentifier: key, elementValue: value } = a
      return { key, value, index: i }
    })
    .filter((i) => i.key.startsWith('age_over_'))
    .map((i) => ({
      nn: Number.parseInt(i.key.replace('age_over_', ''), 10),
      ...i,
    }))
    .sort((a, b) => a.nn - b.nn)

  const reqNN = Number.parseInt(request.replace('age_over_', ''), 10)

  let item: (typeof ageOverList)[number] | undefined
  // Find nearest TRUE
  item = ageOverList.find((i) => i.value === true && i.nn >= reqNN)

  if (!item) {
    // Find the nearest False
    item = ageOverList.sort((a, b) => b.nn - a.nn).find((i) => i.value === false && i.nn <= reqNN)
  }

  if (!item) {
    return null
  }

  return attributes[item.index]
}
