import type { DocRequest } from './doc-request'
import type { DocType } from './doctype'
import type { Document } from './document'
import { IssuerNamespace } from './issuer-namespace'
import type { IssuerSigned } from './issuer-signed'
import type { IssuerSignedItem } from './issuer-signed-item'
import type { Namespace } from './namespace'
import type { InputDescriptor } from './presentation-definition'

export const limitDisclosureToDeviceRequestNameSpaces = (
  issuerSigned: IssuerSigned,
  docRequest: DocRequest
): IssuerNamespace => {
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

  return new IssuerNamespace({ issuerNamespaces })
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

const prepareDigestForInputDescriptor = (
  paths: string[],
  issuerNameSpaces?: IssuerNamespace
): { namespace: string; digest: IssuerSignedItem } | null => {
  for (const path of paths) {
    const { nameSpace: namespace, elementIdentifier } = parsePath(path)
    const nsAttrs = issuerNameSpaces?.issuerNamespaces.get(namespace) ?? []

    const digest = prepareIssuerSignedItem(elementIdentifier, nsAttrs)
    if (digest) return { namespace, digest }
  }
  return null
}

const parsePath = (
  path: string
): {
  nameSpace: string
  elementIdentifier: string
} => {
  /**
   * path looks like this: "$['org.iso.18013.5.1']['family_name']"
   * the regex creates two groups with contents between "['" and "']"
   * the second entry in each group contains the result without the "'[" or "']"
   *
   * @example org.iso.18013.5.1 family_name
   */
  const matches = [...path.matchAll(/\['(.*?)'\]/g)]
  if (matches.length !== 2) {
    throw new Error(`Invalid path format: "${path}"`)
  }

  const [nameSpaceMatch, elementIdentifierMatch] = matches
  const nameSpace = nameSpaceMatch?.[1]
  const elementIdentifier = elementIdentifierMatch?.[1]

  if (!nameSpace || !elementIdentifier) {
    throw new Error(`Failed to parse path: "${path}"`)
  }

  return { nameSpace, elementIdentifier }
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

export const findMdocMatchingDocType = (documents: Array<Document>, docType: DocType) => {
  const matchingMdoc = documents.filter((document) => document.docType === docType)

  if (!matchingMdoc || !matchingMdoc[0]) {
    throw new Error(`Cannot limit the disclosure. No credential is matching the requested DocType '${docType}'`)
  }

  if (matchingMdoc.length > 1) {
    throw new Error(`Cannot limit the disclosure. Multiple credentials are matching the requested DocType '${docType}'`)
  }

  return matchingMdoc[0]
}

export const limitDisclosureToInputDescriptor = (
  issuerSigned: IssuerSigned,
  inputDescriptor: InputDescriptor
): IssuerNamespace => {
  const issuerNamespaces = new Map<Namespace, Array<IssuerSignedItem>>()

  for (const field of inputDescriptor.constraints.fields) {
    const result = prepareDigestForInputDescriptor(field.path, issuerSigned.issuerNamespaces)

    if (!result && field.optional) {
      continue
    }

    if (!result) {
      throw new Error(
        `Cannot limit the disclosure to the input descriptor. No matching field found for '${field.path.join('.')}'`
      )
    }

    const { namespace, digest } = result
    const entry = issuerNamespaces.get(namespace)
    if (!entry) issuerNamespaces.set(namespace, [digest])
    else entry.push(digest)
  }
  return new IssuerNamespace({ issuerNamespaces })
}
