import type { VerificationCallback } from '../mdoc/check-callback'
import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'
import type { DeviceRequest } from '../mdoc/models/device-request'
import type { DeviceResponse } from '../mdoc/models/device-response'
import type { DocType } from '../mdoc/models/doctype'
import type { Document } from '../mdoc/models/document'
import type { IntentToRetain } from '../mdoc/models/intent-to-retain'
import type { Namespace } from '../mdoc/models/namespace'
import { findAgeOverCandidate } from './ageOver'

/**
 * Whether a disclosed element came from the issuer-signed or the device-signed part of a document.
 */
export type DisclosedElementSource = 'issuerSigned' | 'deviceSigned'

export type DisclosedElement = {
  namespace: Namespace
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
}

/**
 * How a single requested element is matched. An `ItemsRequest` can express neither that an element
 * is optional nor where it is expected to come from, so the verifier — which built the request —
 * provides it as context to the match.
 */
export type ElementMatchOptions = {
  /**
   * Whether the response may leave this element out without failing the match. An optional element
   * never makes a document fail, but it is still reported per claim. Defaults to `false`.
   */
  optional?: boolean
  /**
   * Where the element may be disclosed from. Device-signed elements are asserted by the mdoc
   * itself and not by the issuer, so an element the issuer is expected to attest to, an
   * `age_over_NN` for instance must not be answered from `deviceSigned`. Defaults to
   * `'issuerSigned'`.
   *
   * Even if `'deviceSigned'` is allowed, the element must be in the key authorizations of the mdoc.
   */
  source?: DisclosedElementSource | 'any'
}

/**
 * Per-element match options, keyed by docType, namespace and element identifier. The element
 * identifier `'*'` applies to every element in the namespace that is not named explicitly, which is
 * how a namespace that is entirely device-signed is described.
 *
 * ```ts
 * {
 *   'org.iso.18013.5.1.mDL': {
 *     'org.iso.18013.5.1': { portrait: { optional: true } },
 *     'com.example.device': { '*': { source: 'deviceSigned' } },
 *   },
 * }
 * ```
 */
export type DeviceRequestElementOptions = Record<
  DocType,
  Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
>

export type ClaimMatchBase = {
  namespace: Namespace
  /**
   * The element identifier as it appears in the `ItemsRequest`.
   */
  elementIdentifier: DataElementIdentifier
  intentToRetain: IntentToRetain
  /**
   * Whether the element was matched as optional, and therefore cannot make the document fail.
   */
  optional: boolean
}

export type ClaimMatchSuccess = ClaimMatchBase & {
  success: true
  /**
   * The element identifier that was actually disclosed. Only differs from `elementIdentifier` when
   * an `age_over_NN` request was answered with a different age attestation (18013-5 7.2.5).
   */
  disclosedElementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
  source: DisclosedElementSource
}

export type ClaimMatchFailure = ClaimMatchBase & {
  success: false
  /**
   * `'notDisclosed'` — the document did not disclose the element at all.
   *
   * `'disallowedSource'` — the document did disclose it, but only from a source the match options
   * do not allow for this element. By default only `issuerSigned` is allowed, so a `deviceSigned`
   * element the verifier did not mark as device-signed fails here rather than counting as a match.
   */
  failure: 'notDisclosed' | 'disallowedSource'
  /**
   * The source the element was disclosed from, when `failure` is `'disallowedSource'`.
   */
  disclosedFrom?: DisclosedElementSource
  reason: string
}

export type ClaimMatch = ClaimMatchSuccess | ClaimMatchFailure

export type DocumentMatch = {
  /**
   * Index into `deviceResponse.documents` of the document this result is about.
   */
  documentIndex: number
  document: Document
  /**
   * `true` when every requested element of the doc request that is not optional was disclosed by
   * this document, from a source the match options allow for it.
   */
  success: boolean
  /**
   * One entry per requested element, in request order.
   */
  claims: Array<ClaimMatch>
  /**
   * Elements this document disclosed that the doc request did not ask for. Not a failure by itself
   * — it is the mdoc over-disclosing — but a verifier should not process data it did not request.
   */
  unrequestedClaims: Array<DisclosedElement>
  /**
   * Set when the document could not be matched at all, e.g. because the docType in the MSO differs
   * from the docType of the document.
   */
  reason?: string
}

export type DocRequestMatch = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * `true` when at least one document in the response satisfies this doc request in full.
   */
  success: boolean
  /**
   * Every document in the response with this docType, in response order. Empty when the response
   * returned nothing for the requested docType.
   */
  documents: Array<DocumentMatch>
  /**
   * Set when no document was returned for the requested docType.
   */
  reason?: string
}

export type DeviceRequestMatchResult = {
  /**
   * `true` when every doc request in the device request is satisfied by the device response.
   */
  success: boolean
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<DocRequestMatch>
  /**
   * Documents in the response whose docType no doc request asked for.
   */
  unrequestedDocuments: Array<{ documentIndex: number; docType: DocType; document: Document }>
}

/**
 * Match a `DeviceResponse` against the `DeviceRequest` it answers.
 *
 * The ISO mdoc DC API protocol (`org-iso-mdoc`) has no query language such as DCQL that describes
 * which claims a response has to contain, so this walks the device request itself and reports, per
 * doc request and per requested element, whether the response satisfies it.
 *
 * An element only counts as disclosed when it comes from `issuerSigned`, as `deviceSigned` elements
 * are asserted by the mdoc itself rather than by the issuer. Pass `elements` to mark elements that
 * are optional or that are expected to be device-signed.
 *
 * This is purely a structural comparison — it does not verify issuer auth, device auth or the
 * digests of the disclosed elements. Use it alongside `DeviceResponse.verify`, which runs it as
 * part of verification when a `deviceRequest` is passed.
 */
export const matchDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  deviceResponse: DeviceResponse
  /**
   * Per-element match options, for elements that are optional or that may be answered from
   * `deviceSigned`. Every element not named here is required and must be issuer-signed.
   */
  elements?: DeviceRequestElementOptions
}): DeviceRequestMatchResult => {
  const { deviceRequest, deviceResponse } = options

  const documents = deviceResponse.documents ?? []

  const matchedDocumentIndexes = new Set<number>()

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): DocRequestMatch => {
    const { docType, namespaces } = docRequest.itemsRequest

    const documentMatches: Array<DocumentMatch> = []
    for (const [documentIndex, document] of documents.entries()) {
      if (document.docType !== docType) continue

      matchedDocumentIndexes.add(documentIndex)
      documentMatches.push(
        matchDocument({ document, documentIndex, docType, namespaces, elements: options.elements?.[docType] })
      )
    }

    return {
      docRequestIndex,
      docType,
      success: documentMatches.some((documentMatch) => documentMatch.success),
      documents: documentMatches,
      ...(documentMatches.length === 0 && {
        reason: `Device response does not contain a document with docType '${docType}'`,
      }),
    }
  })

  const unrequestedDocuments = documents.flatMap((document, documentIndex) =>
    matchedDocumentIndexes.has(documentIndex) ? [] : [{ documentIndex, docType: document.docType, document }]
  )

  return {
    success: docRequests.every((docRequest) => docRequest.success),
    docRequests,
    unrequestedDocuments,
  }
}

const matchDocument = (options: {
  document: Document
  documentIndex: number
  docType: DocType
  namespaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
}): DocumentMatch => {
  const { document, documentIndex, docType, namespaces } = options

  // The docType outside the MSO is not signed, so a document that matches on it but not on the
  // docType the issuer attested to does not answer the doc request.
  const mobileSecurityObjectDocType = document.issuerSigned.issuerAuth.mobileSecurityObject.docType
  if (mobileSecurityObjectDocType !== docType) {
    return {
      documentIndex,
      document,
      success: false,
      claims: [],
      unrequestedClaims: [],
      reason: `Document has docType '${docType}', but the mobile security object has docType '${mobileSecurityObjectDocType}'`,
    }
  }

  const disclosed = collectDisclosedElements(document)
  const claims: Array<ClaimMatch> = []
  const usedElements = new Set<DisclosedElement>()

  for (const [namespace, requestedElements] of namespaces) {
    const disclosedInNamespace = disclosed.filter((element) => element.namespace === namespace)

    for (const [elementIdentifier, intentToRetain] of requestedElements) {
      const { optional = false, source = 'issuerSigned' } =
        options.elements?.[namespace]?.[elementIdentifier] ?? options.elements?.[namespace]?.['*'] ?? {}

      const claim = { namespace, elementIdentifier, intentToRetain, optional }

      // The source is applied before the element is picked, so that an `age_over_NN` request is not
      // answered by a device-signed attestation while an issuer-signed one is also present.
      const element = findElement(
        elementIdentifier,
        disclosedInNamespace.filter((candidate) => source === 'any' || candidate.source === source)
      )

      if (element) {
        usedElements.add(element)
        claims.push({
          ...claim,
          success: true,
          disclosedElementIdentifier: element.elementIdentifier,
          elementValue: element.elementValue,
          source: element.source,
        })
        continue
      }

      // The element may still be there, just not from a source this verifier accepts for it —
      // report that rather than letting it pass or reporting it as absent.
      const disallowed =
        source === 'any'
          ? undefined
          : findElement(
              elementIdentifier,
              disclosedInNamespace.filter((candidate) => candidate.source !== source)
            )

      if (disallowed) {
        usedElements.add(disallowed)
        claims.push({
          ...claim,
          success: false,
          failure: 'disallowedSource',
          disclosedFrom: disallowed.source,
          reason: `Element '${disallowed.elementIdentifier}' in namespace '${namespace}' was disclosed through ${disallowed.source}, but must be disclosed through ${source}`,
        })
        continue
      }

      claims.push({
        ...claim,
        success: false,
        failure: 'notDisclosed',
        reason: `Element '${elementIdentifier}' in namespace '${namespace}' was not disclosed`,
      })
    }
  }

  return {
    documentIndex,
    document,
    success: claims.every((claim) => claim.success || claim.optional),
    claims,
    unrequestedClaims: disclosed.filter((element) => !usedElements.has(element)),
  }
}

/**
 * The disclosed element that answers a request for `elementIdentifier`, either by identifier or,
 * for an age attestation, by the substitution 18013-5 7.2.5 allows.
 */
const findElement = (elementIdentifier: DataElementIdentifier, candidates: Array<DisclosedElement>) =>
  candidates.find((candidate) => candidate.elementIdentifier === elementIdentifier) ??
  findAgeOverCandidate(elementIdentifier, candidates)

const collectDisclosedElements = (document: Document): Array<DisclosedElement> => {
  const disclosed: Array<DisclosedElement> = []

  for (const [namespace, issuerSignedItems] of document.issuerSigned.issuerNamespaces?.issuerNamespaces ?? []) {
    for (const issuerSignedItem of issuerSignedItems) {
      disclosed.push({
        namespace,
        elementIdentifier: issuerSignedItem.elementIdentifier,
        elementValue: issuerSignedItem.elementValue,
        source: 'issuerSigned',
      })
    }
  }

  for (const [namespace, deviceSignedItems] of document.deviceSigned.deviceNamespaces?.deviceNamespaces ?? []) {
    for (const [elementIdentifier, elementValue] of deviceSignedItems.deviceSignedItems) {
      disclosed.push({ namespace, elementIdentifier, elementValue, source: 'deviceSigned' })
    }
  }

  return disclosed
}

/**
 * Report a {@link DeviceRequestMatchResult} through a verification callback.
 *
 * A doc request that is not satisfied is a `FAILED` check; over-disclosure and documents that were
 * never requested are reported as `WARNING`, as they are the mdoc's doing and it is up to the
 * verifier whether to accept the response anyway.
 *
 * The match is attached to the per doc request checks as their structured `result`, so that it
 * survives a callback that throws on a `FAILED` check instead of collecting them.
 */
export const reportDeviceRequestMatch = (match: DeviceRequestMatchResult, onCheck: VerificationCallback) => {
  for (const docRequest of match.docRequests) {
    const check = `Device response must satisfy doc request ${docRequest.docRequestIndex} for docType '${docRequest.docType}'`

    const result = { type: 'deviceRequestMatch', match } as const

    if (docRequest.success) {
      onCheck({ status: 'PASSED', check, category: 'DOCUMENT_FORMAT', result })
    } else {
      onCheck({
        status: 'FAILED',
        check,
        category: 'DOCUMENT_FORMAT',
        reason: docRequestFailureReason(docRequest),
        result,
      })
    }

    for (const document of docRequest.documents) {
      if (document.unrequestedClaims.length === 0) continue

      onCheck({
        status: 'WARNING',
        check: `Document ${document.documentIndex} must not disclose elements that were not requested`,
        category: 'DOCUMENT_FORMAT',
        reason: `Document ${document.documentIndex} disclosed ${document.unrequestedClaims
          .map((claim) => `'${claim.elementIdentifier}' in namespace '${claim.namespace}'`)
          .join(', ')}, which doc request ${docRequest.docRequestIndex} did not ask for`,
      })
    }
  }

  if (match.unrequestedDocuments.length > 0) {
    onCheck({
      status: 'WARNING',
      check: 'Device response must not contain documents that were not requested',
      category: 'DOCUMENT_FORMAT',
      reason: `Device response contains ${match.unrequestedDocuments
        .map((document) => `document ${document.documentIndex} with docType '${document.docType}'`)
        .join(', ')}, which the device request did not ask for`,
    })
  }
}

const docRequestFailureReason = (docRequest: DocRequestMatch) => {
  if (docRequest.documents.length === 0) {
    return docRequest.reason ?? `No document matched docType '${docRequest.docType}'`
  }

  return docRequest.documents
    .map((document) => {
      if (document.reason) return `Document ${document.documentIndex}: ${document.reason}`

      const failedClaims = document.claims.filter(
        (claim): claim is ClaimMatchFailure => !claim.success && !claim.optional
      )
      return `Document ${document.documentIndex}: ${failedClaims.map((claim) => claim.reason).join('; ')}`
    })
    .join('. ')
}
