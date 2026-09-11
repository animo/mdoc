import type { VerificationCallback } from '../mdoc/check-callback'
import { InvalidDeviceRequestMatchOptionsError } from '../mdoc/errors'
import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'
import type { DeviceNamespaces } from '../mdoc/models/device-namespaces'
import type { DeviceRequest } from '../mdoc/models/device-request'
import type { DeviceResponse } from '../mdoc/models/device-response'
import type { DocType } from '../mdoc/models/doctype'
import type { IntentToRetain } from '../mdoc/models/intent-to-retain'
import type { IssuerSigned } from '../mdoc/models/issuer-signed'
import type { IssuerSignedItem } from '../mdoc/models/issuer-signed-item'
import type { KeyAuthorizations } from '../mdoc/models/key-authorizations'
import type { Namespace } from '../mdoc/models/namespace'
import { findAgeOverCandidate } from './ageOver'

/**
 * Whether an element comes from the issuer-signed or the device-signed part of a document.
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
   * `age_over_NN` for instance, must not be answered from `deviceSigned`. Defaults to
   * `'issuerSigned'`.
   *
   * Even if `'deviceSigned'` is allowed, the element must be in the key authorizations of the mdoc.
   */
  source?: DisclosedElementSource | 'any'
}

/**
 * Match options for a single doc request.
 */
export type DocRequestMatchOptions = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request these options apply to.
   */
  docRequestIndex: number

  /**
   * Per-element match options, keyed by namespace and element identifier. The element identifier
   * `'*'` applies to every element in the namespace that is not named explicitly, which is how a
   * namespace that is entirely device-signed is described.
   *
   * ```ts
   * {
   *   'org.iso.18013.5.1': { portrait: { optional: true } },
   *   'com.example.device': { '*': { source: 'deviceSigned' } },
   * }
   * ```
   */
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
}

export type DeviceRequestMatchOptions = {
  /**
   * Match options per doc request, each referring to its doc request by `docRequestIndex`. A doc
   * request can have options at most once, and a doc request without options is matched with the
   * defaults: every element without options is required and must be issuer-signed.
   */
  docRequests?: Array<DocRequestMatchOptions>
}

export type ClaimMatchBase = {
  namespace: Namespace
  /**
   * The element identifier as it appears in the `ItemsRequest`.
   */
  elementIdentifier: DataElementIdentifier
  intentToRetain: IntentToRetain
  /**
   * Whether the element was matched as optional, and therefore cannot make the claims fail. Always
   * `false` when matching the credentials of a holder, as the request does not say which elements
   * are optional.
   */
  optional: boolean
}

export type ClaimMatchSuccess = ClaimMatchBase & {
  success: true
  /**
   * The element identifier that is disclosed. Only differs from `elementIdentifier` when an
   * `age_over_NN` request is answered with a different age attestation (18013-5 7.2.5).
   */
  disclosedElementIdentifier: DataElementIdentifier
  /**
   * The value of the element. When matching the credentials of a holder this is `undefined` for a
   * device-signed element, as its value is only provided when creating the response.
   */
  elementValue: DataElementValue
  source: DisclosedElementSource
}

export type ClaimMatchFailure = ClaimMatchBase & {
  success: false
  /**
   * `'notDisclosed'` — the document did not disclose the element, or the credential cannot: the
   * issuer did not sign it, and the device key is not authorized for it.
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

type NonEmptyArray<T> = [T, ...Array<T>]

/**
 * The document or credential has the docType the doc request asks for.
 */
export type DocTypeMatchSuccess = {
  success: true
  docType: DocType
}

/**
 * The document or credential does not have the docType the doc request asks for.
 */
export type DocTypeMatchFailure = {
  success: false
  /**
   * The docType of the document or credential.
   */
  docType: DocType
  reason: string
}

/**
 * Whether a document or credential has the docType the doc request asks for.
 */
export type DocTypeMatchResult = DocTypeMatchSuccess | DocTypeMatchFailure

/**
 * Every requested element that is not optional is disclosed.
 */
export type ClaimsMatchSuccess = {
  success: true
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The optional requested elements that are not disclosed, in request order.
   */
  failedClaims: Array<ClaimMatchFailure & { optional: true }>
}

/**
 * At least one requested element that is not optional is not disclosed.
 */
export type ClaimsMatchFailure = {
  success: false
  /**
   * The requested elements that are disclosed, in request order.
   */
  validClaims: Array<ClaimMatchSuccess>
  /**
   * The requested elements that are not disclosed, in request order. Can contain optional elements.
   */
  failedClaims: NonEmptyArray<ClaimMatchFailure>
}

/**
 * Whether a document or credential discloses the requested elements.
 */
export type ClaimsMatchResult = ClaimsMatchSuccess | ClaimsMatchFailure

type UnrequestedClaims = {
  /**
   * Elements the document disclosed that the doc request did not ask for. Not a failure by itself
   * — it is the mdoc over-disclosing — but a verifier should not process data it did not request.
   */
  unrequestedClaims: Array<DisclosedElement>
}

export type DocumentClaimsMatchSuccess = ClaimsMatchSuccess & UnrequestedClaims
export type DocumentClaimsMatchFailure = ClaimsMatchFailure & UnrequestedClaims
export type DocumentClaimsMatchResult = DocumentClaimsMatchSuccess | DocumentClaimsMatchFailure

type DocumentMatchBase = {
  /**
   * Index into `deviceResponse.documents` of the document this result is about.
   */
  documentIndex: number
}

/**
 * A document that satisfies the doc request: every check passed.
 */
export type DocumentMatchSuccess = DocumentMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  claims: DocumentClaimsMatchSuccess
}

/**
 * A document that does not satisfy the doc request: at least one check failed.
 */
export type DocumentMatchFailure = DocumentMatchBase & {
  success: false
  docType: DocTypeMatchResult
  claims: DocumentClaimsMatchResult
}

/**
 * Whether a document satisfies a doc request. The `docType` check requires both the docType of the
 * document and the docType of its mobile security object to be the requested docType: the docType
 * outside the MSO is not signed.
 */
export type DocumentMatch = DocumentMatchSuccess | DocumentMatchFailure

type DocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The documents that do not satisfy this doc request, in response order. This includes every
   * document of another docType, for which the `docType` check failed.
   */
  failedDocuments: Array<DocumentMatchFailure>
}

/**
 * At least one document in the response satisfies the doc request.
 */
export type DocRequestMatchSuccess = DocRequestMatchBase & {
  success: true
  /**
   * The documents that satisfy this doc request, in response order.
   */
  validDocuments: NonEmptyArray<DocumentMatchSuccess>
}

/**
 * No document in the response satisfies the doc request.
 */
export type DocRequestMatchFailure = DocRequestMatchBase & {
  success: false
  validDocuments: []
}

export type DocRequestMatch = DocRequestMatchSuccess | DocRequestMatchFailure

type DeviceRequestMatchBase = {
  /**
   * Documents in the response whose docType no doc request asked for.
   */
  unrequestedDocuments: Array<{ documentIndex: number; docType: DocType }>
}

/**
 * The device response satisfies every doc request in the device request.
 */
export type DeviceRequestMatchSuccess = DeviceRequestMatchBase & {
  success: true
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<DocRequestMatchSuccess>
}

/**
 * The device response does not satisfy at least one doc request in the device request.
 */
export type DeviceRequestMatchFailure = DeviceRequestMatchBase & {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<DocRequestMatch>
}

export type DeviceRequestMatchResult = DeviceRequestMatchSuccess | DeviceRequestMatchFailure

type CredentialMatchBase = {
  /**
   * Index into `credentials` of the credential this result is about.
   */
  credentialIndex: number
}

/**
 * A credential that can satisfy the doc request: every check passed.
 */
export type CredentialMatchSuccess = CredentialMatchBase & {
  success: true
  docType: DocTypeMatchSuccess
  claims: ClaimsMatchSuccess
}

/**
 * A credential that cannot satisfy the doc request: at least one check failed.
 */
export type CredentialMatchFailure = CredentialMatchBase & {
  success: false
  docType: DocTypeMatchResult
  claims: ClaimsMatchResult
}

/**
 * Whether a credential can satisfy a doc request. The `docType` check requires the docType of the
 * mobile security object of the credential to be the requested docType.
 */
export type CredentialMatch = CredentialMatchSuccess | CredentialMatchFailure

type HolderDocRequestMatchBase = {
  /**
   * Index into `deviceRequest.docRequests` of the doc request this result is about.
   */
  docRequestIndex: number
  docType: DocType
  /**
   * The credentials that do not satisfy this doc request, in the order they were provided. This
   * includes every credential of another docType, for which the `docType` check failed.
   */
  failedCredentials: Array<CredentialMatchFailure>
}

/**
 * At least one credential can satisfy the doc request.
 */
export type HolderDocRequestMatchSuccess = HolderDocRequestMatchBase & {
  success: true
  /**
   * The credentials that satisfy this doc request, in the order they were provided.
   */
  validCredentials: NonEmptyArray<CredentialMatchSuccess>
}

/**
 * No credential can satisfy the doc request.
 */
export type HolderDocRequestMatchFailure = HolderDocRequestMatchBase & {
  success: false
  validCredentials: []
}

export type HolderDocRequestMatch = HolderDocRequestMatchSuccess | HolderDocRequestMatchFailure

/**
 * The credentials can satisfy every doc request in the device request.
 */
export type HolderDeviceRequestMatchSuccess = {
  success: true
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<HolderDocRequestMatchSuccess>
}

/**
 * The credentials cannot satisfy at least one doc request in the device request.
 */
export type HolderDeviceRequestMatchFailure = {
  success: false
  /**
   * One entry per doc request, in request order.
   */
  docRequests: Array<HolderDocRequestMatch>
}

export type HolderDeviceRequestMatchResult = HolderDeviceRequestMatchSuccess | HolderDeviceRequestMatchFailure

/**
 * Match a `DeviceResponse` against the `DeviceRequest` it answers (verifier side).
 *
 * The ISO mdoc DC API protocol (`org-iso-mdoc`) has no query language such as DCQL that describes
 * which claims a response has to contain, so this walks the device request itself and reports, per
 * doc request, per document and per check whether the response satisfies it.
 *
 * An element only counts as disclosed when it comes from `issuerSigned`, as `deviceSigned` elements
 * are asserted by the mdoc itself rather than by the issuer. Pass `matchOptions` to mark elements
 * that are optional or that are expected to be device-signed.
 *
 * Uses the same rules as {@link matchCredentialsToDeviceRequest}.
 *
 * This is purely a structural comparison — it does not verify issuer auth, device auth or the
 * digests of the disclosed elements. Use it alongside `DeviceResponse.verify`, which runs it as
 * part of verification when a `deviceRequest` is passed.
 */
export const matchDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  deviceResponse: DeviceResponse
  matchOptions?: DeviceRequestMatchOptions
}): DeviceRequestMatchResult => {
  const { deviceRequest, deviceResponse, matchOptions } = options
  const docRequestOptions = indexDocRequestOptions(deviceRequest, matchOptions)

  const documents = deviceResponse.documents ?? []

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): DocRequestMatch => {
    const { docType, namespaces } = docRequest.itemsRequest
    const elements = docRequestOptions.get(docRequestIndex)?.elements

    const documentMatches = documents.map((document, documentIndex): DocumentMatch => {
      const mobileSecurityObjectDocType = document.issuerSigned.issuerAuth.mobileSecurityObject.docType
      const docTypeResult: DocTypeMatchResult =
        document.docType !== docType
          ? {
              success: false,
              docType: document.docType,
              reason: `Document has docType '${document.docType}', but docType '${docType}' was requested`,
            }
          : mobileSecurityObjectDocType !== docType
            ? {
                success: false,
                docType: document.docType,
                reason: `Document has docType '${docType}', but the mobile security object has docType '${mobileSecurityObjectDocType}'`,
              }
            : { success: true, docType }

      const { claims, unusedElements } = matchElements({
        mode: 'verifier',
        namespaces,
        elements,
        issuerSigned: document.issuerSigned,
        deviceNamespaces: document.deviceSigned.deviceNamespaces,
      })
      const claimsResult: DocumentClaimsMatchResult = {
        ...toClaimsMatchResult(claims),
        unrequestedClaims: unusedElements,
      }

      return docTypeResult.success && claimsResult.success
        ? { documentIndex, success: true, docType: docTypeResult, claims: claimsResult }
        : { documentIndex, success: false, docType: docTypeResult, claims: claimsResult }
    })

    const validDocuments = documentMatches.filter((documentMatch) => documentMatch.success)
    const failedDocuments = documentMatches.filter((documentMatch) => !documentMatch.success)

    return isNonEmptyArray(validDocuments)
      ? { docRequestIndex, docType, success: true, validDocuments, failedDocuments }
      : { docRequestIndex, docType, success: false, validDocuments: [], failedDocuments }
  })

  const requestedDocTypes = new Set(deviceRequest.docRequests.map((docRequest) => docRequest.itemsRequest.docType))
  const unrequestedDocuments = documents.flatMap((document, documentIndex) =>
    requestedDocTypes.has(document.docType) ? [] : [{ documentIndex, docType: document.docType }]
  )

  return docRequests.every((docRequest) => docRequest.success)
    ? { success: true, docRequests, unrequestedDocuments }
    : { success: false, docRequests, unrequestedDocuments }
}

/**
 * Match the credentials of a holder against a `DeviceRequest` (holder side), to select which
 * credentials can answer which doc request.
 *
 * Reports per doc request, per credential and per check whether the credential satisfies the doc
 * request, so a holder can show which credentials match, and for a credential of the right docType
 * which requested elements it is missing. Every credential is matched against every doc request, and
 * is referred to by its index in `credentials`.
 *
 * A requested element is disclosed issuer-signed when the issuer signed it (or, for an
 * `age_over_NN` request, the age attestation 18013-5 7.2.5 allows in its place). Otherwise it is
 * disclosed device-signed when the device key is authorized for it in the key authorizations of the
 * MSO, and its value has to be provided in the device namespaces when creating the response.
 *
 * Uses the same rules as {@link matchDeviceRequest}. The request does not say which elements are
 * optional, so every requested element is required.
 */
export const matchCredentialsToDeviceRequest = (options: {
  deviceRequest: DeviceRequest
  credentials: Array<IssuerSigned>
}): HolderDeviceRequestMatchResult => {
  const { deviceRequest, credentials } = options

  const docRequests = deviceRequest.docRequests.map((docRequest, docRequestIndex): HolderDocRequestMatch => {
    const { docType, namespaces } = docRequest.itemsRequest

    const credentialMatches = credentials.map((issuerSigned, credentialIndex): CredentialMatch => {
      const credentialDocType = issuerSigned.issuerAuth.mobileSecurityObject.docType
      const docTypeResult: DocTypeMatchResult =
        credentialDocType === docType
          ? { success: true, docType }
          : {
              success: false,
              docType: credentialDocType,
              reason: `Credential has docType '${credentialDocType}', but docType '${docType}' was requested`,
            }

      const claimsResult = toClaimsMatchResult(matchElements({ mode: 'holder', namespaces, issuerSigned }).claims)

      return docTypeResult.success && claimsResult.success
        ? { credentialIndex, success: true, docType: docTypeResult, claims: claimsResult }
        : { credentialIndex, success: false, docType: docTypeResult, claims: claimsResult }
    })

    const validCredentials = credentialMatches.filter((credentialMatch) => credentialMatch.success)
    const failedCredentials = credentialMatches.filter((credentialMatch) => !credentialMatch.success)

    return isNonEmptyArray(validCredentials)
      ? { docRequestIndex, docType, success: true, validCredentials, failedCredentials }
      : { docRequestIndex, docType, success: false, validCredentials: [], failedCredentials }
  })

  return docRequests.every((docRequest) => docRequest.success)
    ? { success: true, docRequests }
    : { success: false, docRequests }
}

type ElementCandidate = DisclosedElement & {
  /**
   * The issuer-signed item the element comes from, so a holder can disclose it as is.
   */
  issuerSignedItem?: IssuerSignedItem
}

/**
 * @internal
 */
export type ElementMatch = {
  claim: ClaimMatch
  /**
   * The element that answers the claim. Absent when the claim failed, or when the value of a
   * device-signed element was not provided to a holder match.
   */
  element?: ElementCandidate
}

/**
 * Match the requested elements of a single doc request against a single document or credential.
 * Shared by the verifier and the holder side, so both apply the same rules.
 *
 * - `verifier` matches the elements a document disclosed, from the source the `elements` options
 *   allow (by default `issuerSigned`).
 * - `holder` matches the elements a credential can disclose: issuer-signed when the issuer signed
 *   it, and otherwise device-signed when the device key is authorized for it. Values for
 *   device-signed elements are taken from `deviceNamespaces` when provided.
 *
 * @internal
 */
export const matchElements = (options: {
  mode: 'holder' | 'verifier'
  namespaces: Map<Namespace, Map<DataElementIdentifier, IntentToRetain>>
  elements?: Record<Namespace, Record<DataElementIdentifier, ElementMatchOptions>>
  issuerSigned: IssuerSigned
  deviceNamespaces?: DeviceNamespaces
}): { claims: Array<ElementMatch>; unusedElements: Array<DisclosedElement> } => {
  const { mode, namespaces } = options
  const keyAuthorizations = options.issuerSigned.issuerAuth.mobileSecurityObject.deviceKeyInfo.keyAuthorizations

  const available = collectElements(options.issuerSigned, options.deviceNamespaces)
  // 18013-5 9.1.3.4: device-signed elements only count when the device key is authorized for them.
  const candidates = available.filter(
    (element) =>
      element.source === 'issuerSigned' ||
      isDeviceSignedElementAuthorized(keyAuthorizations, element.namespace, element.elementIdentifier)
  )

  const claims: Array<ElementMatch> = []
  const usedElements = new Set<DisclosedElement>()

  const success = (claim: ClaimMatchBase, element: ElementCandidate) => {
    usedElements.add(element)
    claims.push({
      element,
      claim: {
        ...claim,
        success: true,
        disclosedElementIdentifier: element.elementIdentifier,
        elementValue: element.elementValue,
        source: element.source,
      },
    })
  }

  for (const [namespace, requestedElements] of namespaces) {
    const issuerSignedInNamespace = candidates.filter(
      (element) => element.namespace === namespace && element.source === 'issuerSigned'
    )
    const deviceSignedInNamespace = candidates.filter(
      (element) => element.namespace === namespace && element.source === 'deviceSigned'
    )

    for (const [elementIdentifier, intentToRetain] of requestedElements) {
      if (mode === 'holder') {
        const claim = { namespace, elementIdentifier, intentToRetain, optional: false }

        const issuerSignedElement = findElement(elementIdentifier, issuerSignedInNamespace)
        if (issuerSignedElement) {
          success(claim, issuerSignedElement)
          continue
        }

        if (isDeviceSignedElementAuthorized(keyAuthorizations, namespace, elementIdentifier)) {
          const deviceSignedElement = deviceSignedInNamespace.find(
            (element) => element.elementIdentifier === elementIdentifier
          )
          if (deviceSignedElement) {
            success(claim, deviceSignedElement)
            continue
          }

          claims.push({
            claim: {
              ...claim,
              success: true,
              disclosedElementIdentifier: elementIdentifier,
              elementValue: undefined,
              source: 'deviceSigned',
            },
          })
          continue
        }

        claims.push({
          claim: {
            ...claim,
            success: false,
            failure: 'notDisclosed',
            reason: `Element '${elementIdentifier}' in namespace '${namespace}' is not issuer-signed in the credential, and the device key is not authorized to sign it`,
          },
        })
        continue
      }

      const { optional = false, source = 'issuerSigned' } =
        options.elements?.[namespace]?.[elementIdentifier] ?? options.elements?.[namespace]?.['*'] ?? {}
      const claim = { namespace, elementIdentifier, intentToRetain, optional }

      // The source is applied before the element is picked, so that an `age_over_NN` request is not
      // answered by a device-signed attestation while an issuer-signed one is also present.
      const element =
        source === 'deviceSigned'
          ? findElement(elementIdentifier, deviceSignedInNamespace)
          : (findElement(elementIdentifier, issuerSignedInNamespace) ??
            (source === 'any' ? findElement(elementIdentifier, deviceSignedInNamespace) : undefined))

      if (element) {
        success(claim, element)
        continue
      }

      // The element may still be there, just not from a source this verifier accepts for it —
      // report that rather than letting it pass or reporting it as absent.
      const disallowed =
        source === 'any'
          ? undefined
          : findElement(
              elementIdentifier,
              source === 'issuerSigned' ? deviceSignedInNamespace : issuerSignedInNamespace
            )

      if (disallowed) {
        usedElements.add(disallowed)
        claims.push({
          claim: {
            ...claim,
            success: false,
            failure: 'disallowedSource',
            disclosedFrom: disallowed.source,
            reason: `Element '${disallowed.elementIdentifier}' in namespace '${namespace}' was disclosed through ${disallowed.source}, but must be disclosed through ${source}`,
          },
        })
        continue
      }

      claims.push({
        claim: {
          ...claim,
          success: false,
          failure: 'notDisclosed',
          reason: `Element '${elementIdentifier}' in namespace '${namespace}' was not disclosed`,
        },
      })
    }
  }

  return {
    claims,
    unusedElements: available
      .filter((element) => !usedElements.has(element))
      .map(({ issuerSignedItem: _, ...element }) => element),
  }
}

const toClaimsMatchResult = (claims: Array<ElementMatch>): ClaimsMatchResult => {
  const validClaims = claims.flatMap(({ claim }) => (claim.success ? [claim] : []))
  const failedClaims = claims.flatMap(({ claim }) => (claim.success ? [] : [claim]))

  if (isNonEmptyArray(failedClaims) && failedClaims.some((claim) => !claim.optional)) {
    return { success: false, validClaims, failedClaims }
  }

  // Every failed claim is optional, and optional elements never make the claims fail.
  return { success: true, validClaims, failedClaims: failedClaims.filter(isOptionalClaim) }
}

const isOptionalClaim = (claim: ClaimMatchFailure): claim is ClaimMatchFailure & { optional: true } => claim.optional

/**
 * The match options per doc request index, after checking that every option refers to a doc request
 * of the device request, and that no doc request has options more than once.
 */
const indexDocRequestOptions = (deviceRequest: DeviceRequest, matchOptions?: DeviceRequestMatchOptions) => {
  const docRequestOptions = new Map<number, DocRequestMatchOptions>()

  for (const options of matchOptions?.docRequests ?? []) {
    const { docRequestIndex } = options
    if (
      !Number.isInteger(docRequestIndex) ||
      docRequestIndex < 0 ||
      docRequestIndex >= deviceRequest.docRequests.length
    ) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options refer to doc request ${docRequestIndex}, but the device request has ${deviceRequest.docRequests.length} doc request(s)`
      )
    }
    if (docRequestOptions.has(docRequestIndex)) {
      throw new InvalidDeviceRequestMatchOptionsError(
        `Match options are provided more than once for doc request ${docRequestIndex}`
      )
    }
    docRequestOptions.set(docRequestIndex, options)
  }

  return docRequestOptions
}

const isNonEmptyArray = <T>(array: Array<T>): array is NonEmptyArray<T> => array.length > 0

/**
 * The element that answers a request for `elementIdentifier`, either by identifier or, for an age
 * attestation, by the substitution 18013-5 7.2.5 allows.
 *
 * @internal
 */
export const findElement = <Candidate extends { elementIdentifier: DataElementIdentifier; elementValue: unknown }>(
  elementIdentifier: DataElementIdentifier,
  candidates: Array<Candidate>
) =>
  candidates.find((candidate) => candidate.elementIdentifier === elementIdentifier) ??
  findAgeOverCandidate(elementIdentifier, candidates)

const isDeviceSignedElementAuthorized = (
  keyAuthorizations: KeyAuthorizations | undefined,
  namespace: Namespace,
  elementIdentifier: DataElementIdentifier
) =>
  (keyAuthorizations?.namespaces?.includes(namespace) ||
    keyAuthorizations?.dataElements?.get(namespace)?.includes(elementIdentifier)) ??
  false

const collectElements = (issuerSigned: IssuerSigned, deviceNamespaces?: DeviceNamespaces) => {
  const elements: Array<ElementCandidate> = []

  for (const [namespace, issuerSignedItems] of issuerSigned.issuerNamespaces?.issuerNamespaces ?? []) {
    for (const issuerSignedItem of issuerSignedItems) {
      elements.push({
        namespace,
        elementIdentifier: issuerSignedItem.elementIdentifier,
        elementValue: issuerSignedItem.elementValue,
        source: 'issuerSigned',
        issuerSignedItem,
      })
    }
  }

  for (const [namespace, deviceSignedItems] of deviceNamespaces?.deviceNamespaces ?? []) {
    for (const [elementIdentifier, elementValue] of deviceSignedItems.deviceSignedItems) {
      elements.push({ namespace, elementIdentifier, elementValue, source: 'deviceSigned' })
    }
  }

  return elements
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

    // Only the documents answering this doc request can over-disclose for it.
    for (const document of docRequest.validDocuments) {
      if (document.claims.unrequestedClaims.length === 0) continue

      onCheck({
        status: 'WARNING',
        check: `Document ${document.documentIndex} must not disclose elements that were not requested`,
        category: 'DOCUMENT_FORMAT',
        reason: `Document ${document.documentIndex} disclosed ${document.claims.unrequestedClaims
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
  // Documents of another docType are not an attempt to answer this doc request.
  const documents = docRequest.failedDocuments.filter(
    (document) => document.docType.success || document.docType.docType === docRequest.docType
  )

  if (documents.length === 0) {
    return `Device response does not contain a document with docType '${docRequest.docType}'`
  }

  return documents
    .map((document) => {
      if (!document.docType.success) return `Document ${document.documentIndex}: ${document.docType.reason}`

      const failedClaims = document.claims.failedClaims.filter((claim) => !claim.optional)
      return `Document ${document.documentIndex}: ${failedClaims.map((claim) => claim.reason).join('; ')}`
    })
    .join('. ')
}
