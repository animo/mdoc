export {
  CoseKey,
  Curve,
  cborDecode,
  cborEncode,
  DateOnly,
  KeyOps,
  KeyType,
  Mac0,
  ProtectedHeaders,
  RegisteredCwtClaimKey,
  RegisteredCwtHeaderClaimKey,
  Sign1,
  SignatureAlgorithm,
  UnprotectedHeaders,
} from '@owf/cose'
export { StatusListInfo } from '@owf/token-status-list'
export * from './context'
export * from './holder'
export * from './iso-mdoc-dc-api'
export * from './issuer'
export * from './mdoc'
export { findAgeOverCandidate, parseAgeOverIdentifier } from './utils/ageOver'
export {
  collectDeviceSignedElements,
  type DeviceSignedElement,
  describeUnauthorizedDeviceSignedElements,
  findUnauthorizedDeviceSignedElements,
} from './utils/keyAuthorizations'
export { limitDisclosureToDeviceRequestNameSpaces } from './utils/limitDisclosure'
export {
  type ClaimMatch,
  type ClaimMatchFailure,
  type ClaimMatchSuccess,
  type DeviceRequestElementOptions,
  type DeviceRequestMatchResult,
  type DisclosedElement,
  type DisclosedElementSource,
  type DocRequestMatch,
  type DocumentMatch,
  type ElementMatchOptions,
  matchDeviceRequest,
  reportDeviceRequestMatch,
} from './utils/matchDeviceRequest'
export * from './verifier'
