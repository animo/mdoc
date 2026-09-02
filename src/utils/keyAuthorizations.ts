import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DeviceNamespaces } from '../mdoc/models/device-namespaces'
import type { KeyAuthorizations } from '../mdoc/models/key-authorizations'
import type { Namespace } from '../mdoc/models/namespace'

export type DeviceSignedElement = {
  namespace: Namespace
  elementIdentifier: DataElementIdentifier
}

/**
 * The data elements the mdoc authenticated through `DeviceNameSpaces`, flattened across namespaces.
 */
export const collectDeviceSignedElements = (deviceNamespaces?: DeviceNamespaces): Array<DeviceSignedElement> =>
  Array.from(deviceNamespaces?.deviceNamespaces ?? []).flatMap(([namespace, deviceSignedItems]) =>
    Array.from(deviceSignedItems.deviceSignedItems.keys()).map((elementIdentifier) => ({
      namespace,
      elementIdentifier,
    }))
  )

/**
 * The device-signed elements the device key is not authorized to authenticate.
 *
 * ISO/IEC 18013-5 9.1.3.4: "An mdoc shall only authenticate response data elements in
 * `DeviceNameSpaces` if the key it is using for mdoc authentication is authorized to authenticate
 * these elements in the `KeyAuthorizations` structure in the MSO. The mdoc reader shall validate
 * this authorization as part of validating the mdoc authentication." Authorization is given either
 * for a whole namespace or per data element (9.1.2.4), so both sides run this: the mdoc before it
 * signs or MACs a response, the mdoc reader after it decodes one.
 */
export const findUnauthorizedDeviceSignedElements = (options: {
  deviceNamespaces?: DeviceNamespaces
  keyAuthorizations?: KeyAuthorizations
}): Array<DeviceSignedElement> => {
  const authorizedNamespaces = options.keyAuthorizations?.namespaces ?? []
  const authorizedDataElements = options.keyAuthorizations?.dataElements

  return collectDeviceSignedElements(options.deviceNamespaces).filter(
    ({ namespace, elementIdentifier }) =>
      !authorizedNamespaces.includes(namespace) && !authorizedDataElements?.get(namespace)?.includes(elementIdentifier)
  )
}

/**
 * A shared description of unauthorized elements, so the mdoc's error and the mdoc reader's failed
 * check name the same elements in the same way.
 */
export const describeUnauthorizedDeviceSignedElements = (unauthorized: Array<DeviceSignedElement>) =>
  `The device key is not authorized to authenticate ${unauthorized
    .map(({ namespace, elementIdentifier }) => `'${elementIdentifier}' in namespace '${namespace}'`)
    .join(', ')}`
