---
'@owf/mdoc': minor
---

`DeviceResponse.createWithDeviceRequest` and `IsoMdocDcApi.createResponse` select the elements to disclose with the same rules as `Holder.matchDeviceRequest`:

- A requested element the issuer did not sign, but that the device key is authorized for, is disclosed through the `deviceNamespaces` of the document. Before, every requested element had to be issuer-signed.
- A document can pass `elements` to disclose only some of the requested elements, for instance leaving out the ones the user declined to share.
- A requested element that cannot be disclosed throws a `MissingRequestedElementError`.
