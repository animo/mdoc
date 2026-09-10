---
'@owf/mdoc': minor
---

Add `Verifier.matchDeviceRequest` to check which requested elements a `DeviceResponse` disclosed, per doc request, document and element. It also reports elements that were disclosed but not requested, and which `age_over_NN` answered an age request.

Requested elements must be issuer-signed and are required by default. Use `elements` to mark them optional or allow them from `deviceSigned`:

```ts
const match = Verifier.matchDeviceRequest({
  deviceRequest,
  deviceResponse,
  elements: {
    'org.iso.18013.5.1.mDL': {
      'org.iso.18013.5.1': { portrait: { optional: true } },
      // '*' applies to every element in the namespace
      'com.example.device': { '*': { source: 'deviceSigned' } },
    },
  },
})
```

When you pass a `deviceRequest` to `DeviceResponse.verify`, `Verifier.verifyDeviceResponse` or `IsoMdocDcApi.verifyResponse`, they run the same match. The element options go in `deviceRequestElements`, and the result comes back as `deviceRequestMatch`. A failed match now lists every missing element instead of stopping at the first one. Failed checks throw a `VerificationError`, which still extends `MdlError`, and the match is attached as `error.assessment.result.match`.
