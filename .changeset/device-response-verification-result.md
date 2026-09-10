---
'@owf/mdoc': minor
---

**Breaking:** `DeviceResponse.verify`, `Verifier.verifyDeviceResponse` and `IsoMdocDcApi.verifyResponse` (as `verificationResult`) now return an object instead of an array. The per document results moved to `documents`:

```ts
// before
const results = await deviceResponse.verify(options, ctx)

// after
const { documents } = await deviceResponse.verify(options, ctx)
```
