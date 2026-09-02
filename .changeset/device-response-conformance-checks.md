---
'@owf/mdoc': minor
---

Add three ISO/IEC 18013-5 conformance checks that verification was missing. All three are reported through the existing `onCheck` callback, so `defaultVerificationCallback` now throws on responses that previously passed:

- **Key authorizations (9.1.3.4).** An mdoc "shall only authenticate response data elements in `DeviceNameSpaces` if the key it is using for mdoc authentication is authorized to authenticate these elements in the `KeyAuthorizations` structure in the MSO", and "the mdoc reader shall validate this authorization as part of validating the mdoc authentication".
- **Response status (8.3.2.1.2.3, Table 8).** "If the mdoc returns a status code different from 0, it shall not return any documents".
- **Duplicate element identifiers (8.3.2.1.2.2).** "The mdoc shall not include two or more `IssuerSignedItem` elements with the same `DataElementIdentifier` in a single `NameSpace` and `Document`".