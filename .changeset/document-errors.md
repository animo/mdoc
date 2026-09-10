---
'@owf/mdoc': minor
---

`Document.errors` is now always an `Errors` instance. `DocumentOptions.errors` takes an `Errors` instead of a `Map<Namespace, ErrorItems>`:

```ts
Document.create({
  docType,
  issuerSigned,
  deviceSigned,
  errors: Errors.create({
    errors: new Map([[namespace, ErrorItems.create({ errorItems: new Map([['birth_date', 0]]) })]]),
  }),
})
```

`Errors` gains `errors`, `getErrorItems(namespace)` and `create`, and `ErrorItems` gains `errorItems`
and `getErrorCode(dataElementIdentifier)`.
