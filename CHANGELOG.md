# @animo-id/mdoc

## 0.4.0

### Minor Changes

- 59e3266: fix: do not include age_over_NN attributes by default
- e54a767: - Remove magic surrounding the date type, this means that when you provide the input for an mdl, make sure that the `birth_date`, `driving_privileges[n].issue_date` and `driving_privileges[n].expiry_date` are of class `DateOnly` and `issue_date` and `expiry_date` are of type `Date`.

### Patch Changes

- 4187667: feat: add OID4VP DC API session transcript calculation
- ff41f06: Include different age*over_NN values and exclude age_over*<CURRENT_AGE>

## 0.3.0

### Minor Changes

- 65fcc93: feat: support ISO 18013-7 Draft 2024-03-12.

  This mostly changes the structure of the calculated session transcript bytes for usage with the Web API or OpenID4VP. This is a breaking change and incompatible with older versions of this library.

## 0.2.39

### Patch Changes

- d3cee49: fix: use null for payload instead of undefined
- d3cee49: fix: correctly handle map vs object

## 0.2.38

### Patch Changes

- 9df25d9: build: publish dist

## 0.2.37

### Patch Changes

- 43becf8: refactor: restructure repo
