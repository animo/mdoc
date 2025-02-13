---
"@animo-id/mdoc": minor
---

- Remove magic surrounding the date type, this means that when you provide the input for an mdl, make sure that the `birth_date`, `driving_privileges[n].issue_date` and `driving_privileges[n].expiry_date` are of class `DateOnly` and `issue_date` and `expiry_date` are of type `Date`.
