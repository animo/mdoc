import type { DataElementIdentifier } from '../mdoc/models/data-element-identifier'
import type { DataElementValue } from '../mdoc/models/data-element-value'

const ageOverPrefix = 'age_over_'

export type AgeOverCandidate = {
  elementIdentifier: DataElementIdentifier
  elementValue: DataElementValue
}

/**
 * The `NN` of an `age_over_NN` element identifier, or `undefined` when the identifier is not an
 * age attestation.
 */
export const parseAgeOverIdentifier = (elementIdentifier: DataElementIdentifier): number | undefined => {
  if (!elementIdentifier.startsWith(ageOverPrefix)) return undefined

  const nn = Number.parseInt(elementIdentifier.slice(ageOverPrefix.length), 10)
  return Number.isNaN(nn) ? undefined : nn
}

/**
 * Find the `age_over_MM` attestation that answers a request for `age_over_NN`.
 *
 * ISO/IEC 18013-5 7.2.5 lets the mdoc answer with a different age attestation than the one
 * requested: the nearest one that is `true` for `MM >= NN`, and otherwise the nearest one that is
 * `false` for `MM <= NN`.
 */
export const findAgeOverCandidate = <Candidate extends AgeOverCandidate>(
  requestedElementIdentifier: DataElementIdentifier,
  candidates: Array<Candidate>
): Candidate | undefined => {
  const requestedNn = parseAgeOverIdentifier(requestedElementIdentifier)
  if (requestedNn === undefined) return undefined

  const ageOverCandidates = candidates.flatMap((candidate) => {
    const nn = parseAgeOverIdentifier(candidate.elementIdentifier)
    return nn === undefined ? [] : [{ nn, candidate }]
  })

  const nearestTrue = ageOverCandidates
    .filter(({ nn, candidate }) => candidate.elementValue === true && nn >= requestedNn)
    .sort((a, b) => a.nn - b.nn)[0]
  if (nearestTrue) return nearestTrue.candidate

  const nearestFalse = ageOverCandidates
    .filter(({ nn, candidate }) => candidate.elementValue === false && nn <= requestedNn)
    .sort((a, b) => b.nn - a.nn)[0]

  return nearestFalse?.candidate
}
